// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use akv_cli::{cache::ClientCache, ErrorKind, Result};
use azure_identity::DefaultAzureCredential;
use azure_security_keyvault_secrets::{ResourceId, SecretClient};
use clap::Parser;
use futures::StreamExt as _;
use std::{
    collections::HashMap,
    env,
    io::{self, Write},
    path::PathBuf,
    process::{exit, Stdio},
    sync::Arc,
};
use tokio::{process::Command, sync::Mutex};
use tokio_util::codec::{FramedRead, LinesCodec};
use tracing::Level;

const MASK: &str = "<concealed by akv>";

#[derive(Debug, Parser)]
#[command(arg_required_else_help = true)]
pub struct Args {
    /// Read environment files e.g., `.env`, with subsequent files overwriting previous environment variables.
    #[arg(long, value_name = "PATH")]
    env_file: Vec<PathBuf>,

    /// Disable masking of secrets in stdout and stderr. Multiline secrets may not mask properly.
    #[arg(long)]
    no_masking: bool,

    /// A command and optional arguments to run. No options are parsed after parsing a command.
    #[arg(
        allow_hyphen_values = true,
        hide = true,
        required = true,
        trailing_var_arg = true
    )]
    args: Vec<String>,
}

impl Args {
    #[tracing::instrument(level = Level::INFO, skip(self), err)]
    pub async fn run(&self) -> Result<()> {
        for path in &self.env_file {
            dotenvy::from_path_override(path)?;
        }

        let credentials = DefaultAzureCredential::new()?;
        let mut cache = ClientCache::new();
        let secrets = Arc::new(Mutex::new(HashMap::<String, String>::new()));

        // Replace any env var containing only a Key Vault URI with its value.
        // Keep track of which values we replace to mask them later.
        for (name, value) in env::vars_os() {
            let Ok(value) = value.into_string() else {
                continue;
            };

            let Ok(id) = value.parse::<ResourceId>() else {
                continue;
            };

            tracing::debug!("replacing environment variable {name:?} from {value}");
            let mut secrets = secrets.lock().await;

            // Use a cached secret if available.
            if let Some(secret) = secrets.get(&value) {
                env::set_var(name, secret.as_str());
                continue;
            }

            // Otherwise, fetch the secret and cache it by the URL.
            let client = cache
                .get(Arc::new(SecretClient::new(
                    &id.vault_url,
                    credentials.clone(),
                    None,
                )?))
                .await?;

            let secret = client
                .get_secret(&id.name, id.version.as_deref().unwrap_or_default(), None)
                .await?
                .into_body()
                .await?;

            let Some(secret) = secret.value else {
                // No value: should not happen, but is not fatal.
                continue;
            };

            env::set_var(name, secret.as_str());
            secrets.insert(value, secret);
        }

        // Copy the values for faster access.
        let secrets: Vec<String> = secrets
            .lock()
            .await
            .values()
            .map(ToOwned::to_owned)
            .collect();

        let mut args = self.args.iter();
        let mut cmd = Command::new(args.next().ok_or_else(|| {
            akv_cli::Error::with_message(ErrorKind::InvalidData, "command required")
        })?);

        // Write directly to stdout, stderr if not masking.
        if self.no_masking {
            let mut process = cmd.args(args).spawn()?;
            if let Some(code) = process.wait().await?.code() {
                exit(code);
            }

            return Ok(());
        }

        // Otherwise, capture stdout, stderr and mask any instances of cached secrets.
        let (tx, rx) = std::sync::mpsc::channel::<TaggedLine>();
        let mut process = cmd
            .args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let mut stdout = FramedRead::new(
            process.stdout.take().ok_or_else(|| {
                akv_cli::Error::with_message(ErrorKind::Other, "failed to redirect stdout")
            })?,
            LinesCodec::new(),
        );
        let stdout_tx = tx.clone();
        let stdout_fut = tokio::spawn(async move {
            while let Some(line) = stdout.next().await {
                if let Ok(line) = line {
                    #[allow(unused_must_use)]
                    stdout_tx.send(TaggedLine::stdio(line));
                }
            }
        });
        let mut stderr = FramedRead::new(
            process.stderr.take().ok_or_else(|| {
                akv_cli::Error::with_message(ErrorKind::Other, "failed to redirect stderr")
            })?,
            LinesCodec::new(),
        );
        let stderr_tx = tx.clone();
        let stderr_fut = tokio::spawn(async move {
            while let Some(line) = stderr.next().await {
                if let Ok(line) = line {
                    #[allow(unused_must_use)]
                    stderr_tx.send(TaggedLine::stderr(line));
                }
            }
        });
        drop(tx);

        let mut stdout = io::stdout();
        let mut stderr = io::stderr();
        for tagged_line in rx.iter() {
            let masked = mask_secrets(&tagged_line.line, &secrets);
            match tagged_line.tag {
                Tag::Stdout => {
                    stdout.write_all(masked.as_bytes())?;
                    stdout.flush()?;
                }
                Tag::Stderr => {
                    stderr.write_all(masked.as_bytes())?;
                    stderr.flush()?;
                }
            }
        }

        let (status, _, _) = tokio::join!(process.wait(), stdout_fut, stderr_fut);
        if let Some(code) = status?.code() {
            exit(code);
        }

        return Ok(());
    }
}

#[derive(Debug)]
struct TaggedLine {
    tag: Tag,
    line: String,
}

impl TaggedLine {
    fn stdio(line: String) -> Self {
        Self {
            tag: Tag::Stdout,
            line,
        }
    }

    fn stderr(line: String) -> Self {
        Self {
            tag: Tag::Stderr,
            line,
        }
    }
}

#[derive(Debug)]
enum Tag {
    Stdout,
    Stderr,
}

fn mask_secrets(line: &str, secrets: &Vec<String>) -> String {
    let mut masked = line.to_string();
    for secret in secrets {
        masked = masked.replace(secret, MASK);
    }
    masked + "\n"
}
