// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use akv_cli::{cache::ClientCache, pty::CommandExt, ErrorKind, Result};
use azure_identity::DefaultAzureCredential;
use azure_security_keyvault_secrets::{ResourceId, SecretClient};
use clap::Parser;
use std::{
    collections::HashMap,
    env,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{exit, Command},
    sync::Arc,
};
use tokio::sync::Mutex;
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

        // Write directly to stdout, stderr if not masking.
        if self.no_masking {
            let mut args = self.args.iter();
            let program = args.next().ok_or_else(|| {
                akv_cli::Error::with_message(ErrorKind::InvalidData, "command required")
            })?;
            let mut cmd = Command::new(program);
            let mut process = cmd.args(args).spawn()?;
            if let Some(code) = process.wait()?.code() {
                exit(code);
            }

            return Ok(());
        }

        let mut args = self.args.iter();
        let program = args.next().ok_or_else(|| {
            akv_cli::Error::with_message(ErrorKind::InvalidData, "command required")
        })?;
        let mut cmd = Command::new(program);
        cmd.args(args);

        let (mut process, pty) = cmd.spawn_pty()?;
        let pipe = tokio::spawn({
            let pty = pty.clone();
            async move {
                let reader = BufReader::new(pty);
                let lines = reader.lines().fuse();
                for line in lines {
                    let Ok(line) = line else {
                        continue;
                    };

                    let masked = mask_secrets(&line, &secrets);
                    println!("{masked}");
                }
            }
        });

        let status = process.wait();
        drop(pty);

        let _ = pipe.await;
        if let Some(code) = status?.code() {
            exit(code);
        }

        Ok(())
    }
}

fn mask_secrets(line: &str, secrets: &Vec<String>) -> String {
    let mut masked = line.to_string();
    for secret in secrets {
        masked = masked.replace(secret, MASK);
    }
    masked
}
