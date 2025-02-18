// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use super::VAULT_ENV_NAME;
use akv_cli::{
    cache::ClientCache,
    parsing::{replace_expressions, replace_vars},
    ErrorKind, Result,
};
use azure_core::Url;
use azure_identity::DefaultAzureCredential;
use azure_security_keyvault_secrets::{ResourceId, SecretClient};
use clap::Parser;
use futures::FutureExt as _;
use std::{
    env, fs,
    io::{self, Read, Write},
    path::PathBuf,
    sync::Arc,
};
use tracing::Level;

#[derive(Debug, Parser)]
pub struct Args {
    /// The vault URL e.g., "https://my-vault.vault.azure.net". Allows for just secret names.
    #[arg(long, value_name = "URL", env = VAULT_ENV_NAME)]
    vault: Option<Url>,

    /// The filename of the template file to inject.
    #[arg(short = 'i', long, value_name = "PATH")]
    in_file: Option<PathBuf>,

    /// Write the secret to a file instead of stdout.
    #[arg(short = 'o', long, value_name = "PATH")]
    out_file: Option<PathBuf>,

    /// Force overwriting an existing file.
    #[arg(short = 'f', long)]
    force: bool,
}

impl Args {
    #[tracing::instrument(level = Level::INFO, skip(self), err)]
    pub async fn inject(&self) -> Result<()> {
        let input = match &self.in_file {
            Some(in_file) if in_file.exists() => {
                let mut input = String::new();
                fs::File::open(in_file)?.read_to_string(&mut input)?;
                input
            }
            Some(in_file) => {
                return Err(akv_cli::Error::with_message_fn(ErrorKind::Io, || {
                    format!("{} does not exist", in_file.display())
                }));
            }
            _ => {
                let mut input = String::new();
                io::stdin().read_to_string(&mut input)?;
                input
            }
        };

        let credentials = DefaultAzureCredential::new()?;
        let mut cache = ClientCache::new();
        if let Some(vault) = self.vault.as_ref() {
            cache
                .get(Arc::new(SecretClient::new(
                    vault.as_str(),
                    credentials.clone(),
                    None,
                )?))
                .await?;
        };

        let mut buf = Vec::new();
        replace_expressions(&input, &mut buf, |expr| {
            let mut cache = cache.clone();
            let credentials = credentials.clone();

            async move {
                tracing::debug!("replacing expression {expr}");

                let id = replace_vars(expr, |var| {
                    tracing::debug!("replacing variable ${var}");
                    env::var(var).map_err(|err| {
                        if let env::VarError::NotPresent = err {
                            return akv_cli::Error::with_message_fn(ErrorKind::Other, || {
                                format!("environment variable ${var} not found")
                            });
                        }

                        err.into()
                    })
                })?;

                tracing::debug!("reading secret {id}");
                let id: ResourceId = id.parse()?;

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

                Ok(secret.value.unwrap_or_else(String::new))
            }
            .boxed()
        })
        .await?;

        let mut output: Box<dyn Write> = match &self.out_file {
            Some(out_file) => Box::new(
                fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .create_new(!self.force)
                    .open(out_file)?,
            ),
            _ => Box::new(io::stdout()),
        };

        io::copy(&mut buf.as_slice(), output.as_mut())
            .map(|_| ())
            .map_err(Into::into)
    }
}
