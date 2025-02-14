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
use futures::FutureExt;
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
    #[arg(long, env = VAULT_ENV_NAME)]
    vault: Option<Url>,

    /// The filename of the template file to inject.
    #[arg(short = 'i', long)]
    in_file: Option<PathBuf>,

    /// Write the secret to a file instead of stdout.
    #[arg(short = 'o', long)]
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

        let credentials = DefaultAzureCredential::new()?;
        let mut cache = ClientCache::new();
        if let Some(vault) = self.vault.as_ref() {
            cache.get(Arc::new(SecretClient::new(
                vault.as_str(),
                credentials.clone(),
                None,
            )?))?;
        };

        replace_expressions(&input, &mut output, |expr| {
            let mut cache = cache.clone();
            let credentials = credentials.clone();

            async move {
                tracing::debug!("replacing expression {expr}");

                let id = replace_vars(expr, |var| {
                    tracing::debug!("replacing variable ${var}");
                    env::var(var).map_err(Into::into)
                })?;

                tracing::debug!("reading secret {id}");
                let id: ResourceId = id.parse()?;

                let client = cache.get(Arc::new(SecretClient::new(
                    &id.vault_url,
                    credentials.clone(),
                    None,
                )?))?;

                let secret = client
                    .get_secret(&id.name, id.version.as_deref().unwrap_or_default(), None)
                    .await?
                    .into_body()
                    .await?;

                Ok(secret.value.unwrap_or_else(String::new))
            }
            .boxed()
        })
        .await
    }
}
