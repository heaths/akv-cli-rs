// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use super::VAULT_ENV_NAME;
use crate::credential;
use akv_cli::Result;
use azure_core::http::Url;
use azure_security_keyvault_secrets::{models::SecretClientGetSecretOptions, SecretClient};
use clap::Parser;
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};
use tracing::{Level, Span};

#[derive(Debug, Parser)]
pub struct Args {
    /// The secret URL e.g., "https://my-vault.vault.azure.net/secrets/my-secret".
    #[arg(group = "ident", value_name = "URL")]
    id: Option<Url>,

    /// The secret name.
    #[arg(long, group = "ident", requires = "vault")]
    name: Option<String>,

    /// The vault URL e.g., "https://my-vault.vault.azure.net".
    #[arg(long, value_name = "URL", env = VAULT_ENV_NAME)]
    vault: Option<Url>,

    /// Do not print a new line after the secret.
    #[arg(short = 'n', long)]
    no_newline: bool,

    /// Write the secret to a file instead of stdout.
    #[arg(short = 'o', long, value_name = "PATH")]
    out_file: Option<PathBuf>,

    /// Force overwriting an existing file.
    #[arg(short = 'f', long)]
    force: bool,
}

impl Args {
    #[tracing::instrument(level = Level::INFO, skip(self), fields(vault, name, version), err)]
    pub async fn read(&self) -> Result<()> {
        let (vault, name, version) =
            super::select(self.id.as_ref(), self.vault.as_ref(), self.name.as_ref())?;

        let current = Span::current();
        current.record("vault", &*vault);
        current.record("name", &*name);
        current.record("version", version.as_deref());

        let client = SecretClient::new(&vault, credential(), None)?;
        let secret = client
            .get_secret(
                &name,
                Some(SecretClientGetSecretOptions {
                    secret_version: version.map(Into::into),
                    ..Default::default()
                }),
            )
            .await?
            .into_body()?;
        tracing::debug!("retrieved {:?}", &secret);

        if let Some(value) = secret.value {
            match self.out_file.as_ref() {
                // Write to a file.
                Some(path) => {
                    let mut file = fs::OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .create_new(!self.force)
                        .open(path)?;
                    file.write_all(value.as_bytes())?;
                }
                // Print to stdout without a newline.
                _ if self.no_newline => {
                    print!("{value}");
                    io::stdout().flush()?;
                }
                // Print line to stdout.
                _ => println!("{value}"),
            }
        }

        Ok(())
    }
}
