// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use akv_cli::{get_secret, Result};
use azure_core::Url;
use azure_identity::DefaultAzureCredential;
use azure_security_keyvault_secrets::SecretClient;
use clap::Parser;
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};

use super::VAULT_ENV_NAME;

#[derive(Debug, Parser)]
pub struct Args {
    /// The secret URL e.g., "https://my-vault.vault.azure.net/secrets/my-secret".
    #[arg(group = "ident")]
    id: Option<Url>,

    /// The secret name.
    #[arg(long, group = "ident", requires = "vault")]
    name: Option<String>,

    /// The vault URL e.g., "https://my-vault.vault.azure.net".
    #[arg(long, env = VAULT_ENV_NAME)]
    vault: Option<Url>,

    /// Do not print a new line after the secret.
    #[arg(short = 'n', long)]
    no_newline: bool,

    /// Write the secret to a file instead of stdout.
    #[arg(short = 'o', long)]
    out_file: Option<PathBuf>,
}

impl Args {
    pub async fn read(&self) -> Result<()> {
        let (vault, name, version) =
            super::select(self.id.as_ref(), self.vault.as_ref(), self.name.as_ref())?;

        let client = SecretClient::new(&vault, DefaultAzureCredential::new()?, None)?;
        let secret = get_secret(&client, &name, version.as_deref()).await?;
        if let Some(value) = secret.value {
            match self.out_file.as_ref() {
                Some(path) => {
                    let mut file = fs::File::create(path)?;
                    file.write_all(value.as_bytes())?;
                }
                _ if self.no_newline => {
                    print!("{value}");
                    io::stdout().flush()?;
                }
                _ => println!("{value}"),
            }
        }

        Ok(())
    }
}
