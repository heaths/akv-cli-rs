// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

mod decrypt;
mod encrypt;
mod inject;
mod read;
mod run;
mod secret;

use akv_cli::{ErrorKind, Result};
use azure_security_keyvault_secrets::ResourceId;
use clap::{CommandFactory, Subcommand};
use clap_complete::{generate, Shell};
use std::{borrow::Cow, io};
use url::Url;

const VAULT_ENV_NAME: &str = "AZURE_KEYVAULT_URL";

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Manage secrets in Azure Key Vault.
    #[command(subcommand)]
    Secret(secret::Commands),

    /// Inject secrets from Azure Key Vault into a templated file or input between {{ }}
    Inject(inject::Args),

    /// Read a secret from Azure Key Vault.
    Read(read::Args),

    /// Pass secrets in environment variables to a process.
    Run(run::Args),

    /// Encrypt content to a compact JSON Web Encryption (JWE) token.
    Encrypt(encrypt::Args),

    /// Decrypt a compact JSON Web Encryption (JWE) token.
    Decrypt(decrypt::Args),

    /// Generates completion scripts for supported shells.
    Completion {
        /// The shell script to generate.
        #[arg(value_enum)]
        shell: Shell,
    },
}

impl Commands {
    pub async fn handle(&self) -> Result<()> {
        match self {
            Commands::Secret(command) => command.handle().await,
            Commands::Inject(args) => args.inject().await,
            Commands::Read(args) => args.read().await,
            Commands::Run(args) => args.run().await,
            Commands::Encrypt(args) => args.encrypt().await,
            Commands::Decrypt(args) => args.decrypt().await,
            Commands::Completion { shell } => {
                let mut cmd = super::Args::command();
                let bin_name = cmd.get_name().to_string();
                generate(*shell, &mut cmd, bin_name, &mut io::stdout());
                Ok(())
            }
        }
    }
}

#[allow(clippy::type_complexity)]
fn select<'a>(
    id: Option<&Url>,
    vault: Option<&'a Url>,
    name: Option<&'a String>,
) -> akv_cli::Result<(Cow<'a, str>, Cow<'a, str>, Option<Cow<'a, str>>)> {
    match (id, vault, name) {
        (Some(id), _, None) => {
            let resource: ResourceId = id.try_into()?;
            Ok((
                Cow::Owned(resource.vault_url),
                Cow::Owned(resource.name),
                resource.version.map(Cow::Owned),
            ))
        }
        (None, Some(vault), Some(name)) => {
            Ok((Cow::Borrowed(vault.as_str()), Cow::Borrowed(name), None))
        }
        _ => Err(akv_cli::Error::with_message(
            ErrorKind::InvalidData,
            "invalid arguments",
        )),
    }
}
