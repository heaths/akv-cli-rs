// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

mod certificate;
mod decrypt;
mod encrypt;
mod inject;
mod key;
mod read;
mod run;
mod secret;

use akv_cli::{parsing::parse_date_time_opt, ErrorKind, Result};
use azure_security_keyvault_secrets::ResourceId;
use clap::{ArgAction, Args, CommandFactory, Subcommand};
use clap_complete::{generate, Shell};
use std::{borrow::Cow, collections::HashMap, io};
use time::OffsetDateTime;
use url::Url;

const VAULT_ENV_NAME: &str = "AZURE_KEYVAULT_URL";

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Inject secrets from Azure Key Vault into a templated file or input between {{ }}
    Inject(inject::Args),

    /// Pass secrets in environment variables to a process.
    Run(run::Args),

    /// Read a secret from Azure Key Vault.
    Read(read::Args),

    /// Encrypt content to a compact JSON Web Encryption (JWE) token.
    Encrypt(encrypt::Args),

    /// Decrypt a compact JSON Web Encryption (JWE) token.
    Decrypt(decrypt::Args),

    /// Manage secrets in Azure Key Vault.
    #[command(subcommand)]
    Secret(secret::Commands),

    /// Manage keys in Azure Key Vault.
    #[command(subcommand)]
    Key(key::Commands),

    /// Manage certificates in Azure Key Vault.
    #[command(subcommand)]
    Certificate(certificate::Commands),

    /// Generates completion scripts for supported shells.
    Completion {
        /// The shell script to generate.
        #[arg(value_enum)]
        shell: Shell,
    },
}

impl Commands {
    pub async fn handle(&self, global_args: &crate::Args) -> Result<()> {
        match self {
            Commands::Secret(command) => command.handle().await,
            Commands::Key(command) => command.handle().await,
            Commands::Certificate(command) => command.handle(global_args).await,
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

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct AttributeArgs {
    /// Enable or disable the resource. Enabled by default.
    #[arg(long, action = ArgAction::SetTrue)]
    pub enabled: Option<bool>,

    /// When the resource expires in RFC3339 format.
    #[arg(long, value_parser = parse_date_time_opt)]
    pub expires: Option<OffsetDateTime>,

    /// When the resource becomes valid in RFC3339 format.
    #[arg(long, value_parser = parse_date_time_opt)]
    pub not_before: Option<OffsetDateTime>,
}

trait IsDefault {
    fn is_default(&self) -> bool;

    fn default_or(self) -> Option<Self>
    where
        Self: Sized,
    {
        if self.is_default() {
            return None;
        }

        Some(self)
    }
}

fn elapsed(
    formatter: &timeago::Formatter,
    now: OffsetDateTime,
    d: Option<time::OffsetDateTime>,
) -> String {
    d.map(|time| now - time)
        .and_then(|time| time.try_into().ok())
        .map_or_else(String::new, |d| formatter.convert(d))
}

fn map_tags(tags: &[(String, Option<String>)]) -> Option<HashMap<String, String>> {
    if tags.is_empty() {
        None
    } else {
        Some(HashMap::from_iter(tags.iter().map(|(k, v)| {
            (k.to_string(), v.clone().unwrap_or_default())
        })))
    }
}

fn map_vec<'a, T, U, F>(v: Option<&'a [T]>, f: F) -> Option<Vec<U>>
where
    U: From<&'a T>,
    F: FnMut(&'a T) -> U,
{
    match v {
        Some([]) => None,
        Some(v) => Some(v.iter().map(f).collect()),
        None => None,
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
