// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

mod secret;

use akv_cli::{get_secret, Error, Result};
use azure_core::Url;
use azure_identity::DefaultAzureCredential;
use azure_security_keyvault_secrets::{ResourceId, SecretClient};
use clap::Subcommand;
use std::{
    io::{self, Write},
    str::FromStr,
};

const VAULT_ENV_NAME: &str = "AZURE_KEYVAULT_URL";

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Manage secrets in an Azure Key Vault.
    #[command(subcommand)]
    Secret(secret::Commands),

    /// Read a secret from an Azure Key Vault.
    Read {
        /// The URL to a secret in Azure Key Vault e.g., "https://my-vault.vault.azure.net/secrets/my-secret".
        id: Url,

        /// Do not print a new line after the secret.
        #[arg(short = 'n', long)]
        no_newline: bool,
    },
}

impl Commands {
    pub async fn handle(&self) -> Result<()> {
        match self {
            Commands::Secret(items) => items.handle().await,
            Commands::Read { .. } => self.read().await,
        }
    }

    async fn read(&self) -> Result<()> {
        let Commands::Read { id, no_newline } = self else {
            panic!("invalid command");
        };
        let id: ResourceId = id.try_into()?;

        let client = SecretClient::new(&id.vault_url, DefaultAzureCredential::new()?, None)?;
        let secret = get_secret(&client, id.name.as_ref(), id.version.as_deref()).await?;
        if let Some(value) = secret.value {
            if *no_newline {
                print!("{value}");
                return Ok(io::stdout().flush()?);
            }

            println!("{value}");
        }

        Ok(())
    }
}

fn parse_key_value<T>(value: &str) -> Result<(String, T)>
where
    T: FromStr,
    Error: From<<T as FromStr>::Err>,
{
    let idx = value
        .find("=")
        .ok_or_else(|| format!("no '=' found in '{value}'"))?;
    Ok((value[..idx].to_string(), value[idx + 1..].parse()?))
}

#[test]
fn test_parse_key_value() {
    let kv = parse_key_value::<String>("key=value");
    assert!(matches!(kv, Ok(kv) if kv.0 == "key" && kv.1 == "value"));

    let kv = parse_key_value::<String>("key=value=other");
    assert!(matches!(kv, Ok(kv) if kv.0 == "key" && kv.1 == "value=other"));

    parse_key_value::<String>("key").expect_err("requires '='");

    let k = parse_key_value::<i32>("key=1");
    assert!(matches!(k, Ok(k) if k.0 == "key" && k.1 == 1));

    parse_key_value::<i32>("key=value").expect_err("should not parse 'value' as i32");
}

fn parse_key_value_opt<T>(value: &str) -> Result<(String, Option<T>)>
where
    T: FromStr,
    Error: From<<T as FromStr>::Err>,
{
    if let Some(idx) = value.find("=") {
        return Ok((value[..idx].to_string(), Some(value[idx + 1..].parse()?)));
    }

    Ok((value.to_string(), None))
}

#[test]
fn test_parse_key_value_opt() {
    let kv = parse_key_value_opt::<String>("key=value");
    assert!(matches!(kv, Ok(kv) if kv.0 == "key" && kv.1 == Some("value".into())));

    let kv = parse_key_value_opt::<String>("key=value=other");
    assert!(matches!(kv, Ok(kv) if kv.0 == "key" && kv.1 == Some("value=other".into())));

    let k = parse_key_value_opt::<i32>("key");
    assert!(matches!(k, Ok(k) if k.0 == "key" && k.1.is_none()));

    parse_key_value_opt::<i32>("key=value").expect_err("should not parse 'value' as i32");
}
