// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

mod inject;
mod read;
mod secret;

use akv_cli::{Error, ErrorKind, Result};
use azure_security_keyvault_secrets::ResourceId;
use clap::Subcommand;
use std::{borrow::Cow, str::FromStr};
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
}

impl Commands {
    pub async fn handle(&self) -> Result<()> {
        match self {
            Commands::Secret(command) => command.handle().await,
            Commands::Inject(args) => args.inject().await,
            Commands::Read(args) => args.read().await,
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
