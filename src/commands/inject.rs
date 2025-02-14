// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use super::VAULT_ENV_NAME;
use akv_cli::{cache::ClientCache, get_secret, ErrorKind, Result};
use azure_core::Url;
use azure_identity::DefaultAzureCredential;
use azure_security_keyvault_secrets::{ResourceId, SecretClient};
use clap::Parser;
use futures::{future::BoxFuture, FutureExt};
use std::{
    fs,
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

        replace(&input, &mut output, |var| {
            let mut cache = cache.clone();
            let credentials = credentials.clone();
            async move {
                let id: ResourceId = var.parse()?;
                let client = cache.get(Arc::new(SecretClient::new(
                    &id.vault_url,
                    credentials.clone(),
                    None,
                )?))?;
                let secret = get_secret(&client, &id.name, id.version.as_deref()).await?;

                Ok(secret.value.unwrap_or_else(String::new))
            }
            .boxed()
        })
        .await
    }
}

async fn replace<W, F>(mut s: &str, w: &mut W, f: F) -> akv_cli::Result<()>
where
    W: io::Write,
    F: Fn(&str) -> BoxFuture<'_, akv_cli::Result<String>>,
{
    while let Some(mut start) = s.find("{{") {
        // Start only after the first "{{".
        let Some(mut end) = s[start + 2..].find("}}") else {
            return Err(akv_cli::Error::with_message(
                ErrorKind::InvalidData,
                "missing closing '}}'",
            ));
        };
        end += start + 2;

        w.write_all(s[..start].as_bytes())?;
        start += 2;

        let id = s[start..end].trim();
        let secret = f(id).await?;

        w.write_all(secret.as_bytes())?;
        end += 2;

        s = &s[end..];
    }

    w.write_all(s.as_bytes())?;
    Ok(())
}

#[tokio::test]
async fn test_replace() {
    let s = "Hello, {{ var }}!";
    let mut buf = Vec::new();

    replace(s, &mut buf, |v| {
        assert_eq!(v, "var");
        async { Ok(String::from("world")) }.boxed()
    })
    .await
    .unwrap();
    assert_eq!(String::from_utf8(buf).unwrap(), "Hello, world!");
}

#[tokio::test]
async fn test_replace_overlap() {
    let s = "Hello, {{ {{var}} }}!";
    let mut buf = Vec::new();

    replace(s, &mut buf, |v| {
        assert_eq!(v, "{{var");
        async { Ok(String::from("world")) }.boxed()
    })
    .await
    .unwrap();
    assert_eq!(String::from_utf8(buf).unwrap(), "Hello, world }}!");
}

#[tokio::test]
async fn test_replace_missing_end() {
    let s = "Hello, {{ var!";
    let mut buf = Vec::new();

    replace(s, &mut buf, |_| async { Ok(String::from("world")) }.boxed())
        .await
        .expect_err("missing end");
}

#[tokio::test]
async fn test_replace_missing_empty() {
    let s = "";
    let mut buf = Vec::new();

    replace(s, &mut buf, |_| async { Ok(String::from("world")) }.boxed())
        .await
        .unwrap();
    assert_eq!(String::from_utf8(buf).unwrap(), "");
}

#[tokio::test]
async fn test_replace_missing_no_template() {
    let s = "Hello, world!";
    let mut buf = Vec::new();

    replace(s, &mut buf, |_| {
        async { Ok(String::from("Ferris")) }.boxed()
    })
    .await
    .unwrap();
    assert_eq!(String::from_utf8(buf).unwrap(), "Hello, world!");
}
