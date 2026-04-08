// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use super::VAULT_ENV_NAME;
use crate::credential;
use akv_cli::{
    jose::{Algorithm, Encode, EncryptionAlgorithm, Jwe},
    Error, ErrorKind, Result,
};
use azure_core::http::Url;
use azure_security_keyvault_keys::{models::KeyOperationParameters, KeyClient, ResourceId};
use clap::Parser;
use std::path::PathBuf;
use tokio::{
    fs,
    io::{self, AsyncReadExt as _},
};
use tracing::{Level, Span};

#[derive(Debug, Parser)]
pub struct Args {
    /// The key URL e.g., "https://my-vault.vault.azure.net/keys/my-key/version".
    ///
    /// The key URL must include a version.
    #[arg(group = "ident", value_name = "URL")]
    id: Option<Url>,

    /// The key name.
    #[arg(long, group = "ident", requires_all = ["vault", "version"])]
    name: Option<String>,

    /// The key version.
    #[arg(long, requires = "name")]
    version: Option<String>,

    /// The vault URL e.g., "https://my-vault.vault.azure.net".
    #[arg(long, value_name = "URL", env = VAULT_ENV_NAME)]
    vault: Option<Url>,

    /// The algorithm to encrypt the content encryption key (CEK).
    #[arg(long, value_enum, default_value_t = Algorithm::RSA_OAEP)]
    algorithm: Algorithm,

    /// The algorithm used to encrypt plaintext with the content encryption key (CEK).
    #[arg(long, value_enum, default_value_t = EncryptionAlgorithm::A128GCM)]
    encryption: EncryptionAlgorithm,

    /// The content to encrypt.
    #[arg(group = "input")]
    value: Option<String>,

    /// The file to encrypt or "-" to read from stdin.
    ///
    /// If you pass "-" without piping data to stdin, you can type a message and press `Ctrl+D` to end the stream.
    #[arg(short = 'i', long, group = "input", value_name = "PATH")]
    in_file: Option<PathBuf>,
}

impl Args {
    #[tracing::instrument(level = Level::INFO, skip(self), fields(vault, name, version, kid), err)]
    pub async fn encrypt(&self) -> Result<()> {
        let (vault_url, name, version) = match (
            self.id.as_ref(),
            self.vault.as_ref(),
            self.name.as_ref(),
            self.version.as_ref(),
        ) {
            (Some(id), _, _, _) => {
                let resource: ResourceId = id.try_into()?;
                let version = resource.version.ok_or_else(|| {
                    Error::with_message(ErrorKind::InvalidData, "key URL must include a version")
                })?;
                (resource.vault_url, resource.name, version)
            }
            (None, Some(vault), Some(name), Some(version)) => {
                (vault.as_str().to_string(), name.clone(), version.clone())
            }
            _ => {
                return Err(Error::with_message(
                    ErrorKind::InvalidData,
                    "specify a key URL or --name, --vault, and --version",
                ));
            }
        };

        let span = Span::current();
        span.record("vault", &vault_url);
        span.record("name", &name);
        span.record("version", &version);

        let plaintext: Vec<u8> = match (self.value.as_deref(), self.in_file.as_deref()) {
            (Some(value), _) => value.as_bytes().to_vec(),
            (_, Some(in_file)) if in_file.to_str() == Some("-") => {
                let mut buf = Vec::new();
                io::stdin().read_to_end(&mut buf).await?;

                buf
            }
            (_, Some(in_file)) => fs::read(in_file).await?,
            _ => panic!("inconceivable"),
        };

        let kid = format!(
            "{}/keys/{}/{version}",
            vault_url.trim_end_matches('/'),
            name
        );
        let client = KeyClient::new(&vault_url, credential()?, None)?;
        let jwe = Jwe::encryptor()
            .alg(self.algorithm.clone())
            .enc(self.encryption.clone())
            .kid(kid)
            .plaintext(&plaintext)
            .encrypt(async |_, enc, cek| {
                let params = KeyOperationParameters {
                    algorithm: Some(enc.try_into()?),
                    value: Some(cek.into()),
                    ..Default::default()
                };
                client
                    .wrap_key(&name, &version, params.try_into()?, None)
                    .await?
                    .into_model()?
                    .try_into()
            })
            .await?;

        span.record("kid", jwe.kid());
        println!("{}", jwe.encode()?);

        Ok(())
    }
}
