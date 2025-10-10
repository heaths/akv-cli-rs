// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use super::VAULT_ENV_NAME;
use crate::credential;
use akv_cli::{
    jose::{Algorithm, Encode, EncryptionAlgorithm, Jwe},
    Result,
};
use azure_core::http::Url;
use azure_security_keyvault_keys::{
    models::{KeyClientWrapKeyOptions, KeyOperationParameters},
    KeyClient,
};
use clap::Parser;
use std::path::PathBuf;
use tokio::{
    fs,
    io::{self, AsyncReadExt as _},
};
use tracing::{Level, Span};

#[derive(Debug, Parser)]
pub struct Args {
    /// The key name.
    #[arg(long)]
    name: String,

    /// The key version.
    ///
    /// By default, the latest is used and the full key ID is encoded into the JWE to prevent data-lockout.
    #[arg(long)]
    version: Option<String>,

    /// The vault URL e.g., "https://my-vault.vault.azure.net".
    #[arg(long, value_name = "URL", env = VAULT_ENV_NAME)]
    vault: Url,

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
    #[tracing::instrument(level = Level::INFO, skip(self), fields(vault = %self.vault, name = self.name, version, kid), err)]
    pub async fn encrypt(&self) -> Result<()> {
        let version = self.version.as_deref().unwrap_or_default();
        let span = Span::current();
        span.record("version", version);

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

        let client = KeyClient::new(self.vault.as_str(), credential(), None)?;
        let jwe = Jwe::encryptor()
            .alg(self.algorithm.clone())
            .enc(self.encryption.clone())
            .kid(format!(
                "https://{}/keys/{}/{version}",
                self.vault, self.name
            ))
            .plaintext(&plaintext)
            .encrypt(async |_, enc, cek| {
                let params = KeyOperationParameters {
                    algorithm: Some(enc.try_into()?),
                    value: Some(cek.into()),
                    ..Default::default()
                };
                client
                    .wrap_key(
                        &self.name,
                        params.try_into()?,
                        Some(KeyClientWrapKeyOptions {
                            key_version: Some(version.into()),
                            ..Default::default()
                        }),
                    )
                    .await?
                    .into_body()?
                    .try_into()
            })
            .await?;

        span.record("kid", jwe.kid());
        println!("{}", jwe.encode()?);

        Ok(())
    }
}
