// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use crate::credential;
use akv_cli::{
    jose::{Encode, Jwe},
    Error, ErrorKind, Result,
};
use azure_core::http::Url;
use azure_security_keyvault_keys::{
    models::{KeyClientUnwrapKeyOptions, KeyOperationParameters},
    KeyClient, ResourceId,
};
use clap::Parser;
use std::{
    io::{self, Write as _},
    path::PathBuf,
};
use tokio::{fs, io::AsyncWriteExt as _};
use tracing::{Level, Span};

#[derive(Debug, Parser)]
pub struct Args {
    /// The compact JSON Web Encryption (JWE) token to decrypt.
    ///
    /// The JWE must specify a key ID including a version referencing Key Vault,
    /// and must use support algorithms supported by Key Vault. See `encrypt --help` for details.
    #[arg()]
    value: String,

    /// Do not print a new line after the content.
    #[arg(short = 'n', long)]
    no_newline: bool,

    /// Write the content to a file instead of stdout.
    #[arg(short = 'o', long, value_name = "PATH")]
    out_file: Option<PathBuf>,

    /// Force overwriting an existing file.
    #[arg(short = 'f', long)]
    force: bool,
}

impl Args {
    #[tracing::instrument(level = Level::INFO, skip(self), fields(kid), err)]
    pub async fn decrypt(&self) -> Result<()> {
        let span = Span::current();

        let jwe = Jwe::decode(&self.value)?;
        let plaintext = jwe
            .decrypt(async |kid, alg, cek| {
                let kid: Url = kid.parse()?;
                span.record("kid", kid.as_str());

                let ResourceId {
                    vault_url,
                    name,
                    version,
                    ..
                } = kid.try_into()?;

                let params = KeyOperationParameters {
                    algorithm: Some(alg.try_into()?),
                    value: Some(cek.into()),
                    ..Default::default()
                };

                let client = KeyClient::new(&vault_url, credential()?, None)?;
                client
                    .unwrap_key(
                        &name,
                        params.try_into()?,
                        Some(KeyClientUnwrapKeyOptions {
                            key_version: version,
                            ..Default::default()
                        }),
                    )
                    .await?
                    .into_model()?
                    .try_into()
            })
            .await?;

        match (
            String::from_utf8(plaintext.to_vec()),
            self.out_file.as_ref(),
        ) {
            // Write to a file.
            (_, Some(path)) => {
                let mut file = fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .create_new(!self.force)
                    .open(path)
                    .await?;
                file.write_all(&plaintext).await?;
            }

            // Print to stdout without a newline.
            (Ok(plaintext), _) if self.no_newline => {
                print!("{plaintext}");
                io::stdout().flush()?;
            }

            // Print line to stdout.
            (Ok(plaintext), _) => println!("{plaintext}"),

            (Err(err), None) => {
                return Err(Error::with_error_fn(ErrorKind::Other, err, || {
                    "failed to decode string; save to a file using `--out-file`"
                }))
            }
        }

        Ok(())
    }
}
