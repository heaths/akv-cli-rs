// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

#![cfg_attr(windows, feature(windows_process_extensions_raw_attribute))]

pub mod cache;
mod error;
pub mod parsing;
pub mod pty;

use async_stream::try_stream;
use azure_security_keyvault_secrets::{models::SecretProperties, SecretClient};
pub use error::*;
use futures::{Stream, StreamExt as _};
use std::pin::Pin;
use tracing::Level;

#[tracing::instrument(level = Level::INFO, skip(client), fields(vault = %client.endpoint()))]
pub fn list_secrets(
    client: &SecretClient,
    include_managed: bool,
) -> Pin<Box<impl Stream<Item = Result<SecretProperties>> + '_>> {
    Box::pin(try_stream! {
        let mut pager = client.list_secret_properties(None)?;
        while let Some(page) = pager.next().await {
            let result = page?.into_body().await?;
                for secret in result.value {
                    if !include_managed && secret.managed == Some(true) {
                        continue;
                    }
                    yield secret;
                }
        }
    })
}

#[tracing::instrument(level = Level::INFO, skip(client), fields(vault = %client.endpoint()))]
pub fn list_secret_versions<'a>(
    client: &'a SecretClient,
    name: &'a str,
) -> Pin<Box<impl Stream<Item = Result<SecretProperties>> + 'a>> {
    Box::pin(try_stream! {
        let mut pager = client.list_secret_properties_versions(name, None)?;
        while let Some(page) = pager.next().await {
            let result = page?.into_body().await?;
                for secret in result.value {
                    yield secret;
                }
            }
    })
}
