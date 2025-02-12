// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

mod error;

use async_stream::try_stream;
use azure_security_keyvault_secrets::{
    models::{SecretBundle, SecretItem},
    SecretClient,
};
pub use error::*;
use futures::{Stream, StreamExt};
use tracing::Level;

#[tracing::instrument(level = Level::INFO, skip(client), fields(vault = %client.endpoint()))]
pub fn list_secrets(client: &SecretClient) -> impl Stream<Item = Result<SecretItem>> + '_ {
    try_stream! {
        let mut pager = client.get_secrets(None)?;
        while let Some(page) = pager.next().await {
            let result = page?.into_body().await?;
            if let Some(secrets) = result.value {
                for secret in secrets {
                    yield secret;
                }
            }
        }
    }
}

#[tracing::instrument(level = Level::INFO, skip(client), fields(vault = %client.endpoint()), err)]
pub async fn get_secret(
    client: &SecretClient,
    name: &str,
    version: Option<&str>,
) -> Result<SecretBundle> {
    Ok(client
        .get_secret(name, version.unwrap_or_default(), None)
        .await?
        .into_body()
        .await?)
}
