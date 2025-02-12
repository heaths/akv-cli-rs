// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

mod error;

use azure_security_keyvault_secrets::{
    models::{SecretBundle, SecretItem},
    SecretClient,
};
pub use error::*;
use futures::{stream, TryStream};
use tracing::Level;

#[tracing::instrument(level = Level::INFO, skip(client), fields(vault = %client.endpoint()))]
pub async fn list_secrets(client: &SecretClient) -> impl TryStream {
    stream::empty::<Result<SecretItem>>()
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
