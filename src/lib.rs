// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

mod error;

use azure_security_keyvault_secrets::{
    models::{SecretBundle, SecretItem},
    SecretClient,
};
pub use error::*;
use futures::{stream, Stream, StreamExt, TryStreamExt};
use tracing::Level;

#[tracing::instrument(level = Level::INFO, skip(client), fields(vault = %client.endpoint()))]
pub fn list_secrets(client: &SecretClient) -> impl Stream<Item = Result<SecretItem>> {
    stream::try_unfold(Some(client.get_secrets(None)), move |pager| async move {
        if let Some(mut pager) = pager {
            let Some(result) = pager?.next().await else {
                return Ok(None);
            };
            let list = result?.into_body().await?;
            let items = list.value.into_iter().map(Ok);
            let next_pager = if list.next_link.is_some() {
                Some(pager)
            } else {
                None
            };
            Ok(Some((stream::iter(items), next_pager)))
        } else {
            Ok(None)
        }
    })
    .try_flatten()
    .map_ok(|items| items.into_iter())
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
