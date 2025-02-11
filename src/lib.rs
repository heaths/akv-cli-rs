// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

mod error;

use azure_core::Url;
use azure_security_keyvault_secrets::{
    models::{SecretBundle, SecretItem},
    SecretClient,
};
pub use error::*;
use futures::{stream, TryStream};

pub async fn list_secrets(_client: &SecretClient) -> impl TryStream {
    stream::empty::<Result<SecretItem>>()
}

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

pub fn deconstruct(url: Url) -> Result<(String, String, Option<String>)> {
    let vault_url = format!("{}://{}", url.scheme(), url.authority(),);
    let mut segments = url
        .path_segments()
        .ok_or_else(|| Error::with_message(ErrorKind::InvalidData, "invalid URL"))?;
    segments
        .next()
        .and_then(none_if_empty)
        .ok_or_else(|| Error::with_message(ErrorKind::Other, "missing collection"))
        .and_then(|col| {
            if col != "secrets" {
                return Err(Error::with_message(
                    ErrorKind::Other,
                    "not in secrets collection",
                ));
            }
            Ok(col)
        })?;
    let name = segments
        .next()
        .and_then(none_if_empty)
        .ok_or_else(|| Error::with_message(ErrorKind::Other, "missing name"))
        .map(String::from)?;
    let version = segments.next().and_then(none_if_empty).map(String::from);

    Ok((vault_url, name, version))
}

fn none_if_empty(s: &str) -> Option<&str> {
    if s.is_empty() {
        return None;
    }

    Some(s)
}

#[test]
fn test_deconstruct() {
    deconstruct("file:///tmp".parse().unwrap()).expect_err("cannot-be-base url");
    deconstruct("https://vault.azure.net/".parse().unwrap()).expect_err("missing collection");
    deconstruct("https://vault.azure.net/collection/".parse().unwrap())
        .expect_err("invalid collection");
    deconstruct("https://vault.azure.net/secrets/".parse().unwrap()).expect_err("missing name");

    let url: Url = "https://vault.azure.net/secrets/name".parse().unwrap();
    assert_eq!(
        deconstruct(url.clone()).unwrap(),
        ("https://vault.azure.net".into(), "name".into(), None)
    );

    let url: Url = "https://vault.azure.net/secrets/name/version"
        .parse()
        .unwrap();
    assert_eq!(
        deconstruct(url.clone()).unwrap(),
        (
            "https://vault.azure.net".into(),
            "name".into(),
            Some("version".into())
        )
    );

    let url: Url = "https://vault.azure.net:443/secrets/name/version"
        .parse()
        .unwrap();
    assert_eq!(
        deconstruct(url.clone()).unwrap(),
        (
            "https://vault.azure.net".into(),
            "name".into(),
            Some("version".into())
        )
    );

    let url: Url = "https://vault.azure.net:8443/secrets/name/version"
        .parse()
        .unwrap();
    assert_eq!(
        deconstruct(url.clone()).unwrap(),
        (
            "https://vault.azure.net:8443".into(),
            "name".into(),
            Some("version".into())
        )
    );
}
