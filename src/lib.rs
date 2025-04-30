// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

#![cfg_attr(windows, feature(windows_process_extensions_raw_attribute))]

pub mod cache;
mod error;
pub mod jwt;
pub mod parsing;
pub mod pty;

use async_stream::try_stream;
use azure_core::http::{Model, Pager};
use azure_security_keyvault_secrets::models::{ListSecretPropertiesResult, SecretProperties};
pub use error::*;
use futures::{Stream, StreamExt as _};
use std::pin::Pin;

pub trait Page<T> {
    fn items(self) -> impl Iterator<Item = T>;
}

impl Page<SecretProperties> for ListSecretPropertiesResult {
    fn items(self) -> impl Iterator<Item = SecretProperties> {
        self.value.into_iter()
    }
}

pub fn list_items<R, T, F, E>(f: F) -> Pin<Box<impl Stream<Item = Result<T>>>>
where
    R: Model + Page<T>,
    F: AsyncFn() -> std::result::Result<Pager<R>, E>,
    E: Into<Error>,
{
    Box::pin(try_stream! {
        let mut pager = f().await?;
        while let Some(page) = pager.next().await {
            let result = page?.into_body().await?;
            for item in result.items() {
                yield item;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use azure_core::{
        credentials::{AccessToken, TokenCredential},
        http::{
            headers::Headers, ClientOptions, HttpClient, Request, Response, StatusCode,
            TransportOptions,
        },
        Bytes,
    };
    use azure_security_keyvault_secrets::{SecretClient, SecretClientOptions};
    use futures::TryStreamExt as _;
    use std::{collections::VecDeque, sync::Arc};
    use time::{Duration, OffsetDateTime};
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn list_secret_properties() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Set up mock responses.
        let options = mock_list_secret_properties();

        // Credentials return an Arc to promote sharing between clients.
        let credential = MockCredential::new()?;

        let client = SecretClient::new(
            "https://my-vault.vault.azure.net",
            credential.clone(),
            Some(options),
        )?;
        let secret_properties: Vec<SecretProperties> =
            list_items(async || client.list_secret_properties(None))
                .try_collect()
                .await?;
        assert_eq!(secret_properties.len(), 3);

        Ok(())
    }

    #[derive(Debug)]
    struct MockCredential;

    impl MockCredential {
        fn new() -> azure_core::Result<Arc<Self>> {
            Ok(Arc::new(MockCredential))
        }
    }

    #[async_trait::async_trait]
    impl TokenCredential for MockCredential {
        async fn get_token(&self, _scopes: &[&str]) -> azure_core::Result<AccessToken> {
            Ok(AccessToken {
                token: "mock-token".into(),
                expires_on: OffsetDateTime::now_utc() + Duration::minutes(2),
            })
        }
    }

    #[derive(Debug)]
    struct MockTransport {
        responses: Arc<Mutex<VecDeque<Response>>>,
    }

    impl MockTransport {
        fn new(responses: &[(StatusCode, &'static [u8])]) -> Self {
            let responses = VecDeque::from_iter(responses.iter().map(|(status, body)| {
                Response::from_bytes(*status, Headers::new(), Bytes::from_static(body))
            }));
            Self {
                responses: Arc::new(Mutex::new(responses)),
            }
        }
    }

    #[async_trait::async_trait]
    impl HttpClient for MockTransport {
        async fn execute_request(&self, _: &Request) -> azure_core::Result<Response> {
            let mut responses = self.responses.lock().await;
            Ok(responses.pop_front().expect("expected response"))
        }
    }

    fn mock_list_secret_properties() -> SecretClientOptions {
        let transport = Arc::new(MockTransport::new(&[
            (
                StatusCode::Ok,
                br#"{
                    "value": [
                        {"id": "https://my-vault.vault.azure.net/secrets/foo/1"},
                        {"id": "https://my-vault.vault.azure.net/secrets/bar/1"}
                    ],
                    "nextLink": "https://my-vault.azure.net/secrets?page=2"
                }"#,
            ),
            (
                StatusCode::Ok,
                br#"{
                    "value": [],
                    "nextLink": "https://my-vault.azure.net/secrets?page=3"
                }"#,
            ),
            (
                StatusCode::Ok,
                br#"{
                    "value": [
                        {"id": "https://my-vault.vault.azure.net/secrets/baz/1"}
                    ]
                }"#,
            ),
        ]));
        SecretClientOptions {
            client_options: ClientOptions {
                transport: Some(TransportOptions::new(transport)),
                ..Default::default()
            },
            ..Default::default()
        }
    }
}
