// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use super::*;
use crate::Args;
use azure_core::http::{headers::Headers, AsyncRawResponse, StatusCode};
use azure_security_keyvault_secrets::{clients::fake::SecretServer, models};
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn get_secret() -> crate::Result<()> {
    let client = SecretClient::with_fake(
        "https://my-vault.vault.azure.net",
        Arc::new(FakeSecretClient),
        None,
    )?;
    let _ = super::CLIENT.set(client);
    let args = Args {
        command: crate::Commands::Secret(Commands::Get {
            id: None,
            name: Some("my-secret".into()),
            vault: Some("https://my-vault.vault.azure.net".parse()?),
            version: None,
            output: OutputFormat::Default,
        }),
        color: Default::default(),
        verbose: 0,
    };
    args.handle().await?;

    Ok(())
}

struct FakeSecretClient;

#[async_trait::async_trait]
impl SecretServer for FakeSecretClient {
    async fn get_secret(
        &self,
        secret_name: &str,
        _options: Option<models::SecretClientGetSecretOptions<'_>>,
    ) -> azure_core::Result<AsyncRawResponse> {
        assert_eq!(secret_name, "my-secret");
        Ok(AsyncRawResponse::from_bytes(
            StatusCode::Ok,
            Headers::new(),
            json!({
                "id": "https://my-vault.vault.azure.net/secrets/my-secret/secret-version",
                "value": "secret-value",
            })
            .to_string(),
        ))
    }
}
