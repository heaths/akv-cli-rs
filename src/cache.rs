// Copyright 2024 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use azure_security_keyvault_secrets::SecretClient;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use url::Url;

#[derive(Clone, Default)]
pub struct ClientCache {
    // Mutex should be fast enough for our needs of a CLI.
    cache: Arc<Mutex<HashMap<String, Arc<SecretClient>>>>,
}

impl ClientCache {
    pub fn new() -> Self {
        Default::default()
    }

    pub async fn get<F>(
        &mut self,
        endpoint: impl AsRef<str>,
        f: F,
    ) -> crate::Result<Arc<SecretClient>>
    where
        F: FnOnce(&str) -> azure_core::Result<SecretClient>,
    {
        // Canonicalize the URL.
        let endpoint = Url::parse(endpoint.as_ref())?.to_string();
        let mut cache = self.cache.lock().await;
        if let Some(c) = cache.get(&endpoint) {
            tracing::debug!(target: "akv::cache", "found cached client for '{vault}'", vault = &endpoint);
            return Ok(c.clone());
        };

        let client = Arc::new(f(&endpoint)?);

        tracing::debug!(target: "akv::cache", "caching new client for '{vault}'", vault = &endpoint,);
        cache.insert(endpoint, client.clone());
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azure_identity::DefaultAzureCredential;

    #[tokio::test]
    async fn test_client_cache() {
        let credential = DefaultAzureCredential::new().unwrap();

        let mut cache = ClientCache::new();
        cache
            .get("https://vault1.vault.azure.net", |endpoint| {
                SecretClient::new(endpoint, credential.clone(), None)
            })
            .await
            .expect("add first client");
        cache
            .get("https://vault2.vault.azure.net", |endpoint| {
                SecretClient::new(endpoint, credential.clone(), None)
            })
            .await
            .expect("add first client");
        cache
            .get("https://vault1.vault.azure.net/", |endpoint| {
                SecretClient::new(endpoint, credential.clone(), None)
            })
            .await
            .expect("add first client again");

        assert_eq!(cache.cache.lock().await.len(), 2);
    }
}
