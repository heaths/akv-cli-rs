// Copyright 2024 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use url::Url;

#[derive(Default)]
pub struct ClientCache<T> {
    // Mutex should be fast enough for our needs of a CLI.
    cache: Arc<Mutex<HashMap<String, Arc<T>>>>,
}

impl<T> ClientCache<T> {
    pub fn new() -> Self {
        Self {
            cache: Default::default(),
        }
    }

    pub async fn get<F>(&self, endpoint: impl AsRef<str>, f: F) -> crate::Result<Arc<T>>
    where
        F: FnOnce(&str) -> azure_core::Result<T>,
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

impl<T> Clone for ClientCache<T> {
    fn clone(&self) -> Self {
        Self {
            cache: self.cache.clone(),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use azure_identity::DefaultAzureCredential;
    use azure_security_keyvault_secrets::SecretClient;

    #[tokio::test]
    async fn test_client_cache() {
        let credential = DefaultAzureCredential::new().unwrap();

        let cache = ClientCache::<SecretClient>::new();
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
