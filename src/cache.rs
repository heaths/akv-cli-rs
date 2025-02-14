// Copyright 2024 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use crate::ErrorKind;
use azure_security_keyvault_secrets::SecretClient;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone, Default)]
pub struct ClientCache {
    // Mutex should be fast enough for our needs of a CLI.
    cache: Arc<Mutex<HashMap<String, Arc<SecretClient>>>>,
}

impl ClientCache {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn get(&mut self, client: Arc<SecretClient>) -> crate::Result<Arc<SecretClient>> {
        let endpoint = client
            .endpoint()
            .host_str()
            .ok_or_else(|| {
                crate::Error::with_message(ErrorKind::InvalidData, "no host for SecretClient")
            })?
            .to_string();

        let mut cache = self
            .cache
            .lock()
            .map_err(|_| crate::Error::with_message(ErrorKind::Other, "failed to lock cache"))?;
        if let Some(c) = cache.get(&endpoint) {
            tracing::debug!(
                "found cached client for '{vault}'",
                vault = c.endpoint().as_str()
            );
            return Ok(c.clone());
        };

        tracing::debug!("caching new client for '{vault}'", vault = &endpoint,);
        cache.insert(endpoint, client.clone());
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azure_identity::DefaultAzureCredential;

    #[test]
    fn test_client_cache() {
        let credential = DefaultAzureCredential::new().unwrap();

        let mut cache = ClientCache::new();
        cache
            .get(Arc::new(
                SecretClient::new("https://vault1.vault.azure.net", credential.clone(), None)
                    .unwrap(),
            ))
            .expect("add first client");
        cache
            .get(Arc::new(
                SecretClient::new("https://vault2.vault.azure.net", credential.clone(), None)
                    .unwrap(),
            ))
            .expect("add first client");
        cache
            .get(Arc::new(
                SecretClient::new("https://vault1.vault.azure.net/", credential.clone(), None)
                    .unwrap(),
            ))
            .expect("add first client again");

        assert_eq!(cache.cache.lock().unwrap().len(), 2);
    }
}
