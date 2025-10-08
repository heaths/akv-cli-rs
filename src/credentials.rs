// Copyright 2024 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use async_lock::RwLock;
use azure_core::{
    credentials::{AccessToken, TokenCredential, TokenRequestOptions},
    error::{Error, ErrorKind},
};
use azure_identity::{
    AzureCliCredential, AzureCliCredentialOptions, AzureDeveloperCliCredential,
    AzureDeveloperCliCredentialOptions,
};
use std::sync::{Arc, LazyLock};
use tracing::Instrument;

#[derive(Debug)]
pub struct DeveloperCredential {
    options: Option<DeveloperCredentialOptions>,
    credential: RwLock<Option<Arc<dyn TokenCredential>>>,
}

impl DeveloperCredential {
    pub fn new(options: Option<DeveloperCredentialOptions>) -> Arc<Self> {
        Arc::new(Self {
            options,
            credential: RwLock::new(None),
        })
    }
}

#[async_trait::async_trait]
impl TokenCredential for DeveloperCredential {
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        if let Some(credential) = self.credential.read().await.as_ref() {
            return credential.get_token(scopes, options).await;
        }

        let mut lock = self.credential.write().await;
        if let Some(credential) = lock.as_ref() {
            return credential.get_token(scopes, options).await;
        }

        let mut errors = Vec::new();
        for (name, f) in CREDENTIALS.iter() {
            let options = options.clone();
            match async {
                match f(self.options.as_ref()) {
                    Ok(c) => match c.get_token(scopes, options).await {
                        Ok(token) => {
                            tracing::debug!(target: "akv::credentials", "acquired token");
                            *lock = Some(c);
                            Ok(token)
                        }
                        Err(err) => {
                            tracing::debug!(target: "akv::credentials", "failed acquiring token: {err}");
                            Err(err)
                        }
                    },
                    Err(err) => {
                        tracing::debug!(target: "akv::credentials", "failed creating credential: {err}");
                        Err(err)
                    }
                }
            }
            .instrument(tracing::debug_span!(target: "akv::credentials", "trying credential", name))
            .await
            {
                Ok(token) => return Ok(token),
                Err(err) => errors.push(err),
            }
        }

        Err(Error::with_message_fn(ErrorKind::Credential, || {
            format!(
                "Multiple errors when attempting to authenticate:\n{}",
                aggregate(&errors)
            )
        }))
    }
}

#[derive(Debug, Default)]
pub struct DeveloperCredentialOptions {
    pub subscription: Option<String>,
    pub tenant_id: Option<String>,
    pub additionally_allowed_tenants: Vec<String>,
}

impl From<&DeveloperCredentialOptions> for AzureCliCredentialOptions {
    fn from(options: &DeveloperCredentialOptions) -> Self {
        AzureCliCredentialOptions {
            subscription: options.subscription.clone(),
            tenant_id: options.tenant_id.clone(),
            additionally_allowed_tenants: options.additionally_allowed_tenants.clone(),
            ..Default::default()
        }
    }
}

impl From<&DeveloperCredentialOptions> for AzureDeveloperCliCredentialOptions {
    fn from(options: &DeveloperCredentialOptions) -> Self {
        AzureDeveloperCliCredentialOptions {
            tenant_id: options.tenant_id.clone(),
            ..Default::default()
        }
    }
}

type CredentialFn = (
    &'static str,
    Box<
        dyn Fn(Option<&DeveloperCredentialOptions>) -> azure_core::Result<Arc<dyn TokenCredential>>
            + Send
            + Sync
            + 'static,
    >,
);

static CREDENTIALS: LazyLock<Vec<CredentialFn>> = LazyLock::new(|| {
    // Though az is likely more common, try azd first because it fails faster if even in $PATH.
    // This is reverse of DefaultAzureCredential because azd was added long after az and compat was a concern.
    vec![
        (
            "AzureDeveloperCliCredential",
            Box::new(|options| Ok(AzureDeveloperCliCredential::new(options.map(Into::into))?)),
        ),
        (
            "AzureCliCredential",
            Box::new(|options| Ok(AzureCliCredential::new(options.map(Into::into))?)),
        ),
    ]
});

fn aggregate(errors: &[Error]) -> String {
    use std::error::Error;
    errors
        .iter()
        .map(|err| {
            let mut current: Option<&dyn Error> = Some(err);
            let mut stack = vec![];
            while let Some(err) = current.take() {
                stack.push(err.to_string());
                current = err.source();
            }
            stack.join(" - ")
        })
        .collect::<Vec<String>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_multiple_errors() {
        let errors = vec![
            Error::with_error(
                ErrorKind::Other,
                Error::with_message(ErrorKind::Other, "first inner error"),
                "first outer error",
            ),
            Error::with_message(ErrorKind::Other, "second error"),
        ];
        assert_eq!(
            aggregate(&errors),
            "first outer error - first inner error\nsecond error"
        );
    }
}
