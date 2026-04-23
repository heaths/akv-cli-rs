// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use azure_core::time::OffsetDateTime;
use azure_security_keyvault_secrets::models::DeletionRecoveryLevel;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct Secret {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<SecretAttributes>,
    #[serde(rename = "contentType", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed: Option<bool>,
    #[serde(rename = "previousVersion", skip_serializing_if = "Option::is_none")]
    pub previous_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct SecretAttributes {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "azure_core::time::unix_time::option"
    )]
    pub created: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(
        default,
        rename = "exp",
        skip_serializing_if = "Option::is_none",
        with = "azure_core::time::unix_time::option"
    )]
    pub expires: Option<OffsetDateTime>,
    #[serde(
        default,
        rename = "nbf",
        skip_serializing_if = "Option::is_none",
        with = "azure_core::time::unix_time::option"
    )]
    pub not_before: Option<OffsetDateTime>,
    #[serde(rename = "recoverableDays", skip_serializing_if = "Option::is_none")]
    pub recoverable_days: Option<i32>,
    #[serde(rename = "recoveryLevel", skip_serializing_if = "Option::is_none")]
    pub recovery_level: Option<DeletionRecoveryLevel>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "azure_core::time::unix_time::option"
    )]
    pub updated: Option<OffsetDateTime>,
}

impl From<azure_security_keyvault_secrets::models::Secret> for Secret {
    fn from(value: azure_security_keyvault_secrets::models::Secret) -> Self {
        Secret {
            attributes: value.attributes.map(Into::into),
            content_type: value.content_type,
            id: value.id,
            kid: value.kid,
            managed: value.managed,
            previous_version: value.previous_version,
            tags: value.tags,
            value: value.value,
        }
    }
}

impl From<azure_security_keyvault_secrets::models::SecretAttributes> for SecretAttributes {
    fn from(value: azure_security_keyvault_secrets::models::SecretAttributes) -> Self {
        SecretAttributes {
            created: value.created,
            enabled: value.enabled,
            expires: value.expires,
            not_before: value.not_before,
            recoverable_days: value.recoverable_days,
            recovery_level: value.recovery_level,
            updated: value.updated,
        }
    }
}
