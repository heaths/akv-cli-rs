// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use azure_core::{base64, time::OffsetDateTime};
use azure_security_keyvault_keys::models as sdk;
use azure_security_keyvault_keys::models::{CurveName, DeletionRecoveryLevel, KeyType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct JsonWebKey {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<CurveName>,
    #[serde(
        default,
        deserialize_with = "base64::option::deserialize_url_safe",
        serialize_with = "base64::option::serialize_url_safe",
        skip_serializing_if = "Option::is_none"
    )]
    pub d: Option<Vec<u8>>,
    #[serde(
        default,
        deserialize_with = "base64::option::deserialize_url_safe",
        serialize_with = "base64::option::serialize_url_safe",
        skip_serializing_if = "Option::is_none"
    )]
    pub dp: Option<Vec<u8>>,
    #[serde(
        default,
        deserialize_with = "base64::option::deserialize_url_safe",
        serialize_with = "base64::option::serialize_url_safe",
        skip_serializing_if = "Option::is_none"
    )]
    pub dq: Option<Vec<u8>>,
    #[serde(
        default,
        deserialize_with = "base64::option::deserialize_url_safe",
        serialize_with = "base64::option::serialize_url_safe",
        skip_serializing_if = "Option::is_none"
    )]
    pub e: Option<Vec<u8>>,
    #[serde(
        default,
        deserialize_with = "base64::option::deserialize_url_safe",
        serialize_with = "base64::option::serialize_url_safe",
        skip_serializing_if = "Option::is_none"
    )]
    pub k: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kty: Option<KeyType>,
    #[serde(
        default,
        deserialize_with = "base64::option::deserialize_url_safe",
        serialize_with = "base64::option::serialize_url_safe",
        skip_serializing_if = "Option::is_none"
    )]
    pub n: Option<Vec<u8>>,
    #[serde(
        default,
        deserialize_with = "base64::option::deserialize_url_safe",
        serialize_with = "base64::option::serialize_url_safe",
        skip_serializing_if = "Option::is_none"
    )]
    pub p: Option<Vec<u8>>,
    #[serde(
        default,
        deserialize_with = "base64::option::deserialize_url_safe",
        serialize_with = "base64::option::serialize_url_safe",
        skip_serializing_if = "Option::is_none"
    )]
    pub q: Option<Vec<u8>>,
    #[serde(
        default,
        deserialize_with = "base64::option::deserialize_url_safe",
        serialize_with = "base64::option::serialize_url_safe",
        skip_serializing_if = "Option::is_none"
    )]
    pub qi: Option<Vec<u8>>,
    #[serde(
        default,
        deserialize_with = "base64::option::deserialize_url_safe",
        rename = "key_hsm",
        serialize_with = "base64::option::serialize_url_safe",
        skip_serializing_if = "Option::is_none"
    )]
    pub t: Option<Vec<u8>>,
    #[serde(
        default,
        deserialize_with = "base64::option::deserialize_url_safe",
        serialize_with = "base64::option::serialize_url_safe",
        skip_serializing_if = "Option::is_none"
    )]
    pub x: Option<Vec<u8>>,
    #[serde(
        default,
        deserialize_with = "base64::option::deserialize_url_safe",
        serialize_with = "base64::option::serialize_url_safe",
        skip_serializing_if = "Option::is_none"
    )]
    pub y: Option<Vec<u8>>,
}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct Key {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<KeyAttributes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<JsonWebKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_policy: Option<KeyReleasePolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashMap<String, String>>,
}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct KeyAttestation {
    #[serde(
        default,
        deserialize_with = "base64::option::deserialize_url_safe",
        rename = "certificatePemFile",
        serialize_with = "base64::option::serialize_url_safe",
        skip_serializing_if = "Option::is_none"
    )]
    pub certificate_pem_file: Option<Vec<u8>>,
    #[serde(
        default,
        deserialize_with = "base64::option::deserialize_url_safe",
        rename = "privateKeyAttestation",
        serialize_with = "base64::option::serialize_url_safe",
        skip_serializing_if = "Option::is_none"
    )]
    pub private_key_attestation: Option<Vec<u8>>,
    #[serde(
        default,
        deserialize_with = "base64::option::deserialize_url_safe",
        rename = "publicKeyAttestation",
        serialize_with = "base64::option::serialize_url_safe",
        skip_serializing_if = "Option::is_none"
    )]
    pub public_key_attestation: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct KeyAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<KeyAttestation>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exportable: Option<bool>,
    #[serde(rename = "hsmPlatform", skip_serializing_if = "Option::is_none")]
    pub hsm_platform: Option<String>,
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

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct KeyReleasePolicy {
    #[serde(rename = "contentType", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(
        default,
        deserialize_with = "base64::option::deserialize_url_safe",
        rename = "data",
        serialize_with = "base64::option::serialize_url_safe",
        skip_serializing_if = "Option::is_none"
    )]
    pub encoded_policy: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub immutable: Option<bool>,
}

impl From<sdk::Key> for Key {
    fn from(value: sdk::Key) -> Self {
        Key {
            attributes: value.attributes.map(Into::into),
            key: value.key.map(Into::into),
            managed: value.managed,
            release_policy: value.release_policy.map(Into::into),
            tags: value.tags,
        }
    }
}

impl From<sdk::KeyAttributes> for KeyAttributes {
    fn from(value: sdk::KeyAttributes) -> Self {
        KeyAttributes {
            attestation: value.attestation.map(Into::into),
            created: value.created,
            enabled: value.enabled,
            expires: value.expires,
            exportable: value.exportable,
            hsm_platform: value.hsm_platform,
            not_before: value.not_before,
            recoverable_days: value.recoverable_days,
            recovery_level: value.recovery_level,
            updated: value.updated,
        }
    }
}

impl From<sdk::KeyAttestation> for KeyAttestation {
    fn from(value: sdk::KeyAttestation) -> Self {
        KeyAttestation {
            certificate_pem_file: value.certificate_pem_file,
            private_key_attestation: value.private_key_attestation,
            public_key_attestation: value.public_key_attestation,
            version: value.version,
        }
    }
}

impl From<sdk::JsonWebKey> for JsonWebKey {
    fn from(value: sdk::JsonWebKey) -> Self {
        JsonWebKey {
            crv: value.crv,
            d: value.d,
            dp: value.dp,
            dq: value.dq,
            e: value.e,
            k: value.k,
            key_ops: value.key_ops,
            kid: value.kid,
            kty: value.kty,
            n: value.n,
            p: value.p,
            q: value.q,
            qi: value.qi,
            t: value.t,
            x: value.x,
            y: value.y,
        }
    }
}

impl From<sdk::KeyReleasePolicy> for KeyReleasePolicy {
    fn from(value: sdk::KeyReleasePolicy) -> Self {
        KeyReleasePolicy {
            content_type: value.content_type,
            encoded_policy: value.encoded_policy,
            immutable: value.immutable,
        }
    }
}
