// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use azure_core::{base64, time::OffsetDateTime};
use azure_security_keyvault_certificates::models as sdk;
use azure_security_keyvault_certificates::models::{
    CertificatePolicyAction, CurveName, DeletionRecoveryLevel, KeyType, KeyUsageType,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct Certificate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<CertificateAttributes>,
    #[serde(
        default,
        deserialize_with = "base64::option::deserialize",
        serialize_with = "base64::option::serialize",
        skip_serializing_if = "Option::is_none"
    )]
    pub cer: Option<Vec<u8>>,
    #[serde(rename = "contentType", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<CertificatePolicy>,
    #[serde(rename = "preserveCertOrder", skip_serializing_if = "Option::is_none")]
    pub preserve_cert_order: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashMap<String, String>>,
    #[serde(
        default,
        deserialize_with = "base64::option::deserialize_url_safe",
        rename = "x5t",
        serialize_with = "base64::option::serialize_url_safe",
        skip_serializing_if = "Option::is_none"
    )]
    pub x509_thumbprint: Option<Vec<u8>>,
}

impl From<sdk::Certificate> for Certificate {
    fn from(value: sdk::Certificate) -> Self {
        Certificate {
            attributes: value.attributes.map(Into::into),
            cer: value.cer,
            content_type: value.content_type,
            id: value.id,
            kid: value.kid,
            policy: value.policy.map(Into::into),
            preserve_cert_order: value.preserve_cert_order,
            sid: value.sid,
            tags: value.tags,
            x509_thumbprint: value.x509_thumbprint,
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct CertificateAttributes {
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

impl From<sdk::CertificateAttributes> for CertificateAttributes {
    fn from(value: sdk::CertificateAttributes) -> Self {
        CertificateAttributes {
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

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct CertificatePolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<CertificateAttributes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "issuer", skip_serializing_if = "Option::is_none")]
    pub issuer_parameters: Option<IssuerParameters>,
    #[serde(rename = "key_props", skip_serializing_if = "Option::is_none")]
    pub key_properties: Option<KeyProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifetime_actions: Option<Vec<LifetimeAction>>,
    #[serde(rename = "secret_props", skip_serializing_if = "Option::is_none")]
    pub secret_properties: Option<SecretProperties>,
    #[serde(rename = "x509_props", skip_serializing_if = "Option::is_none")]
    pub x509_certificate_properties: Option<X509CertificateProperties>,
}

impl From<sdk::CertificatePolicy> for CertificatePolicy {
    fn from(value: sdk::CertificatePolicy) -> Self {
        CertificatePolicy {
            attributes: value.attributes.map(Into::into),
            id: value.id,
            issuer_parameters: value.issuer_parameters.map(Into::into),
            key_properties: value.key_properties.map(Into::into),
            lifetime_actions: value
                .lifetime_actions
                .map(|v| v.into_iter().map(Into::into).collect()),
            secret_properties: value.secret_properties.map(Into::into),
            x509_certificate_properties: value.x509_certificate_properties.map(Into::into),
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct IssuerParameters {
    #[serde(rename = "cert_transparency", skip_serializing_if = "Option::is_none")]
    pub certificate_transparency: Option<bool>,
    #[serde(rename = "cty", skip_serializing_if = "Option::is_none")]
    pub certificate_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl From<sdk::IssuerParameters> for IssuerParameters {
    fn from(value: sdk::IssuerParameters) -> Self {
        IssuerParameters {
            certificate_transparency: value.certificate_transparency,
            certificate_type: value.certificate_type,
            name: value.name,
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct KeyProperties {
    #[serde(rename = "crv", skip_serializing_if = "Option::is_none")]
    pub curve: Option<CurveName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exportable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_size: Option<i32>,
    #[serde(rename = "kty", skip_serializing_if = "Option::is_none")]
    pub key_type: Option<KeyType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reuse_key: Option<bool>,
}

impl From<sdk::KeyProperties> for KeyProperties {
    fn from(value: sdk::KeyProperties) -> Self {
        KeyProperties {
            curve: value.curve,
            exportable: value.exportable,
            key_size: value.key_size,
            key_type: value.key_type,
            reuse_key: value.reuse_key,
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct LifetimeAction {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<LifetimeActionType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<LifetimeActionTrigger>,
}

impl From<sdk::LifetimeAction> for LifetimeAction {
    fn from(value: sdk::LifetimeAction) -> Self {
        LifetimeAction {
            action: value.action.map(Into::into),
            trigger: value.trigger.map(Into::into),
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct LifetimeActionTrigger {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_before_expiry: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifetime_percentage: Option<i32>,
}

impl From<sdk::LifetimeActionTrigger> for LifetimeActionTrigger {
    fn from(value: sdk::LifetimeActionTrigger) -> Self {
        LifetimeActionTrigger {
            days_before_expiry: value.days_before_expiry,
            lifetime_percentage: value.lifetime_percentage,
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct LifetimeActionType {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_type: Option<CertificatePolicyAction>,
}

impl From<sdk::LifetimeActionType> for LifetimeActionType {
    fn from(value: sdk::LifetimeActionType) -> Self {
        LifetimeActionType {
            action_type: value.action_type,
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct SecretProperties {
    #[serde(rename = "contentType", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

impl From<sdk::SecretProperties> for SecretProperties {
    fn from(value: sdk::SecretProperties) -> Self {
        SecretProperties {
            content_type: value.content_type,
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct SubjectAlternativeNames {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emails: Option<Vec<String>>,
    #[serde(rename = "ipAddresses", skip_serializing_if = "Option::is_none")]
    pub ip_addresses: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uris: Option<Vec<String>>,
    #[serde(rename = "upns", skip_serializing_if = "Option::is_none")]
    pub user_principal_names: Option<Vec<String>>,
}

impl From<sdk::SubjectAlternativeNames> for SubjectAlternativeNames {
    fn from(value: sdk::SubjectAlternativeNames) -> Self {
        SubjectAlternativeNames {
            dns_names: value.dns_names,
            emails: value.emails,
            ip_addresses: value.ip_addresses,
            uris: value.uris,
            user_principal_names: value.user_principal_names,
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct X509CertificateProperties {
    #[serde(rename = "ekus", skip_serializing_if = "Option::is_none")]
    pub enhanced_key_usage: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_usage: Option<Vec<KeyUsageType>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "sans", skip_serializing_if = "Option::is_none")]
    pub subject_alternative_names: Option<SubjectAlternativeNames>,
    #[serde(rename = "validity_months", skip_serializing_if = "Option::is_none")]
    pub validity_in_months: Option<i32>,
}

impl From<sdk::X509CertificateProperties> for X509CertificateProperties {
    fn from(value: sdk::X509CertificateProperties) -> Self {
        X509CertificateProperties {
            enhanced_key_usage: value.enhanced_key_usage,
            key_usage: value.key_usage,
            subject: value.subject,
            subject_alternative_names: value.subject_alternative_names.map(Into::into),
            validity_in_months: value.validity_in_months,
        }
    }
}
