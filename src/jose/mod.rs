// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

#![allow(non_camel_case_types)]

mod jwe;

use std::fmt;

use crate::Result;
use azure_core::{
    base64,
    json::{from_json, to_json},
};
use clap::ValueEnum;
pub use jwe::{Jwe, JweEncryptor, WrapKeyResult};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub trait Encode
where
    Self: Sized,
{
    fn decode(value: &str) -> Result<Self>;
    fn encode(&self) -> Result<String>;
}

impl<T: DeserializeOwned + Serialize> Encode for T {
    fn decode(value: &str) -> Result<Self> {
        let buf = base64::decode_url_safe(value)?;
        Ok(from_json(buf)?)
    }

    fn encode(&self) -> Result<String> {
        let buf = to_json(self)?;
        Ok(base64::encode_url_safe(buf))
    }
}

/// A JSON web algorithm header that precedes a JWE or JWS.
#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    /// For JWEs, the algorithm used to encrypt the content encryption key (CEK).
    ///
    /// Only algorithms supported fully on Key Vault are supported.
    #[serde(rename = "alg")]
    pub alg: Algorithm,

    /// For JWEs, the algorithm used to encrypt content with the content encryption key (CEK).
    #[serde(rename = "enc", skip_serializing_if = "Option::is_none")]
    pub enc: Option<EncryptionAlgorithm>,

    /// They ID of the key in Key Vault used for [`Header::alg`].
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// The type of the payload following this header.
    #[serde(rename = "typ")]
    pub typ: Type,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Type {
    JWE,
    #[serde(untagged)]
    Other(String),
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JWE => f.write_str("JWE"),
            Self::Other(s) => f.write_str(s),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    // JWS algorithms
    // RS256,
    // RS384,
    // RS512,
    // ES256,
    // ES384,
    // ES512,
    // PS256,
    // PS384,
    // PS512,

    // JWE algorithms
    #[serde(rename = "RSA1_5")]
    RSA1_5,
    #[serde(rename = "RSA-OAEP")]
    RSA_OAEP,
    #[serde(rename = "RSA-OAEP-256")]
    RSA_OAEP_256,

    #[serde(untagged)]
    #[value(skip)]
    Other(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "UPPERCASE")]
pub enum EncryptionAlgorithm {
    // A128CBC_HS256,
    // A192CBC_HS384,
    // A256CBC_HS512,
    A128GCM,
    A192GCM,
    A256GCM,

    #[serde(untagged)]
    #[value(skip)]
    Other(String),
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A128GCM => f.write_str("A128GCM"),
            Self::A192GCM => f.write_str("A192GCM"),
            Self::A256GCM => f.write_str("A256GCM"),
            Self::Other(s) => f.write_str(s),
        }
    }
}

#[derive(Debug)]
#[doc(hidden)]
pub enum Set {}

#[derive(Debug)]
#[doc(hidden)]
pub enum Unset {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn header_encode_decode() {
        let header = Header {
            alg: Algorithm::RSA_OAEP_256,
            enc: Some(EncryptionAlgorithm::A256GCM),
            kid: Some("https://myvault.vault.azure.net/keys/mykey/1234567890abcdef".into()),
            typ: Type::JWE,
        };

        let expected_json = json!({
            "alg": "RSA-OAEP-256",
            "enc": "A256GCM",
            "kid": "https://myvault.vault.azure.net/keys/mykey/1234567890abcdef",
            "typ": "JWE"
        });
        let expected_bytes = serde_json::to_vec(&expected_json).unwrap();
        let expected_b64 = azure_core::base64::encode_url_safe(expected_bytes);

        // Encode
        let encoded = header.encode().unwrap();
        assert_eq!(encoded, expected_b64);

        // Decode
        let decoded = Header::decode(&encoded).unwrap();
        assert_eq!(decoded.alg, Algorithm::RSA_OAEP_256);
        assert_eq!(decoded.enc, Some(EncryptionAlgorithm::A256GCM));
        assert_eq!(
            decoded.kid,
            Some("https://myvault.vault.azure.net/keys/mykey/1234567890abcdef".into()),
        );
        assert_eq!(decoded.typ, Type::JWE);
    }
}
