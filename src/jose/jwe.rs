// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use crate::{
    jose::{Algorithm, Encode, EncryptionAlgorithm, Header, Set, Type, Unset},
    Error, ErrorKind, Result,
};
use azure_core::{base64, Bytes};
use azure_security_keyvault_keys::models::KeyOperationResult;
use openssl::{
    rand,
    symm::{self, Cipher},
};
use std::marker::PhantomData;

/// A JSON Web Encryption (JWE) structure.
#[derive(Debug)]
pub struct Jwe {
    header: Header,
    cek: Bytes,
    iv: Bytes,
    ciphertext: Bytes,
    tag: Bytes,
}

impl Jwe {
    pub fn encryptor() -> JweEncryptor<Unset, Unset> {
        JweEncryptor::default()
    }

    pub async fn decrypt<F>(self, unwrap_key: F) -> Result<Bytes>
    where
        F: AsyncFn(&str, &Algorithm, &[u8]) -> Result<WrapKeyResult>,
    {
        if self.header.typ != Type::JWE {
            return Err(Error::with_message_fn(ErrorKind::InvalidData, || {
                format!("expected JWE, got {}", self.header.typ)
            }));
        }

        // Decrypt the CEK.
        let key_id = self
            .header
            .kid
            .as_deref()
            .ok_or_else(|| Error::with_message(ErrorKind::InvalidData, "expected kid"))?;
        let result = unwrap_key(key_id, &self.header.alg, &self.cek).await?;

        let enc = self
            .header
            .enc
            .as_ref()
            .ok_or_else(|| Error::with_message(ErrorKind::InvalidData, "expected enc"))?;
        let cipher: Cipher = enc.try_into()?;
        let aad = self.header.encode()?;

        let plaintext: Bytes = symm::decrypt_aead(
            cipher,
            &result.cek,
            Some(&self.iv),
            aad.as_bytes(),
            &self.ciphertext,
            &self.tag,
        )?
        .into();

        Ok(plaintext)
    }

    pub fn kid(&self) -> Option<&str> {
        self.header.kid.as_deref()
    }
}

impl Encode for Jwe {
    fn decode(value: &str) -> Result<Self> {
        let parts: Vec<_> = value.split(".").collect();
        if parts.len() != 5 {
            return Err(Error::with_message_fn(ErrorKind::InvalidData, || {
                format!("invalid compact JWE: expected 5 parts, got {}", parts.len())
            }));
        }

        Ok(Self {
            header: Header::decode(parts[0])?,
            cek: base64::decode_url_safe(parts[1])?.into(),
            iv: base64::decode_url_safe(parts[2])?.into(),
            ciphertext: base64::decode_url_safe(parts[3])?.into(),
            tag: base64::decode_url_safe(parts[4])?.into(),
        })
    }

    fn encode(&self) -> Result<String> {
        Ok([
            self.header.encode()?,
            base64::encode_url_safe(&self.cek),
            base64::encode_url_safe(&self.iv),
            base64::encode_url_safe(&self.ciphertext),
            base64::encode_url_safe(&self.tag),
        ]
        .join("."))
    }
}

#[derive(Debug)]
pub struct JweEncryptor<C, K> {
    alg: Option<Algorithm>,
    enc: Option<EncryptionAlgorithm>,
    kid: Option<String>,
    cek: Option<Bytes>,
    iv: Option<Bytes>,
    plaintext: Option<Bytes>,
    phantom: PhantomData<(C, K)>,
}

impl<C, K> JweEncryptor<C, K> {
    pub fn alg(self, alg: Algorithm) -> Self {
        Self {
            alg: Some(alg),
            ..self
        }
    }

    pub fn enc(self, enc: EncryptionAlgorithm) -> Self {
        Self {
            enc: Some(enc),
            ..self
        }
    }

    pub fn cek(self, cek: &[u8]) -> Self {
        Self {
            cek: Some(Bytes::copy_from_slice(cek)),
            ..self
        }
    }

    pub fn iv(self, iv: &[u8]) -> Self {
        Self {
            iv: Some(Bytes::copy_from_slice(iv)),
            ..self
        }
    }
}

impl<K> JweEncryptor<Unset, K> {
    pub fn plaintext(self, plaintext: &[u8]) -> JweEncryptor<Set, K> {
        JweEncryptor::<Set, K> {
            plaintext: Some(Bytes::copy_from_slice(plaintext)),
            alg: self.alg,
            enc: self.enc,
            kid: self.kid,
            cek: self.cek,
            iv: self.iv,
            phantom: PhantomData,
        }
    }

    pub fn plaintext_str(self, plaintext: impl AsRef<str>) -> JweEncryptor<Set, K> {
        JweEncryptor::plaintext(self, plaintext.as_ref().as_bytes())
    }
}

impl<C> JweEncryptor<C, Unset> {
    pub fn kid(self, kid: impl Into<String>) -> JweEncryptor<C, Set> {
        JweEncryptor::<C, Set> {
            kid: Some(kid.into()),
            alg: self.alg,
            enc: self.enc,
            cek: self.cek,
            iv: self.iv,
            plaintext: self.plaintext,
            phantom: PhantomData,
        }
    }
}

impl JweEncryptor<Set, Set> {
    pub async fn encrypt<F>(self, wrap_key: F) -> Result<Jwe>
    where
        F: AsyncFn(&str, &Algorithm, &[u8]) -> Result<WrapKeyResult>,
    {
        // Determine how big the CEK should be.
        let enc = &self.enc.unwrap_or(EncryptionAlgorithm::A128GCM);
        let cipher: Cipher = enc.try_into()?;

        // Validate or generate the CEK.
        let cek = match self.cek {
            Some(v) if v.len() == cipher.key_len() => v,
            Some(v) => {
                return Err(Error::with_message_fn(ErrorKind::InvalidData, || {
                    format!(
                        "require key size of {} bytes, got {}",
                        cipher.key_len(),
                        v.len()
                    )
                }));
            }
            None => {
                // Allocate enough space for largest supported cipher.
                let mut buf = [0; 32];
                rand::rand_bytes(&mut buf)?;
                Bytes::copy_from_slice(&buf[0..cipher.key_len()])
            }
        };

        let kid = self
            .kid
            .as_deref()
            .ok_or_else(|| Error::with_message(ErrorKind::InvalidData, "expected kid"))?;
        let alg = self.alg.unwrap_or(Algorithm::RSA_OAEP);

        // Encrypt the CEK so we get the full kid.
        let result = wrap_key(kid, &alg, &cek).await?;

        let header = Header {
            alg,
            enc: Some(enc.clone()),
            kid: Some(result.kid),
            typ: super::Type::JWE,
        };
        let aad = header.encode()?;

        // Generate the IV.
        let iv_len = cipher.iv_len().ok_or_else(|| {
            Error::with_message(
                ErrorKind::InvalidData,
                format!("expected iv length for cipher {}", &enc),
            )
        })?;
        let iv = match self.iv {
            Some(v) if v.len() == iv_len => v,
            Some(v) => {
                return Err(Error::with_message_fn(ErrorKind::InvalidData, || {
                    format!("require iv size of {} bytes, got {}", iv_len, v.len())
                }));
            }
            None => {
                // Allocate enough space for largest supported cipher.
                let mut buf = [0; 12];
                rand::rand_bytes(&mut buf)?;
                Bytes::copy_from_slice(&buf[0..iv_len])
            }
        };

        let plaintext = self.plaintext.expect("expected plaintext");
        let mut tag = [0; 16];
        let ciphertext: Bytes = symm::encrypt_aead(
            cipher,
            &cek,
            Some(&iv),
            aad.as_bytes(),
            &plaintext,
            &mut tag,
        )?
        .into();

        Ok(Jwe {
            header,
            cek: result.cek,
            iv,
            ciphertext,
            tag: Bytes::copy_from_slice(&tag),
        })
    }
}

impl<C, K> Default for JweEncryptor<C, K> {
    fn default() -> Self {
        Self {
            alg: None,
            enc: None,
            kid: None,
            cek: None,
            iv: None,
            plaintext: None,
            phantom: PhantomData,
        }
    }
}

impl TryFrom<EncryptionAlgorithm> for Cipher {
    type Error = Error;
    fn try_from(value: EncryptionAlgorithm) -> Result<Self> {
        (&value).try_into()
    }
}

impl TryFrom<&EncryptionAlgorithm> for Cipher {
    type Error = Error;
    fn try_from(value: &EncryptionAlgorithm) -> Result<Cipher> {
        match value {
            EncryptionAlgorithm::A128GCM => Ok(Cipher::aes_128_gcm()),
            EncryptionAlgorithm::A192GCM => Ok(Cipher::aes_192_gcm()),
            EncryptionAlgorithm::A256GCM => Ok(Cipher::aes_256_gcm()),
            EncryptionAlgorithm::Other(value) => {
                Err(Error::with_message_fn(ErrorKind::InvalidData, || {
                    format!("unsupported encryption algorithm {value}")
                }))
            }
        }
    }
}

impl TryFrom<&Algorithm> for azure_security_keyvault_keys::models::EncryptionAlgorithm {
    type Error = Error;
    fn try_from(value: &Algorithm) -> Result<Self> {
        match value {
            Algorithm::RSA1_5 => Ok(Self::RSA1_5),
            Algorithm::RSA_OAEP => Ok(Self::RsaOaep),
            Algorithm::RSA_OAEP_256 => Ok(Self::RsaOAEP256),
            Algorithm::Other(s) => Err(Error::with_message_fn(ErrorKind::InvalidData, || {
                format!("unsupported algorithm {s}")
            })),
        }
    }
}

#[derive(Debug)]
pub struct WrapKeyResult {
    pub kid: String,
    pub cek: Bytes,
}

impl TryFrom<KeyOperationResult> for WrapKeyResult {
    type Error = Error;
    fn try_from(value: KeyOperationResult) -> Result<Self> {
        Ok(Self {
            kid: value
                .kid
                .ok_or_else(|| Error::with_message(ErrorKind::InvalidData, "expected kid"))?,
            cek: value
                .result
                .map(Into::into)
                .ok_or_else(|| Error::with_message(ErrorKind::InvalidData, "expected CEK"))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azure_core::Bytes;

    #[test]
    fn decode_invalid() {
        assert!(
            matches!(Jwe::decode("1.2.3.4"), Err(err) if err.message() == Some("invalid compact JWE: expected 5 parts, got 4"))
        );
        assert!(
            matches!(Jwe::decode("1.2.3.4.5.6"), Err(err) if err.message() == Some("invalid compact JWE: expected 5 parts, got 6"))
        );
    }

    #[test]
    fn encode_decode_roundtrip() {
        let jwe = Jwe {
            header: Header {
                alg: crate::jose::Algorithm::RSA_OAEP_256,
                enc: Some(crate::jose::EncryptionAlgorithm::A128GCM),
                kid: Some("test-key-id".to_string()),
                typ: crate::jose::Type::JWE,
            },
            cek: Bytes::from_static(&[0x12, 0x34, 0x56, 0x78]),
            iv: Bytes::from_static(&[0x9a, 0xbc, 0xde, 0xf0]),
            ciphertext: Bytes::from_static(&[0x01, 0x23, 0x45, 0x67]),
            tag: Bytes::from_static(&[0x89, 0xab, 0xcd, 0xef]),
        };

        // cspell:disable-next-line
        const EXPECTED: &str = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIiwia2lkIjoidGVzdC1rZXktaWQiLCJ0eXAiOiJKV0UifQ.EjRWeA.mrze8A.ASNFZw.iavN7w";

        let encoded = jwe.encode().expect("encode should succeed");
        assert_eq!(encoded, EXPECTED);

        let decoded = Jwe::decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded.header.alg, crate::jose::Algorithm::RSA_OAEP_256);
        assert_eq!(
            decoded.header.enc,
            Some(crate::jose::EncryptionAlgorithm::A128GCM)
        );
        assert_eq!(decoded.header.kid, Some("test-key-id".to_string()));
        assert_eq!(decoded.header.typ, crate::jose::Type::JWE);
        assert_eq!(decoded.cek, Bytes::from_static(&[0x12, 0x34, 0x56, 0x78]));
        assert_eq!(decoded.iv, Bytes::from_static(&[0x9a, 0xbc, 0xde, 0xf0]));
        assert_eq!(
            decoded.ciphertext,
            Bytes::from_static(&[0x01, 0x23, 0x45, 0x67])
        );
        assert_eq!(decoded.tag, Bytes::from_static(&[0x89, 0xab, 0xcd, 0xef]));
    }

    #[test]
    fn encryption_algorithm_cipher() {
        let cipher: Cipher = EncryptionAlgorithm::A128GCM
            .try_into()
            .expect("try_into should succeed");
        assert_eq!(cipher.iv_len(), Some(12));
        assert_eq!(cipher.key_len(), 16);

        let cipher: Cipher = EncryptionAlgorithm::A192GCM
            .try_into()
            .expect("try_into should succeed");
        assert_eq!(cipher.iv_len(), Some(12));
        assert_eq!(cipher.key_len(), 24);

        let cipher: Cipher = EncryptionAlgorithm::A256GCM
            .try_into()
            .expect("try_into should succeed");
        assert_eq!(cipher.iv_len(), Some(12));
        assert_eq!(cipher.key_len(), 32);
    }

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip() {
        let kid = "key-name";
        let alg = Algorithm::RSA_OAEP;
        let enc = EncryptionAlgorithm::A128GCM;
        let plaintext = b"Hello, world!";

        // wrap_key callback: asserts kid and enc, returns cek as-is
        let wrap_key = async |key_id: &str, wrap_alg: &Algorithm, cek: &[u8]| {
            assert_eq!(key_id, kid);
            assert_eq!(wrap_alg, &alg);
            Ok(crate::jose::jwe::WrapKeyResult {
                kid: "key-name/key-version".into(),
                cek: Bytes::copy_from_slice(cek),
            })
        };

        // unwrap_key callback: asserts kid and enc, returns cek as-is
        let unwrap_key = async |key_id: &str, wrap_alg: &Algorithm, cek: &[u8]| {
            assert_eq!(key_id, "key-name/key-version");
            assert_eq!(wrap_alg, &alg);
            Ok(crate::jose::jwe::WrapKeyResult {
                kid: "key-name/key-version".into(),
                cek: Bytes::copy_from_slice(cek),
            })
        };

        let jwe = Jwe::encryptor()
            .alg(alg.clone())
            .enc(enc)
            .kid(kid)
            .plaintext(plaintext)
            .encrypt(wrap_key)
            .await
            .expect("encryption should succeed");

        let decrypted = jwe
            .decrypt(unwrap_key)
            .await
            .expect("decryption should succeed");
        assert_eq!(decrypted, plaintext.as_ref());
    }
}
