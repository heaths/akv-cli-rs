// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use crate::{error::Result, Error, ErrorKind};
use azure_core::{
    base64,
    json::{from_json, to_json},
    Bytes,
};
use azure_security_keyvault_keys::models::SignatureAlgorithm;
use openssl::hash::{hash, MessageDigest};
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

#[derive(Debug, Deserialize, Serialize)]
pub struct Header {
    pub kid: String,
    pub alg: String,
}

pub struct Jws {
    pub header: Header,
    pub payload: Bytes,
    pub signature: Option<Bytes>,
}

impl Jws {
    pub fn digest(&self, alg: SignatureAlgorithm) -> Result<Vec<u8>> {
        let header = self.header.encode()?;
        let payload = base64::encode_url_safe(&self.payload);
        let compact_jws = [header, payload].join(".");
        let t = signature_digest_alg(alg)?;
        let digest =
            hash(t, compact_jws.as_bytes()).map_err(|err| Error::new(ErrorKind::Other, err))?;
        Ok(digest.to_vec())
    }
}

impl Encode for Jws {
    fn decode(value: &str) -> Result<Self> {
        let components: Vec<&str> = value.split(".").collect();
        if components.len() < 2 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "JWS requires at least 2 components",
            ));
        }
        if components.len() > 3 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Too many components for JWS",
            ));
        }
        let mut jws = Jws {
            header: Header::decode(components[0])?,
            payload: base64::decode_url_safe(components[1])?.into(),
            signature: None,
        };
        if components.len() > 2 {
            jws.signature = Some(base64::decode_url_safe(components[2])?.into());
        }
        Ok(jws)
    }

    fn encode(&self) -> Result<String> {
        let header = self.header.encode()?;
        let payload = base64::encode_url_safe(&self.payload);
        let mut compact_jws = [header, payload].join(".");
        if let Some(signature) = &self.signature {
            let signature = base64::encode_url_safe(signature);
            compact_jws = [compact_jws, signature].join(".");
        }
        Ok(compact_jws)
    }
}

fn signature_digest_alg(alg: SignatureAlgorithm) -> Result<MessageDigest> {
    Ok(match alg {
        SignatureAlgorithm::RS256 => MessageDigest::sha256(),
        SignatureAlgorithm::RS384 => MessageDigest::sha384(),
        SignatureAlgorithm::RS512 => MessageDigest::sha512(),
        SignatureAlgorithm::PS256 => MessageDigest::sha256(),
        SignatureAlgorithm::PS384 => MessageDigest::sha384(),
        SignatureAlgorithm::PS512 => MessageDigest::sha512(),
        SignatureAlgorithm::ES256 => MessageDigest::sha256(),
        SignatureAlgorithm::ES256K => MessageDigest::sha256(),
        SignatureAlgorithm::ES384 => MessageDigest::sha384(),
        SignatureAlgorithm::ES512 => MessageDigest::sha512(),
        _ => Err(Error::with_message(
            ErrorKind::InvalidData,
            format!("unsupported algorithm: {}", alg.as_ref()),
        ))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use azure_security_keyvault_keys::models::SignatureAlgorithm;

    #[test]
    fn header_encode() {
        let header = Header {
            kid: "https://my-vault.vault.azure.net/keys/my-key".into(),
            alg: SignatureAlgorithm::RS256.as_ref().into(),
        };
        assert_eq!(header.encode().unwrap(), "eyJraWQiOiJodHRwczovL215LXZhdWx0LnZhdWx0LmF6dXJlLm5ldC9rZXlzL215LWtleSIsImFsZyI6IlJTMjU2In0");
    }

    #[test]
    fn header_decode() {
        let header = Header::decode("eyJraWQiOiJodHRwczovL215LXZhdWx0LnZhdWx0LmF6dXJlLm5ldC9rZXlzL215LWtleSIsImFsZyI6IkVTMjU2In0").unwrap();
        assert_eq!(header.kid, "https://my-vault.vault.azure.net/keys/my-key");
        assert_eq!(header.alg, "ES256");
    }

    #[test]
    fn jws_encode() {
        let jws = Jws {
            header: Header {
                kid: "https://my-vault.vault.azure.net/keys/my-key".into(),
                alg: SignatureAlgorithm::ES256.as_ref().into(),
            },
            payload: Bytes::from_static(b"Hello, world"),
            signature: None,
        };
        // cspell::disable-next-line
        assert_eq!(jws.encode().unwrap(), "eyJraWQiOiJodHRwczovL215LXZhdWx0LnZhdWx0LmF6dXJlLm5ldC9rZXlzL215LWtleSIsImFsZyI6IkVTMjU2In0.SGVsbG8sIHdvcmxk");
        let jws = Jws {
            header: Header {
                kid: "https://my-vault.vault.azure.net/keys/my-key".into(),
                alg: SignatureAlgorithm::ES256.as_ref().into(),
            },
            payload: Bytes::from_static(b"Hello, world"),
            signature: Some(base64::decode("kD9u5PuR97B1YZ6BtV33lnoIFRJrwydQgTzsi4w10TTgseJzBloywT2xfMcdOL6AYL3lXzdHWBkyRabCTlBtzQ==").unwrap().into()),
        };
        // cspell::disable-next-line
        assert_eq!(jws.encode().unwrap(), "eyJraWQiOiJodHRwczovL215LXZhdWx0LnZhdWx0LmF6dXJlLm5ldC9rZXlzL215LWtleSIsImFsZyI6IkVTMjU2In0.SGVsbG8sIHdvcmxk.kD9u5PuR97B1YZ6BtV33lnoIFRJrwydQgTzsi4w10TTgseJzBloywT2xfMcdOL6AYL3lXzdHWBkyRabCTlBtzQ");
    }

    #[test]
    fn jws_decode() {
        // cspell::disable-next-line
        let unsigned_jws = "eyJraWQiOiJodHRwczovL215LXZhdWx0LnZhdWx0LmF6dXJlLm5ldC9rZXlzL215LWtleSIsImFsZyI6IkVTMjU2In0.SGVsbG8sIHdvcmxk";
        let jws = Jws::decode(unsigned_jws).unwrap();

        assert_eq!(
            jws.header.kid,
            "https://my-vault.vault.azure.net/keys/my-key"
        );
        assert_eq!(jws.header.alg, "ES256");
        assert_eq!(jws.payload, Bytes::from_static(b"Hello, world"));
        assert!(jws.signature.is_none());

        // cspell::disable-next-line
        let signed_jws = "eyJraWQiOiJodHRwczovL215LXZhdWx0LnZhdWx0LmF6dXJlLm5ldC9rZXlzL215LWtleSIsImFsZyI6IkVTMjU2In0.SGVsbG8sIHdvcmxk.kD9u5PuR97B1YZ6BtV33lnoIFRJrwydQgTzsi4w10TTgseJzBloywT2xfMcdOL6AYL3lXzdHWBkyRabCTlBtzQ";
        let jws = Jws::decode(signed_jws).unwrap();

        assert_eq!(
            jws.header.kid,
            "https://my-vault.vault.azure.net/keys/my-key"
        );
        assert_eq!(jws.header.alg, "ES256");
        assert_eq!(jws.payload, Bytes::from_static(b"Hello, world"));
        assert!(jws.signature.is_some());

        let expected_signature = base64::decode("kD9u5PuR97B1YZ6BtV33lnoIFRJrwydQgTzsi4w10TTgseJzBloywT2xfMcdOL6AYL3lXzdHWBkyRabCTlBtzQ==").unwrap();
        assert_eq!(jws.signature.unwrap(), Bytes::from(expected_signature));
    }

    #[test]
    fn jws_digest() {
        let jws = Jws {
            header: Header {
                kid: "https://my-vault.vault.azure.net/keys/my-key".into(),
                alg: SignatureAlgorithm::ES256.as_ref().into(),
            },
            payload: Bytes::from_static(b"Hello, world"),
            signature: None,
        };
        assert_eq!(
            base64::encode(jws.digest(SignatureAlgorithm::ES256).unwrap()),
            "KrqITPGJIBwNPHPTQP/VFqrNC6seS9iPhC5BxcoC1aY=",
        );
    }
}
