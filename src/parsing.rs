// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

//! Parsing utility functions.

use crate::{Error, ErrorKind, Result, ResultExt};
use futures::future::BoxFuture;
use std::{borrow::Cow, io, str::FromStr};
use time::{format_description::well_known, OffsetDateTime};
use url::Url;

/// Parse an optional [`OffsetDateTime`] argument from `clap`.
pub fn parse_date_time_opt(value: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &well_known::Rfc3339)
        .with_context(ErrorKind::InvalidData, "failed to parse date-time")
}

/// Parse a `key=value` argument from `clap`.
pub fn parse_key_value<T>(value: &str) -> Result<(String, T)>
where
    T: FromStr,
    Error: From<<T as FromStr>::Err>,
{
    let idx = value
        .find("=")
        .ok_or_else(|| format!("no '=' found in '{value}'"))?;
    Ok((value[..idx].to_string(), value[idx + 1..].parse()?))
}

/// Parse an `key=(value)` argument from `clap` where `value` is optional.
pub fn parse_key_value_opt<T>(value: &str) -> Result<(String, Option<T>)>
where
    T: FromStr,
    Error: From<<T as FromStr>::Err>,
{
    if let Some(idx) = value.find("=") {
        return Ok((value[..idx].to_string(), Some(value[idx + 1..].parse()?)));
    }

    Ok((value.to_string(), None))
}

/// Replaces variables between `{{ }}` with text returned from function.
///
/// The function `f` receives a variable named (trimmed of leading and trailing whitespace)
/// and must return an `Ok(String)` or an `Err`, which will terminate the replacement. Any text written to
/// the [`io::Write`] `w` will be left as-is.
///
/// Overlapping templates e.g., `{{ {{foo}} }}` with attempt to replace the text
/// between the first occurrences of both `{{` and `}}`, so the function would receive `{{foo`
/// and, even if the function returned `Ok("".to_string())`, would still contain the final `}}` in the text.
///
/// # Examples
///
/// ```
/// use akv_cli::parsing::replace_expressions;
/// # use futures::{FutureExt, StreamExt};
///
/// # async fn test_replace_expressions() {
/// let s = "Hello, {{ var }}!";
/// let mut buf = Vec::new();
///
/// replace_expressions(s, &mut buf, |v| {
///     assert_eq!(v, "var");
///     async { Ok(String::from("world")) }.boxed()
/// }).await.unwrap();
///
/// assert_eq!(String::from_utf8(buf).unwrap(), "Hello, world!");
/// # }
/// ```
pub async fn replace_expressions<W, F>(mut template: &str, w: &mut W, f: F) -> Result<()>
where
    W: io::Write,
    F: Fn(&str) -> BoxFuture<'_, Result<String>>,
{
    const START: &str = "{{";
    const START_LEN: usize = START.len();
    const END: &str = "}}";
    const END_LEN: usize = END.len();

    while let Some(mut start) = template.find(START) {
        // Start only after the first "{{".
        let Some(mut end) = template[start + START_LEN..].find(END) else {
            return Err(Error::with_message(
                ErrorKind::InvalidData,
                "missing closing '}}'",
            ));
        };
        end += start + START_LEN;

        w.write_all(&template.as_bytes()[..start])?;
        start += START_LEN;

        let id = template[start..end].trim();
        let secret = f(id).await?;

        w.write_all(secret.as_bytes())?;
        end += END_LEN;

        template = &template[end..];
    }

    w.write_all(template.as_bytes())?;
    Ok(())
}

/// Replaces variables in the form $VAR_NAME with text returned from a function.
pub fn replace_vars<F>(input: &str, f: F) -> Result<Cow<'_, str>>
where
    F: Fn(&str) -> Result<String>,
{
    let mut cur = input;
    let mut output = String::new();

    while let Some(start) = cur.find('$') {
        output += &cur[..start];
        cur = &cur[start + 1..];

        let mut end = cur.len();
        for (i, c) in cur.char_indices() {
            if !c.is_ascii_alphanumeric() && c != '_' {
                end = i;
                break;
            }
        }

        let name = &cur[..end];
        if !name.is_empty() {
            output += &f(name)?;
        }
        cur = &cur[end..];
    }

    if output.is_empty() {
        Ok(Cow::Borrowed(input))
    } else {
        output += cur;
        Ok(Cow::Owned(output))
    }
}

/// Represents secret, key, or certificate resources.
#[derive(Clone, Debug)]
pub struct Resource {
    /// The containing vault URL e.g., "https://my-vault.vault.azure.net".
    pub vault_url: String,

    /// The name of the secret, key, or certificate resource.
    pub name: String,

    /// The optional version of the secret, key, or certificate resource.
    pub version: Option<String>,
}

impl TryFrom<Url> for Resource {
    type Error = crate::Error;

    #[inline]
    fn try_from(url: Url) -> std::result::Result<Self, Self::Error> {
        Self::try_from(&url)
    }
}

impl TryFrom<&Url> for Resource {
    type Error = crate::Error;

    fn try_from(url: &Url) -> std::result::Result<Self, Self::Error> {
        Ok(azure_security_keyvault_secrets::ResourceId::try_from(url)
            .map(From::from)
            .or_else(|_| azure_security_keyvault_keys::ResourceId::try_from(url).map(From::from))
            .or_else(|_| {
                azure_security_keyvault_certificates::ResourceId::try_from(url).map(From::from)
            })?)
    }
}

impl From<azure_security_keyvault_secrets::ResourceId> for Resource {
    fn from(value: azure_security_keyvault_secrets::ResourceId) -> Self {
        Self {
            vault_url: value.vault_url,
            name: value.name,
            version: value.version,
        }
    }
}

impl From<azure_security_keyvault_keys::ResourceId> for Resource {
    fn from(value: azure_security_keyvault_keys::ResourceId) -> Self {
        Self {
            vault_url: value.vault_url,
            name: value.name,
            version: value.version,
        }
    }
}

impl From<azure_security_keyvault_certificates::ResourceId> for Resource {
    fn from(value: azure_security_keyvault_certificates::ResourceId) -> Self {
        Self {
            vault_url: value.vault_url,
            name: value.name,
            version: value.version,
        }
    }
}

impl FromStr for Resource {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self> {
        let url: Url = s.parse()?;
        url.try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt as _;

    #[test]
    fn resource_from_secret_url() {
        let url: Url = "https://my-vault.vault.azure.net/secrets/my-secret"
            .parse()
            .unwrap();
        let resource = Resource::try_from(url).expect("valid secret URL");
        assert_eq!(resource.vault_url, "https://my-vault.vault.azure.net");
        assert_eq!(resource.name, "my-secret");
        assert!(resource.version.is_none());
    }

    #[test]
    fn resource_from_secret_url_with_version() {
        let url: Url =
            "https://my-vault.vault.azure.net/secrets/my-secret/746984e474594896aad9aff48aca0849"
                .parse()
                .unwrap();
        let resource = Resource::try_from(url).expect("valid secret URL with version");
        assert_eq!(resource.vault_url, "https://my-vault.vault.azure.net");
        assert_eq!(resource.name, "my-secret");
        assert_eq!(
            resource.version.as_deref(),
            Some("746984e474594896aad9aff48aca0849")
        );
    }

    #[test]
    fn resource_from_key_url() {
        let url: Url = "https://my-vault.vault.azure.net/keys/my-key"
            .parse()
            .unwrap();
        let resource = Resource::try_from(url).expect("valid key URL");
        assert_eq!(resource.vault_url, "https://my-vault.vault.azure.net");
        assert_eq!(resource.name, "my-key");
        assert!(resource.version.is_none());
    }

    #[test]
    fn resource_from_key_url_with_version() {
        let url: Url = "https://my-vault.vault.azure.net/keys/my-key/1234567890abcdef"
            .parse()
            .unwrap();
        let resource = Resource::try_from(url).expect("valid key URL with version");
        assert_eq!(resource.vault_url, "https://my-vault.vault.azure.net");
        assert_eq!(resource.name, "my-key");
        assert_eq!(resource.version.as_deref(), Some("1234567890abcdef"));
    }

    #[test]
    fn resource_from_certificate_url() {
        let url: Url = "https://my-vault.vault.azure.net/certificates/my-cert"
            .parse()
            .unwrap();
        let resource = Resource::try_from(url).expect("valid certificate URL");
        assert_eq!(resource.vault_url, "https://my-vault.vault.azure.net");
        assert_eq!(resource.name, "my-cert");
        assert!(resource.version.is_none());
    }

    #[test]
    fn resource_from_certificate_url_with_version() {
        let url: Url = "https://my-vault.vault.azure.net/certificates/my-cert/abcdef1234567890"
            .parse()
            .unwrap();
        let resource = Resource::try_from(url).expect("valid certificate URL with version");
        assert_eq!(resource.vault_url, "https://my-vault.vault.azure.net");
        assert_eq!(resource.name, "my-cert");
        assert_eq!(resource.version.as_deref(), Some("abcdef1234567890"));
    }

    #[test]
    fn resource_from_str() {
        let resource: Resource = "https://my-vault.vault.azure.net/secrets/my-secret"
            .parse()
            .expect("valid secret URL string");
        assert_eq!(resource.vault_url, "https://my-vault.vault.azure.net");
        assert_eq!(resource.name, "my-secret");
        assert!(resource.version.is_none());
    }

    #[test]
    fn resource_from_invalid_url() {
        let url: Url = "https://my-vault.vault.azure.net".parse().unwrap();
        Resource::try_from(url).expect_err("vault URL without resource path should fail");
    }

    #[test]
    fn test_parse_key_value() {
        let kv = parse_key_value::<String>("key=value");
        assert!(matches!(kv, Ok(kv) if kv.0 == "key" && kv.1 == "value"));

        let kv = parse_key_value::<String>("key=value=other");
        assert!(matches!(kv, Ok(kv) if kv.0 == "key" && kv.1 == "value=other"));

        parse_key_value::<String>("key").expect_err("requires '='");

        let k = parse_key_value::<i32>("key=1");
        assert!(matches!(k, Ok(k) if k.0 == "key" && k.1 == 1));

        parse_key_value::<i32>("key=value").expect_err("should not parse 'value' as i32");
    }

    #[test]
    fn test_parse_key_value_opt() {
        let kv = parse_key_value_opt::<String>("key=value");
        assert!(matches!(kv, Ok(kv) if kv.0 == "key" && kv.1 == Some("value".into())));

        let kv = parse_key_value_opt::<String>("key=value=other");
        assert!(matches!(kv, Ok(kv) if kv.0 == "key" && kv.1 == Some("value=other".into())));

        let k = parse_key_value_opt::<i32>("key");
        assert!(matches!(k, Ok(k) if k.0 == "key" && k.1.is_none()));

        parse_key_value_opt::<i32>("key=value").expect_err("should not parse 'value' as i32");
    }

    #[tokio::test]
    async fn test_replace_expressions() {
        let s = "Hello, {{ var }}!";
        let mut buf = Vec::new();

        replace_expressions(s, &mut buf, |v| {
            assert_eq!(v, "var");
            async { Ok(String::from("world")) }.boxed()
        })
        .await
        .unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "Hello, world!");
    }

    #[tokio::test]
    async fn replace_expressions_overlap() {
        let s = "Hello, {{ {{var}} }}!";
        let mut buf = Vec::new();

        replace_expressions(s, &mut buf, |v| {
            assert_eq!(v, "{{var");
            async { Ok(String::from("world")) }.boxed()
        })
        .await
        .unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "Hello, world }}!");
    }

    #[tokio::test]
    async fn replace_expressions_missing_end() {
        let s = "Hello, {{ var!";
        let mut buf = Vec::new();

        replace_expressions(s, &mut buf, |_| async { Ok(String::from("world")) }.boxed())
            .await
            .expect_err("missing end");
    }

    #[tokio::test]
    async fn replace_expressions_missing_empty() {
        let s = "";
        let mut buf = Vec::new();

        replace_expressions(s, &mut buf, |_| async { Ok(String::from("world")) }.boxed())
            .await
            .unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "");
    }

    #[tokio::test]
    async fn replace_expressions_missing_no_template() {
        let s = "Hello, world!";
        let mut buf = Vec::new();

        replace_expressions(s, &mut buf, |_| {
            async { Ok(String::from("Ferris")) }.boxed()
        })
        .await
        .unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "Hello, world!");
    }

    #[test]
    fn replace_vars_borrowed() {
        let s = "echo NONE";
        let out = replace_vars(s, |name| {
            assert_eq!(name, "VAR");
            Ok(String::from("VALUE"))
        })
        .expect("replaces $VAR with VALUE");
        assert!(matches!(out, Cow::Borrowed(out) if out == "echo NONE"));
    }

    #[test]
    fn replace_vars_owned() {
        let s = "echo $VAR";
        let out = replace_vars(s, |name| {
            assert_eq!(name, "VAR");
            Ok(String::from("VALUE"))
        })
        .expect("replaces $VAR with VALUE");
        assert!(matches!(out, Cow::Owned(out) if out == "echo VALUE"));
    }

    #[test]
    fn replace_only_vars() {
        let s = "$VAR";
        let out = replace_vars(s, |name| {
            assert_eq!(name, "VAR");
            Ok(String::from("VALUE"))
        })
        .expect("replaces $VAR with VALUE");
        assert!(matches!(out, Cow::Owned(out) if out == "VALUE"));
    }

    #[test]
    fn replace_vars_errs() {
        let s = "echo $VAR";
        replace_vars(s, |name| {
            assert_eq!(name, "VAR");
            Err(Error::with_message(ErrorKind::Other, "test"))
        })
        .expect_err("expected error");
    }

    #[tokio::test]
    async fn replace_expression_with_var() {
        let s = "Hello, {{ $VAR }}!";
        let mut buf = Vec::new();

        replace_expressions(s, &mut buf, |expr| {
            async move {
                assert_eq!(expr, "$VAR");
                replace_vars(expr, |var| {
                    assert_eq!(var, "VAR");
                    Ok(String::from("world"))
                })
                .map(Into::into)
            }
            .boxed()
        })
        .await
        .expect("replaces $VAR with 'world'");
        assert_eq!(String::from_utf8(buf).unwrap(), "Hello, world!");
    }
}
