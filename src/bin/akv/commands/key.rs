// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use super::{elapsed, VAULT_ENV_NAME};
use crate::credential;
use akv_cli::{parsing::parse_key_value_opt, Result};
use azure_core::{date::OffsetDateTime, http::Url};
use azure_security_keyvault_keys::{
    models::{
        CreateKeyParameters, Key, KeyProperties, KeyType as JsonKeyType,
        UpdateKeyPropertiesParameters,
    },
    KeyClient, ResourceExt as _, ResourceId,
};
use clap::{
    builder::{PossibleValue, TypedValueParser, ValueParserFactory},
    Subcommand, ValueEnum,
};
use futures::{future, TryStreamExt as _};
use prettytable::{color, format, Attr, Cell, Row, Table};
use std::{collections::HashMap, ops::Deref, str::FromStr};
use timeago::Formatter;
use tracing::{Level, Span};

// clap doesn't support global, required arguments so we have to put `vault` into each subcommand.

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Create keys in an Azure Key Vault.
    Create {
        /// Name of the key.
        #[arg(long)]
        name: String,

        /// The vault URL e.g., "https://my-vault.vault.azure.net".
        #[arg(long, value_name = "URL", env = VAULT_ENV_NAME)]
        vault: Url,

        /// The content type of the key.
        #[arg(id = "type", long, value_enum)]
        r#type: KeyType,

        /// The key size in bits for RSA keys.
        #[arg(long, value_parser, required_if_eq("type", "rsa"))]
        size: Option<KeySize>,

        /// The elliptic curve name for EC keys.
        #[arg(long, value_enum, required_if_eq("type", "ec"))]
        curve: Option<CurveName>,

        /// Tags to set on the key formatted as "name[=value]".
        /// Repeat argument once for each tag.
        #[arg(long, value_name = "NAME[=VALUE]", value_parser = parse_key_value_opt::<String>)]
        tags: Vec<(String, Option<String>)>,
    },

    /// Edits a key in an Azure Key Vault.
    Edit {
        /// The key URL e.g., "https://my-vault.vault.azure.net/keys/my-key".
        #[arg(group = "ident", value_name = "URL")]
        id: Option<Url>,

        /// The key name.
        #[arg(long, group = "ident", requires = "vault")]
        name: Option<String>,

        /// The vault URL e.g., "https://my-vault.vault.azure.net".
        #[arg(long, value_name = "URL", env = VAULT_ENV_NAME)]
        vault: Option<Url>,

        /// Tags to set on the key formatted as "name[=value]".
        /// Repeat argument once for each tag.
        #[arg(long, value_name = "NAME[=VALUE]", value_parser = parse_key_value_opt::<String>)]
        tags: Vec<(String, Option<String>)>,
    },

    /// Gets information about a key in an Azure Key Vault.
    Get {
        /// The key URL e.g., "https://my-vault.vault.azure.net/keys/my-key".
        #[arg(group = "ident", value_name = "URL")]
        id: Option<Url>,

        /// The key name.
        #[arg(long, group = "ident", requires = "vault")]
        name: Option<String>,

        /// The vault URL e.g., "https://my-vault.vault.azure.net".
        #[arg(long, value_name = "URL", env = VAULT_ENV_NAME)]
        vault: Option<Url>,
    },

    /// List keys in an Azure Key Vault.
    List {
        /// The vault URL e.g., "https://my-vault.vault.azure.net".
        #[arg(long, value_name = "URL", env = VAULT_ENV_NAME)]
        vault: Url,

        /// Show more details about each key.
        #[arg(long)]
        long: bool,

        /// Include managed keys.
        #[arg(long)]
        include_managed: bool,
    },

    /// List versions of a key in an Azure Key Vault.
    ListVersions {
        /// The key URL e.g., "https://my-vault.vault.azure.net/keys/my-key".
        #[arg(group = "ident", value_name = "URL")]
        id: Option<Url>,

        /// The key name.
        #[arg(long, group = "ident", requires = "vault")]
        name: Option<String>,

        /// The vault URL e.g., "https://my-vault.vault.azure.net".
        #[arg(long, value_name = "URL", env = VAULT_ENV_NAME)]
        vault: Option<Url>,

        /// Show more details about each version.
        #[arg(long)]
        long: bool,
    },
}

impl Commands {
    pub async fn handle(&self) -> Result<()> {
        match &self {
            Commands::Create { .. } => self.create().await,
            Commands::Edit { .. } => self.edit().await,
            Commands::Get { .. } => self.get().await,
            Commands::List { .. } => self.list().await,
            Commands::ListVersions { .. } => self.list_versions().await,
        }
    }

    #[tracing::instrument(level = Level::INFO, skip(self), fields(vault, name), err)]
    async fn create(&self) -> Result<()> {
        let Commands::Create {
            name,
            vault,
            r#type,
            size,
            curve,
            tags,
        } = self
        else {
            panic!("invalid command");
        };

        let current = Span::current();
        current.record("vault", vault.as_str());
        current.record("name", name);

        let client = KeyClient::new(vault.as_str(), credential()?, None)?;

        let params = CreateKeyParameters {
            kty: Some(r#type.into()),
            key_size: size.map(|value| *value),
            curve: curve.map(Into::into),
            tags: Some(HashMap::from_iter(
                tags.iter()
                    .map(|(k, v)| (k.to_string(), v.clone().unwrap_or_default())),
            )),
            ..Default::default()
        };

        let key = client
            .create_key(name, params.try_into()?, None)
            .await?
            .into_body()
            .await?;

        show(&key)
    }

    #[tracing::instrument(level = Level::INFO, skip(self), fields(vault, name, version), err)]
    async fn edit(&self) -> Result<()> {
        let Commands::Edit {
            id,
            vault,
            name,
            tags,
        } = self
        else {
            panic!("invalid command");
        };

        let (vault, name, version) = super::select(id.as_ref(), vault.as_ref(), name.as_ref())?;
        let current = Span::current();
        current.record("vault", &*vault);
        current.record("name", &*name);
        current.record("version", version.as_deref());

        let client = KeyClient::new(&vault, credential()?, None)?;

        let tags = HashMap::from_iter(
            tags.iter()
                .map(|(k, v)| (k.to_string(), v.clone().unwrap_or_default())),
        );
        let params = UpdateKeyPropertiesParameters {
            tags: Some(tags),
            ..Default::default()
        };

        let key = client
            .update_key_properties(
                &name,
                version.as_deref().unwrap_or_default(),
                params.try_into()?,
                None,
            )
            .await?
            .into_body()
            .await?;

        show(&key)
    }

    #[tracing::instrument(level = Level::INFO, skip(self), fields(vault, name, version), err)]
    async fn get(&self) -> Result<()> {
        let Commands::Get { id, name, vault } = self else {
            panic!("invalid command");
        };

        let (vault, name, version) = super::select(id.as_ref(), vault.as_ref(), name.as_ref())?;
        let current = Span::current();
        current.record("vault", &*vault);
        current.record("name", &*name);
        current.record("version", version.as_deref());

        let client = KeyClient::new(&vault, credential()?, None)?;
        let key = client
            .get_key(&name, version.as_deref().unwrap_or_default(), None)
            .await?
            .into_body()
            .await?;

        show(&key)
    }

    #[tracing::instrument(level = Level::INFO, skip(self), fields(vault), err)]
    async fn list(&self) -> Result<()> {
        let Commands::List {
            vault,
            long,
            include_managed,
        } = self
        else {
            panic!("invalid command");
        };

        Span::current().record("vault", vault.as_str());

        let client = KeyClient::new(vault.as_str(), credential()?, None)?;
        let mut keys: Vec<KeyProperties> = client
            .list_key_properties(None)?
            .try_filter(|p| future::ready(*include_managed || !p.managed.unwrap_or_default()))
            .try_collect()
            .await?;
        keys.sort_by(|a, b| a.kid.cmp(&b.kid));

        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);

        let mut titles = Row::new(vec![
            Cell::new("NAME").with_style(Attr::Dim),
            Cell::new("ID").with_style(Attr::Dim),
        ]);
        if *long {
            titles.add_cell(Cell::new("CREATED").with_style(Attr::Dim));
        }
        titles.add_cell(Cell::new("EDITED").with_style(Attr::Dim));
        table.set_titles(titles);

        let now = OffsetDateTime::now_utc();
        let formatter = Formatter::new();
        let name_attr = Attr::ForegroundColor(color::GREEN);

        for key in &keys {
            let resource: ResourceId = key.resource_id()?;
            let source_id = resource.source_id;

            let mut row = Row::new(vec![
                Cell::new(resource.name.as_str()).with_style(name_attr),
                Cell::new(source_id.as_str()),
            ]);
            if *long {
                let created = elapsed(
                    &formatter,
                    now,
                    key.attributes.as_ref().and_then(|attr| attr.created),
                );
                row.add_cell(Cell::new(created.as_str()));
            }
            let edited = elapsed(
                &formatter,
                now,
                key.attributes.as_ref().and_then(|attr| attr.updated),
            );
            row.add_cell(Cell::new(edited.as_str()));

            table.add_row(row);
        }

        // cspell:ignore printstd
        table.printstd();

        Ok(())
    }

    #[tracing::instrument(level = Level::INFO, skip(self), fields(vault, name, version), err)]
    async fn list_versions(&self) -> Result<()> {
        let Commands::ListVersions {
            id,
            name,
            vault,
            long,
        } = self
        else {
            panic!("invalid command");
        };

        let (vault, name, version) = super::select(id.as_ref(), vault.as_ref(), name.as_ref())?;
        let current = Span::current();
        current.record("vault", &*vault);
        current.record("name", &*name);
        current.record("version", version.as_deref());

        let client = KeyClient::new(&vault, credential()?, None)?;
        let mut keys: Vec<KeyProperties> = client
            .list_key_properties_versions(&name, None)?
            .try_collect()
            .await?;
        keys.sort_by(|a, b| {
            let a = a.attributes.as_ref().and_then(|x| x.updated);
            let b = b.attributes.as_ref().and_then(|x| x.updated);
            a.cmp(&b).reverse()
        });

        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);

        let mut titles = Row::new(vec![Cell::new("ID").with_style(Attr::Dim)]);
        if *long {
            titles.add_cell(Cell::new("CREATED").with_style(Attr::Dim));
        }
        titles.add_cell(Cell::new("EDITED").with_style(Attr::Dim));
        table.set_titles(titles);

        let now = OffsetDateTime::now_utc();
        let formatter = Formatter::new();
        let id_attr = Attr::ForegroundColor(color::GREEN);

        for key in &keys {
            let resource: ResourceId = key.resource_id()?;
            let source_id = resource.source_id;

            let mut row = Row::new(vec![Cell::new(source_id.as_str()).with_style(id_attr)]);
            if *long {
                let created = elapsed(
                    &formatter,
                    now,
                    key.attributes.as_ref().and_then(|attr| attr.created),
                );
                row.add_cell(Cell::new(created.as_str()));
            }
            let edited = elapsed(
                &formatter,
                now,
                key.attributes.as_ref().and_then(|attr| attr.updated),
            );
            row.add_cell(Cell::new(edited.as_str()));

            table.add_row(row);
        }

        // cspell:ignore printstd
        table.printstd();

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeySize(i32);

impl Deref for KeySize {
    type Target = i32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

const KEY_SIZE_VALUES: [i32; 3] = [2048, 3084, 4096];

impl FromStr for KeySize {
    type Err = clap::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        use clap::error::{Error, ErrorKind};

        let i: i32 = s.parse().map_err(|_| Error::new(ErrorKind::InvalidValue))?;
        if !KEY_SIZE_VALUES.contains(&i) {
            return Err(Error::new(ErrorKind::InvalidValue));
        }

        Ok(KeySize(i))
    }
}

#[derive(Debug, Clone)]
pub struct KeySizeParser;

impl TypedValueParser for KeySizeParser {
    type Value = KeySize;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> std::result::Result<Self::Value, clap::Error> {
        use clap::error::{ContextKind, ContextValue, Error, ErrorKind};

        let s = value
            .to_str()
            .ok_or_else(|| Error::new(ErrorKind::InvalidUtf8))?;

        s.parse().map_err(|_| {
            let mut err = Error::new(ErrorKind::InvalidValue).with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(
                    ContextKind::InvalidArg,
                    ContextValue::String(arg.get_long().map_or_else(String::new, Into::into)),
                );
            }
            err.insert(ContextKind::InvalidValue, ContextValue::String(s.into()));
            err.insert(
                ContextKind::ValidValue,
                ContextValue::Strings(KEY_SIZE_VALUES.iter().map(ToString::to_string).collect()),
            );
            err
        })
    }

    fn possible_values(&self) -> Option<Box<dyn Iterator<Item = PossibleValue> + '_>> {
        Some(Box::new(
            KEY_SIZE_VALUES
                .iter()
                .map(ToString::to_string)
                .map(PossibleValue::new),
        ))
    }
}

impl ValueParserFactory for KeySize {
    type Parser = KeySizeParser;

    fn value_parser() -> Self::Parser {
        KeySizeParser
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum KeyType {
    Ec,
    EcHsm,
    Rsa,
    RsaHsm,
}

impl From<&KeyType> for azure_security_keyvault_keys::models::KeyType {
    fn from(value: &KeyType) -> Self {
        match value {
            KeyType::Ec => Self::EC,
            KeyType::EcHsm => Self::EcHsm,
            KeyType::Rsa => Self::RSA,
            KeyType::RsaHsm => Self::RsaHsm,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CurveName {
    P256,
    P384,
    P521,
}

impl From<CurveName> for azure_security_keyvault_keys::models::CurveName {
    fn from(value: CurveName) -> Self {
        match value {
            CurveName::P256 => Self::P256,
            CurveName::P384 => Self::P384,
            CurveName::P521 => Self::P521,
        }
    }
}

fn show(key: &Key) -> Result<()> {
    let resource = key.resource_id()?;

    let now = OffsetDateTime::now_utc();
    let formatter = Formatter::new();

    println!("ID: {}", &resource.source_id);
    println!("Name: {}", &resource.name);
    println!("Version: {}", resource.version.unwrap_or_default());
    let jwk = key.key.clone().unwrap_or_default();
    println!(
        "Type: {}",
        jwk.kty
            .as_ref()
            .map_or_else(String::new, ToString::to_string)
    );
    match jwk.kty {
        Some(JsonKeyType::RSA | JsonKeyType::RsaHsm) => println!(
            "Size: {}",
            jwk.n
                .map_or_else(String::new, |n| (n.len() * 8).to_string())
        ),
        Some(JsonKeyType::EC | JsonKeyType::EcHsm) => println!(
            "Curve: {}",
            jwk.crv.map_or_else(String::new, |crv| crv.to_string())
        ),
        _ => {}
    };
    println!(
        "Enabled: {}",
        key.attributes
            .as_ref()
            .and_then(|attr| attr.enabled)
            .unwrap_or_default()
    );
    println!("Managed: {}", key.managed.unwrap_or_default());
    println!(
        "Created: {}",
        elapsed(
            &formatter,
            now,
            key.attributes.as_ref().and_then(|attr| attr.created)
        )
    );
    println!(
        "Edited: {}",
        elapsed(
            &formatter,
            now,
            key.attributes.as_ref().and_then(|attr| attr.updated)
        )
    );
    println!(
        "Not before: {}",
        elapsed(
            &formatter,
            now,
            key.attributes.as_ref().and_then(|attr| attr.not_before)
        )
    );
    println!(
        "Expires: {}",
        elapsed(
            &formatter,
            now,
            key.attributes.as_ref().and_then(|attr| attr.expires)
        )
    );
    println!("Tags:");
    if let Some(tags) = &key.tags {
        for (k, v) in tags {
            println!("  {k}: {v}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    #[test]
    fn key_size_parse() {
        assert!(
            matches!(KeySize::from_str("str"), Err(err) if err.kind() == ErrorKind::InvalidValue)
        );
        assert!(
            matches!(KeySize::from_str("1234"),  Err(err) if err.kind() == ErrorKind::InvalidValue)
        );
        assert_eq!(*KeySize::from_str("2048").unwrap(), 2048);
        assert_eq!(*KeySize::from_str("3084").unwrap(), 3084);
        assert_eq!(*KeySize::from_str("4096").unwrap(), 4096);
    }
}
