// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use super::VAULT_ENV_NAME;
use akv_cli::{
    list_items,
    parsing::{parse_key_value, parse_key_value_opt},
    Result,
};
use azure_core::{date::OffsetDateTime, http::Url};
use azure_identity::DefaultAzureCredential;
use azure_security_keyvault_secrets::{
    models::{Secret, SecretProperties, SetSecretParameters, UpdateSecretPropertiesParameters},
    ResourceExt, ResourceId, SecretClient,
};
use clap::Subcommand;
use futures::{future, TryStreamExt as _};
use prettytable::{color, format, Attr, Cell, Row, Table};
use std::collections::HashMap;
use timeago::Formatter;
use tracing::{Level, Span};

// clap doesn't support global, required arguments so we have to put `vault` into each subcommand.

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Create secrets in an Azure Key Vault.
    Create {
        /// A secret formatted as "name=value".
        #[arg(value_name = "NAME=VALUE", value_parser = parse_key_value::<String>)]
        secret: (String, String),

        /// The vault URL e.g., "https://my-vault.vault.azure.net".
        #[arg(long, value_name = "URL", env = VAULT_ENV_NAME)]
        vault: Url,

        /// The content type of the secret.
        #[arg(long, default_value = "text/plain")]
        content_type: Option<String>,

        /// Tags to set on the secret formatted as "name[=value]".
        /// Repeat argument once for each tag.
        #[arg(long, value_name = "NAME[=VALUE]", value_parser = parse_key_value_opt::<String>)]
        tags: Vec<(String, Option<String>)>,
    },

    /// Edits a secret in an Azure Key Vault.
    Edit {
        /// The secret URL e.g., "https://my-vault.vault.azure.net/secrets/my-secret".
        #[arg(group = "ident", value_name = "URL")]
        id: Option<Url>,

        /// The secret name.
        #[arg(long, group = "ident", requires = "vault")]
        name: Option<String>,

        /// The vault URL e.g., "https://my-vault.vault.azure.net".
        #[arg(long, value_name = "URL", env = VAULT_ENV_NAME)]
        vault: Option<Url>,

        /// The content type of the secret.
        #[arg(long)]
        content_type: Option<String>,

        /// Tags to set on the secret formatted as "name[=value]".
        /// Repeat argument once for each tag.
        #[arg(long, value_name = "NAME[=VALUE]", value_parser = parse_key_value_opt::<String>)]
        tags: Vec<(String, Option<String>)>,
    },

    /// Gets information about a secret in an Azure Key Vault.
    Get {
        /// The secret URL e.g., "https://my-vault.vault.azure.net/secrets/my-secret".
        #[arg(group = "ident", value_name = "URL")]
        id: Option<Url>,

        /// The secret name.
        #[arg(long, group = "ident", requires = "vault")]
        name: Option<String>,

        /// The vault URL e.g., "https://my-vault.vault.azure.net".
        #[arg(long, value_name = "URL", env = VAULT_ENV_NAME)]
        vault: Option<Url>,
    },

    /// List secrets in an Azure Key Vault.
    List {
        /// The vault URL e.g., "https://my-vault.vault.azure.net".
        #[arg(long, value_name = "URL", env = VAULT_ENV_NAME)]
        vault: Url,

        /// Show more details about each secret.
        #[arg(long)]
        long: bool,

        /// Include managed secrets.
        #[arg(long)]
        include_managed: bool,
    },

    /// List versions of a secret in an Azure Key Vault.
    ListVersions {
        /// The secret URL e.g., "https://my-vault.vault.azure.net/secrets/my-secret".
        #[arg(group = "ident", value_name = "URL")]
        id: Option<Url>,

        /// The secret name.
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
            secret,
            vault,
            content_type,
            tags,
        } = self
        else {
            panic!("invalid command");
        };

        let current = Span::current();
        current.record("vault", vault.as_str());
        current.record("name", &secret.0);

        let client = SecretClient::new(vault.as_str(), DefaultAzureCredential::new()?, None)?;

        let params = SetSecretParameters {
            value: Some(secret.0.to_string()),
            content_type: content_type.clone(),
            tags: HashMap::from_iter(
                tags.iter()
                    .map(|(k, v)| (k.to_string(), v.clone().unwrap_or_default())),
            ),
            ..Default::default()
        };

        let secret = client
            .set_secret(&secret.0, params.try_into()?, None)
            .await?
            .into_body()
            .await?;

        show(&secret)
    }

    #[tracing::instrument(level = Level::INFO, skip(self), fields(vault, name, version), err)]
    async fn edit(&self) -> Result<()> {
        let Commands::Edit {
            id,
            vault,
            name,
            content_type,
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

        let client = SecretClient::new(&vault, DefaultAzureCredential::new()?, None)?;

        let tags = HashMap::from_iter(
            tags.iter()
                .map(|(k, v)| (k.to_string(), v.clone().unwrap_or_default())),
        );
        let params = UpdateSecretPropertiesParameters {
            content_type: content_type.clone(),
            tags,
            ..Default::default()
        };

        let secret = client
            .update_secret_properties(
                &name,
                version.as_deref().unwrap_or_default(),
                params.try_into()?,
                None,
            )
            .await?
            .into_body()
            .await?;

        show(&secret)
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

        let client = SecretClient::new(&vault, DefaultAzureCredential::new()?, None)?;
        let secret = client
            .get_secret(&name, version.as_deref().unwrap_or_default(), None)
            .await?
            .into_body()
            .await?;

        show(&secret)
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

        let client = SecretClient::new(vault.as_str(), DefaultAzureCredential::new()?, None)?;
        let mut secrets: Vec<SecretProperties> =
            list_items(async || client.list_secret_properties(None))
                .try_filter(|props| {
                    if *include_managed {
                        return future::ready(true);
                    }
                    future::ready(!props.managed.unwrap_or_default())
                })
                .try_collect()
                .await?;
        secrets.sort_by(|a, b| a.id.cmp(&b.id));

        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);

        let mut titles = Row::new(vec![
            Cell::new("NAME").with_style(Attr::Dim),
            Cell::new("ID").with_style(Attr::Dim),
            Cell::new("TYPE").with_style(Attr::Dim),
        ]);
        if *long {
            titles.add_cell(Cell::new("CREATED").with_style(Attr::Dim));
        }
        titles.add_cell(Cell::new("EDITED").with_style(Attr::Dim));
        table.set_titles(titles);

        let now = OffsetDateTime::now_utc();
        let formatter = Formatter::new();
        let name_attr = Attr::ForegroundColor(color::GREEN);

        for secret in &secrets {
            let resource: ResourceId = secret.resource_id()?;
            let source_id = resource.source_id;
            let r#type = secret.content_type.as_deref().unwrap_or_default();

            let mut row = Row::new(vec![
                Cell::new(resource.name.as_str()).with_style(name_attr),
                Cell::new(source_id.as_str()),
                Cell::new(r#type),
            ]);
            if *long {
                let created = elapsed(
                    &formatter,
                    now,
                    secret.attributes.as_ref().and_then(|attr| attr.created),
                );
                row.add_cell(Cell::new(created.as_str()));
            }
            let edited = elapsed(
                &formatter,
                now,
                secret.attributes.as_ref().and_then(|attr| attr.updated),
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

        let client = SecretClient::new(&vault, DefaultAzureCredential::new()?, None)?;
        let mut secrets: Vec<SecretProperties> =
            list_items(async || client.list_secret_properties_versions(&name, None))
                .try_collect()
                .await?;
        secrets.sort_by(|a, b| a.id.cmp(&b.id));

        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);

        let mut titles = Row::new(vec![
            Cell::new("ID").with_style(Attr::Dim),
            Cell::new("TYPE").with_style(Attr::Dim),
        ]);
        if *long {
            titles.add_cell(Cell::new("CREATED").with_style(Attr::Dim));
        }
        titles.add_cell(Cell::new("EDITED").with_style(Attr::Dim));
        table.set_titles(titles);

        let now = OffsetDateTime::now_utc();
        let formatter = Formatter::new();
        let id_attr = Attr::ForegroundColor(color::GREEN);

        for secret in &secrets {
            let resource: ResourceId = secret.resource_id()?;
            let source_id = resource.source_id;
            let r#type = secret.content_type.as_deref().unwrap_or_default();

            let mut row = Row::new(vec![
                Cell::new(source_id.as_str()).with_style(id_attr),
                Cell::new(r#type),
            ]);
            if *long {
                let created = elapsed(
                    &formatter,
                    now,
                    secret.attributes.as_ref().and_then(|attr| attr.created),
                );
                row.add_cell(Cell::new(created.as_str()));
            }
            let edited = elapsed(
                &formatter,
                now,
                secret.attributes.as_ref().and_then(|attr| attr.updated),
            );
            row.add_cell(Cell::new(edited.as_str()));

            table.add_row(row);
        }

        // cspell:ignore printstd
        table.printstd();

        Ok(())
    }
}

fn elapsed(
    formatter: &timeago::Formatter,
    now: OffsetDateTime,
    d: Option<time::OffsetDateTime>,
) -> String {
    d.map(|time| now - time)
        .and_then(|time| time.try_into().ok())
        .map_or_else(String::new, |d| formatter.convert(d))
}

fn show(secret: &Secret) -> Result<()> {
    let resource = secret.resource_id()?;

    let now = OffsetDateTime::now_utc();
    let formatter = Formatter::new();

    println!("ID: {}", &resource.source_id);
    println!("Name: {}", &resource.name);
    println!("Version: {}", resource.version.unwrap_or_default());
    println!(
        "Enabled: {}",
        secret
            .attributes
            .as_ref()
            .and_then(|attr| attr.enabled)
            .unwrap_or_default()
    );
    println!("Managed: {}", secret.managed.unwrap_or_default());
    println!(
        "Created: {}",
        elapsed(
            &formatter,
            now,
            secret.attributes.as_ref().and_then(|attr| attr.created)
        )
    );
    println!(
        "Edited: {}",
        elapsed(
            &formatter,
            now,
            secret.attributes.as_ref().and_then(|attr| attr.updated)
        )
    );
    println!(
        "Not before: {}",
        elapsed(
            &formatter,
            now,
            secret.attributes.as_ref().and_then(|attr| attr.not_before)
        )
    );
    println!(
        "Expires: {}",
        elapsed(
            &formatter,
            now,
            secret.attributes.as_ref().and_then(|attr| attr.expires)
        )
    );

    println!(
        "Type: {}",
        secret
            .content_type
            .as_ref()
            .map_or_else(String::new, |s| s.into()),
    );
    println!("Tags:");
    for (k, v) in &secret.tags {
        println!("  {k}: {v}");
    }

    Ok(())
}
