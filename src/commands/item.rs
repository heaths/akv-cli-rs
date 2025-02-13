// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use std::collections::HashMap;

use super::{parse_key_value, parse_key_value_opt};
use akv_cli::{list_secrets, Result};
use azure_core::{date::OffsetDateTime, Url};
use azure_identity::DefaultAzureCredential;
use azure_security_keyvault_secrets::{
    models::{SecretBundle, SecretItem, SecretSetParameters, SecretUpdateParameters},
    ResourceExt, ResourceId, SecretClient,
};
use clap::Subcommand;
use futures::TryStreamExt as _;
use prettytable::{color, format, Attr, Cell, Row, Table};
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

        /// The host name of the Azure Key Vault e.g., "https://my-vault.vault.azure.net".
        #[arg(long)]
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
        /// The URL to a secret in Azure Key Vault e.g., "https://my-vault.vault.azure.net/secrets/my-secret".
        id: Url,

        /// The content type of the secret.
        #[arg(long)]
        content_type: Option<String>,

        /// Tags to set on the secret formatted as "name[=value]".
        /// Repeat argument once for each tag.
        #[arg(long, value_name = "NAME[=VALUE]", value_parser = parse_key_value_opt::<String>)]
        tags: Vec<(String, Option<String>)>,
    },

    Get {
        /// The URL to a secret in Azure Key Vault e.g., "https://my-vault.vault.azure.net/secrets/my-secret".
        id: Url,
    },

    /// List secrets in an Azure Key Vault.
    List {
        /// The host name of the Azure Key Vault e.g., "https://my-vault.vault.azure.net".
        #[arg(long)]
        vault: Url,

        /// List more details about each secret.
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
        current.record("name", secret.0.as_str());

        let client = SecretClient::new(vault.as_str(), DefaultAzureCredential::new()?, None)?;
        let params = SecretSetParameters {
            value: Some(secret.0.to_string()),
            content_type: content_type.clone(),
            tags: Some(HashMap::from_iter(
                tags.iter()
                    .map(|(k, v)| (k.to_string(), v.clone().unwrap_or_default())),
            )),
            ..Default::default()
        };

        let secret = client
            .set_secret(secret.0.as_str(), params.try_into()?, None)
            .await?
            .into_body()
            .await?;

        show(&secret)
    }

    #[tracing::instrument(level = Level::INFO, skip(self), fields(vault, name), err)]
    async fn edit(&self) -> Result<()> {
        let Commands::Edit {
            id,
            content_type,
            tags,
        } = self
        else {
            panic!("invalid command");
        };
        let id: ResourceId = id.try_into()?;

        let current = Span::current();
        current.record("vault", id.vault_url.as_str());
        current.record("name", id.name.as_str());

        let client =
            SecretClient::new(id.vault_url.as_str(), DefaultAzureCredential::new()?, None)?;
        let params = SecretUpdateParameters {
            content_type: content_type.clone(),
            tags: Some(HashMap::from_iter(
                tags.iter()
                    .map(|(k, v)| (k.to_string(), v.clone().unwrap_or_default())),
            )),
            ..Default::default()
        };

        let secret = client
            .update_secret(
                id.name.as_str(),
                id.version.as_deref().unwrap_or_default(),
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
        let Commands::Get { id } = self else {
            panic!("invalid command");
        };
        let id: ResourceId = id.try_into()?;

        let current = Span::current();
        current.record("vault", id.vault_url.as_str());
        current.record("name", id.name.as_str());
        current.record("version", id.version.as_ref());

        let client =
            SecretClient::new(id.vault_url.as_str(), DefaultAzureCredential::new()?, None)?;
        let secret = client
            .get_secret(&id.name, id.version.as_deref().unwrap_or_default(), None)
            .await?
            .into_body()
            .await?;

        show(&secret)
    }

    #[tracing::instrument(level = Level::INFO, skip(self), fields(vault), err)]
    async fn list(&self) -> Result<()> {
        let Commands::List { vault, long } = self else {
            panic!("invalid command");
        };

        Span::current().record("vault", vault.as_str());

        let client = SecretClient::new(vault.as_str(), DefaultAzureCredential::new()?, None)?;
        let mut secrets: Vec<SecretItem> = list_secrets(&client).try_collect().await?;
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

fn show(secret: &SecretBundle) -> Result<()> {
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
    if let Some(tags) = &secret.tags {
        for (k, v) in tags {
            println!("  {k}: {v}");
        }
    }

    Ok(())
}
