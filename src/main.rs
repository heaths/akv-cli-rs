// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use akv_cli::Result;
use akv_cli::{get_secret, list_secrets};
use azure_core::{credentials::TokenCredential, date::OffsetDateTime, Url};
use azure_identity::DefaultAzureCredential;
use azure_security_keyvault_secrets::models::SecretItem;
use azure_security_keyvault_secrets::{ResourceExt as _, ResourceId, SecretClient};
use clap::{Parser, Subcommand};
use futures::TryStreamExt as _;
use prettytable::{format, row, Table};
use std::sync::Arc;
use timeago::Formatter;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let verbosity = match args.verbose {
        0 => LevelFilter::OFF,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };
    let mut filter = EnvFilter::from_default_env();
    if matches!(filter.max_level_hint(), Some(level) if level < verbosity) {
        filter = filter.add_directive(verbosity.into());
    }
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::NEW)
        .init();

    let credentials = DefaultAzureCredential::new()?;
    match args.command {
        cmd @ Commands::List { .. } => list(credentials.clone(), &cmd).await,
        cmd @ Commands::Read { .. } => read(credentials.clone(), &cmd).await,
    }
}

#[derive(Debug, Parser)]
#[command(about, long_about = None, version)]
struct Args {
    #[command(subcommand)]
    command: Commands,

    /// Log verbose messages. Pass `-vv` to log more verbosely.
    #[arg(global = true, short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// List secrets in an Azure Key Vault.
    List {
        /// The host name of the Azure Key Vault e.g., "https://my-vault.vault.azure.net".
        #[arg(long)]
        vault: Url,

        /// List more details about each secret.
        #[arg(long)]
        long: bool,
    },

    /// Read a secret from an Azure Key Vault.
    Read {
        /// The URL to a secret in Azure Key Vault e.g., "https://my-vault.vault.azure.net/secrets/my-secret".
        id: Url,
    },
}

async fn list(credentials: Arc<dyn TokenCredential>, cmd: &Commands) -> Result<()> {
    let Commands::List { vault, long } = cmd else {
        panic!("invalid command");
    };

    let client = SecretClient::new(vault.as_str(), credentials, None)?;
    let mut secrets: Vec<SecretItem> = list_secrets(&client).try_collect().await?;
    secrets.sort_by(|a, b| a.id.cmp(&b.id));

    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(row!["NAME", "ID", "EDITED", "TYPE"]);

    let now = OffsetDateTime::now_utc();
    let formatter = Formatter::new();
    for secret in secrets {
        let resource: ResourceId = secret.resource_id()?;
        let mut source_id = resource.source_id;
        if *long {
            if let Some(version) = resource.version {
                source_id = source_id
                    .parse::<Url>()?
                    .join(version.as_ref())?
                    .to_string();
            }
        }
        let edited = secret
            .attributes
            .and_then(|attrs| attrs.updated)
            .map(|time| now - time)
            .map(into_std_duration)
            .map_or_else(String::new, |d| formatter.convert(d));
        let r#type = secret.content_type.unwrap_or_default();
        table.add_row(row![Fg -> resource.name, source_id, edited, r#type]);
    }

    // cspell:ignore printstd
    table.printstd();

    Ok(())
}
async fn read(credentials: Arc<dyn TokenCredential>, cmd: &Commands) -> Result<()> {
    let Commands::Read { id } = cmd else {
        panic!("invalid command");
    };

    let id: ResourceId = id.try_into()?;
    let client = SecretClient::new(&id.vault_url, credentials.clone(), None)?;
    let secret = get_secret(&client, id.name.as_ref(), id.version.as_deref()).await?;
    if let Some(value) = secret.value {
        println!("{value}");
    }

    Ok(())
}

fn into_std_duration(d: time::Duration) -> std::time::Duration {
    std::time::Duration::from_secs(d.whole_seconds() as u64)
}
