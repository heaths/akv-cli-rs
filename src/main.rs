// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use akv_cli::{get_secret, list_secrets};
use azure_core::{date::OffsetDateTime, Url};
use azure_identity::DefaultAzureCredential;
use azure_security_keyvault_secrets::{ResourceExt, ResourceId, SecretClient};
use clap::{Parser, Subcommand};
use futures::TryStreamExt;
use prettytable::{format, row, Table};
use std::pin::pin;
use timeago::Formatter;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
        Commands::List { vault } => {
            let client = SecretClient::new(vault.as_str(), credentials.clone(), None)?;
            let mut pager = pin!(list_secrets(&client));

            let mut table = Table::new();
            table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
            table.set_titles(row!["NAME", "ID", "EDITED", "TYPE"]);

            let now = OffsetDateTime::now_utc();
            let formatter = Formatter::new();
            while let Some(secret) = pager.try_next().await? {
                let resource: ResourceId = secret.resource_id()?;
                let edited = secret
                    .attributes
                    .and_then(|attrs| attrs.updated)
                    .map(|time| now - time)
                    .map(into_std_duration)
                    .map_or_else(String::new, |d| formatter.convert(d));
                let r#type = secret.content_type.unwrap_or_default();
                table.add_row(row![Fg -> resource.name, resource.source_id, edited, r#type]);
            }
            // cspell:ignore printstd
            table.printstd();
        }
        Commands::Read { id } => {
            let id: ResourceId = id.try_into()?;
            let client = SecretClient::new(&id.vault_url, credentials.clone(), None)?;
            let secret = get_secret(&client, id.name.as_ref(), id.version.as_deref()).await?;
            if let Some(value) = secret.value {
                println!("{value}");
            }
        }
    }

    Ok(())
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
    },

    Read {
        /// The URL to a secret in Azure Key Vault e.g., "https://my-vault.vault.azure.net/secrets/my-secret".
        id: Url,
    },
}

fn into_std_duration(d: time::Duration) -> std::time::Duration {
    std::time::Duration::from_secs(d.whole_seconds() as u64)
}
