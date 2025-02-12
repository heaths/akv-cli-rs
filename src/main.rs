// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use akv_cli::{get_secret, list_secrets};
use azure_core::Url;
use azure_identity::DefaultAzureCredential;
use azure_security_keyvault_secrets::{ResourceId, SecretClient};
use clap::{Parser, Subcommand};
use futures::StreamExt as _;
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
            let mut pager = list_secrets(&client).await?;
            while let Some(secret) = pager.next().await? {
                println!("{:#?}", secret);
            }
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
