// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use akv_cli::{deconstruct, get_secret};
use azure_core::Url;
use azure_identity::DefaultAzureCredential;
use azure_security_keyvault_secrets::SecretClient;
use clap::{Parser, Subcommand};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let def = match args.verbose {
        1 => LevelFilter::DEBUG,
        2 => LevelFilter::TRACE,
        _ => LevelFilter::INFO,
    };
    let filter = EnvFilter::builder()
        .with_default_directive(def.into())
        .from_env_lossy();
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let credentials = DefaultAzureCredential::new()?;
    match args.command {
        Commands::List { vault } => {
            let _client = SecretClient::new(vault.as_str(), credentials.clone(), None)?;
            todo!()
        }
        Commands::Read { id } => {
            let (vault, name, version) = deconstruct(id)?;
            let client = SecretClient::new(&vault, credentials.clone(), None)?;
            let secret = get_secret(&client, name.as_ref(), version.as_deref()).await?;
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
