// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use akv_cli::{ErrorKind, ResultExt};
use azure_core::credentials::Secret;
use azure_identity::ClientSecretCredential;
use azure_storage_blob::BlobServiceClient;
use clap::{Parser, Subcommand};
use futures::TryStreamExt;
use std::{env, path::PathBuf};
use tokio::{
    fs,
    io::{self, AsyncWriteExt},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotazure::load()?;
    let args = Args::parse();

    let endpoint = env::var("AZURE_STORAGE_SERVICE_ENDPOINT")
        .with_context(ErrorKind::Other, "$AZURE_STORAGE_SERVICE_ENDPOINT required")?;
    let tenant_id =
        env::var("AZURE_TENANT_ID").with_context(ErrorKind::Other, "$AZURE_TENANT_ID required")?;
    let client_id =
        env::var("AZURE_CLIENT_ID").with_context(ErrorKind::Other, "$AZURE_CLIENT_ID required")?;
    let client_secret: Secret = env::var("AZURE_CLIENT_SECRET")
        .with_context(ErrorKind::Other, "$AZURE_CLIENT_SECRET required")?
        .into();

    // Get a container client.
    let credential = ClientSecretCredential::new(&tenant_id, client_id, client_secret, None)?;
    let client = BlobServiceClient::new(&endpoint, credential, None)?
        .blob_container_client("examples".into());

    if args.list_args().is_some() {
        // List blobs within the "examples" container.
        let mut pager = client.list_blobs(None)?;
        while let Some(page) = pager.try_next().await? {
            let page = page.into_body().await?;
            for blob in page.segment.blob_items {
                let blob_name = blob.name.and_then(|n| n.content);
                let blob_name = blob_name.as_deref().unwrap_or("(unknown)");
                let content_type = blob.properties.and_then(|p| p.content_type);
                let content_type = content_type.as_deref().unwrap_or("(unknown)");
                println!("{blob_name} ({content_type})");
            }
        }
    } else if let Some(Commands::Read(args)) = args.command {
        // Read a blob within the "examples" container.
        let content = client
            .blob_client(args.name)
            .download(None)
            .await?
            .into_raw_body()
            .collect()
            .await?;
        match args.output {
            Some(path) => fs::write(path, content).await?,
            None => io::stdout().write_all(content.as_ref()).await?,
        };
    }

    Ok(())
}

#[derive(Debug, Parser)]
#[command(args_conflicts_with_subcommands = true)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    /// List blobs.
    #[command(flatten)]
    list: ListArgs,
}

impl Args {
    fn list_args(&self) -> Option<&ListArgs> {
        match self.command {
            Some(Commands::List(ref args)) => Some(args),
            Some(_) => None,
            None => Some(&self.list),
        }
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// List blobs (default).
    List(ListArgs),

    /// Read a blob.
    Read(ReadArgs),
}

#[derive(Debug, clap::Args)]
struct ListArgs;

#[derive(Debug, clap::Args)]
struct ReadArgs {
    /// Name of the blob to read.
    #[arg(short = 'n', long)]
    name: String,

    /// Optional file output.
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
}
