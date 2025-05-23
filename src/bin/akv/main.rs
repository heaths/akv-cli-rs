// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

#![cfg_attr(windows, feature(windows_process_extensions_raw_attribute))]

mod commands;
mod pty;

use akv_cli::{credentials::DeveloperCredential, Result};
#[cfg(debug_assertions)]
use akv_cli::{ErrorKind, ResultExt as _};
use azure_core::credentials::TokenCredential;
#[cfg(debug_assertions)]
use azure_identity::AzureDeveloperCliCredential;
use clap::Parser;
use commands::Commands;
use once_cell::sync::OnceCell;
use std::sync::Arc;
use time::macros::format_description;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{
    fmt::{format::FmtSpan, time::LocalTime},
    EnvFilter,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env files only in debug builds.
    #[cfg(debug_assertions)]
    let loaded_env = dotazure::load().with_kind(ErrorKind::Io)?;

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
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_writer(std::io::stderr)
        .with_timer(LocalTime::new(format_description!(
            // cspell:disable-next-line
            "[hour]:[minute]:[second].[subsecond digits:6]"
        )))
        .init();

    #[cfg(debug_assertions)]
    if loaded_env {
        tracing::debug!("loaded environment variables from azd");
        let _ = CREDENTIAL.set(AzureDeveloperCliCredential::new(None)? as Arc<dyn TokenCredential>);
    }

    args.handle().await
}

#[derive(Debug, Parser)]
#[command(name = env!("CARGO_BIN_NAME"), about, long_about = None, version)]
struct Args {
    #[command(subcommand)]
    command: Commands,

    /// Log verbose messages. Pass `-vv` to log more verbosely.
    #[arg(global = true, short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
}

impl Args {
    async fn handle(&self) -> Result<()> {
        self.command.handle().await
    }
}

static CREDENTIAL: OnceCell<Arc<dyn TokenCredential>> = OnceCell::new();

pub(crate) fn credential() -> Result<Arc<dyn TokenCredential>> {
    CREDENTIAL
        .get_or_try_init(|| Ok(DeveloperCredential::new(None)))
        .cloned()
}
