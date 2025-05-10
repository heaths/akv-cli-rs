// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

mod commands;
mod pty;

use akv_cli::{ErrorKind, Result, ResultExt as _};
use clap::Parser;
use commands::Commands;
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

    if loaded_env {
        tracing::debug!("loaded environment variables from azd");
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
