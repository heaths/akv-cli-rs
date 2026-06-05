// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

#![cfg_attr(windows, feature(windows_process_extensions_raw_attribute))]
#![feature(once_cell_try)]

mod commands;
mod pty;

use akv_cli::{ColorMode, ErrorKind, Result, ResultExt as _};
use azure_core::credentials::TokenCredential;
use azure_identity::{AzureDeveloperCliCredential, DeveloperToolsCredential};
#[cfg(feature = "color")]
use clap::ColorChoice;
use clap::Parser;
use commands::Commands;
use std::{
    path::PathBuf,
    process,
    sync::{Arc, OnceLock},
};
use time::macros::format_description;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{
    fmt::{format::FmtSpan, time::LocalTime},
    EnvFilter,
};

#[tokio::main]
async fn main() {
    let mut style = ColorMode::Auto.style();
    let loaded_dotenv = match dotenv() {
        Ok(b) => b,
        Err(err) => {
            eprintln!("{}: {err}", style.error("Error"),);
            process::exit(1);
        }
    };

    let args = Args::parse();
    style = args.color_mode().style();
    if let Err(err) = run(loaded_dotenv, args).await {
        eprintln!("{}: {err:#}", style.error("Error"));
        process::exit(1);
    }
}

async fn run(loaded_dotenv: Dotenv, args: Args) -> Result<()> {
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
        .with_ansi(args.color_enabled())
        .with_timer(LocalTime::new(format_description!(
            // cspell:disable-next-line
            "[hour]:[minute]:[second].[subsecond digits:6]"
        )))
        .init();

    match loaded_dotenv {
        Dotenv::Azure => {
            tracing::debug!("loaded environment variables from azd");
            // Use only azd credential if we loaded azd .env file for consistent auth.
            let _ =
                CREDENTIAL.set(AzureDeveloperCliCredential::new(None)? as Arc<dyn TokenCredential>);
        }
        Dotenv::Fallback(path) => {
            tracing::debug!("loaded environment variables from {}", path.display())
        }
        _ => {}
    }

    args.handle().await
}

#[derive(Debug, Parser)]
#[command(name = env!("CARGO_BIN_NAME"), about, long_about = None, version)]
struct Args {
    #[command(subcommand)]
    command: Commands,

    /// Print colors.
    #[cfg(feature = "color")]
    #[arg(short = 'c', long, default_value_t, global = true)]
    color: ColorChoice,

    /// Log verbose messages. Pass `-vv` to log more verbosely.
    #[arg(global = true, short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
}

impl Args {
    fn color_enabled(&self) -> bool {
        self.color_mode().enabled()
    }

    fn color_mode(&self) -> ColorMode {
        #[cfg(feature = "color")]
        match self.color {
            ColorChoice::Always => ColorMode::Always,
            ColorChoice::Never => ColorMode::Never,
            ColorChoice::Auto => ColorMode::Auto,
        }

        #[cfg(not(feature = "color"))]
        ColorMode::Never
    }

    async fn handle(&self) -> Result<()> {
        self.command.handle(self).await
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Dotenv {
    None,
    Azure,
    Fallback(PathBuf),
}

fn dotenv() -> akv_cli::Result<Dotenv> {
    if dotazure::load().with_kind(ErrorKind::Io)? {
        return Ok(Dotenv::Azure);
    }

    // Fall back to normal .env lookup.
    match dotenvy::dotenv() {
        Ok(path) => Ok(Dotenv::Fallback(path)),
        Err(err) if err.not_found() => Ok(Dotenv::None),
        Err(err) => Err(akv_cli::Error::new(ErrorKind::Io, err)),
    }
}

static CREDENTIAL: OnceLock<Arc<dyn TokenCredential>> = OnceLock::new();

fn credential() -> Result<Arc<dyn TokenCredential>> {
    Ok(CREDENTIAL
        .get_or_try_init::<_, akv_cli::Error>(|| {
            Ok(DeveloperToolsCredential::new(None)? as Arc<dyn TokenCredential>)
        })?
        .to_owned())
}

trait TableExt {
    fn print_color_conditionally(&self, mode: ColorMode) -> crate::Result<usize>;
}

impl TableExt for prettytable::Table {
    fn print_color_conditionally(&self, mode: ColorMode) -> crate::Result<usize> {
        if mode.enabled() {
            self.print_tty(mode == ColorMode::Always)
                .with_kind(ErrorKind::Io)
        } else {
            let mut stdout = std::io::stdout().lock();
            self.print(&mut stdout).with_kind(ErrorKind::Io)
        }
    }
}
