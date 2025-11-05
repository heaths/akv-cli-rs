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
use std::sync::{Arc, OnceLock};
use time::macros::format_description;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{
    fmt::{format::FmtSpan, time::LocalTime},
    EnvFilter,
};

#[tokio::main]
async fn main() -> Result<()> {
    let loaded_azure_dotenv = dotazure::load().with_kind(ErrorKind::Io)?;
    if loaded_azure_dotenv {
        tracing::debug!("loaded environment variables from azd");
    } else {
        // Fall back to normal .env lookup.
        let path = dotenvy::dotenv().with_kind(ErrorKind::Io)?;
        tracing::debug!("loaded environment variables from {}", path.display());
    }

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

    // Use only azd credential if we loaded azd .env file for consistent auth.
    if loaded_azure_dotenv {
        let _ = CREDENTIAL.set(AzureDeveloperCliCredential::new(None)? as Arc<dyn TokenCredential>);
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
    fn color(&self) -> ColorMode {
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

static CREDENTIAL: OnceLock<Arc<dyn TokenCredential>> = OnceLock::new();

fn credential() -> Result<Arc<dyn TokenCredential>> {
    Ok(CREDENTIAL
        .get_or_try_init::<_, akv_cli::Error>(|| {
            Ok(DeveloperToolsCredential::new(None)? as Arc<dyn TokenCredential>)
        })?
        .to_owned())
}

fn color(#[allow(unused_variables)] mode: ColorMode) -> bool {
    #[cfg(feature = "color")]
    {
        use yansi::Condition;

        match mode {
            ColorMode::Always => true,
            ColorMode::Auto => Condition::tty_and_color(),
            ColorMode::Never => false,
        }
    }

    #[cfg(not(feature = "color"))]
    false
}

trait TableExt {
    fn print_color_conditionally(&self, mode: ColorMode) -> crate::Result<usize>;
}

impl TableExt for prettytable::Table {
    fn print_color_conditionally(&self, mode: ColorMode) -> crate::Result<usize> {
        if color(mode) {
            self.print_tty(mode == ColorMode::Always)
                .with_kind(ErrorKind::Io)
        } else {
            let mut stdout = std::io::stdout().lock();
            self.print(&mut stdout).with_kind(ErrorKind::Io)
        }
    }
}
