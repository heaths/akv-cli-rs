// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

mod commands;

use akv_cli::Result;
use clap::Parser;
use commands::Commands;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env files only in debug builds.
    #[cfg(debug_assertions)]
    load_env();

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
        .with_writer(std::io::stderr)
        .without_time()
        .init();

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

#[cfg(debug_assertions)]
fn load_env() {
    use std::{env, fs};

    // Load any user-created .env file from the root first.
    dotenvy::dotenv().ok();

    let azure_env = env::var("AZURE_ENV_NAME").ok();
    let Some(azure_dir) = env::current_dir().ok().map(|d| d.join(".azure")) else {
        return;
    };
    let Ok(child_dirs) = azure_dir.read_dir() else {
        return;
    };
    let child_dirs: Vec<fs::DirEntry> = child_dirs
        .filter_map(std::result::Result::ok)
        .filter(|d| d.metadata().is_ok_and(|m| m.is_dir()))
        .collect();
    let child_dir = match child_dirs.len() {
        0 => return,
        1 => &child_dirs[0],
        _ if azure_env.is_some() => {
            let azure_env = azure_env.unwrap();
            if let Some(child_dir) = child_dirs.iter().reduce(|mut found, e| {
                if e.file_name().eq_ignore_ascii_case(&azure_env) {
                    found = e;
                }
                found
            }) {
                child_dir
            } else {
                // No azd profile directories found matching AZURE_ENV_NAME.
                return;
            }
        }
        _ => {
            // Multiple azd profiles found; set $AZURE_ENV_NAME to disambiguate.
            return;
        }
    };
    let env_file = child_dir.path().join(".env");
    if env_file.exists() {
        dotenvy::from_filename(env_file).ok();
    }
}
