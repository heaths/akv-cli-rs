// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use anstyle::{AnsiColor, Style};
use clap::Parser;
use std::{env, time::Duration};
use tokio::time::sleep;

const GREEN: Style = Style::new().fg_color(Some(anstyle::Color::Ansi(AnsiColor::Green)));
const RED: Style = Style::new().fg_color(Some(anstyle::Color::Ansi(AnsiColor::Red)));

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut vars: Vec<(String, String)> = if args.vars.is_empty() {
        env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect()
    } else {
        let mut vars = Vec::new();
        for k in args.vars {
            let Some(v) = env::var(&k).ok() else {
                continue;
            };
            vars.push((k, v));
        }
        vars
    };

    // Sort for easy comparison to expected output.
    vars.sort_by(|a, b| a.0.cmp(&b.0));

    // Interleave stdout and stderr for testing purposes.
    let stdout_prefix = format!("{GREEN}stdout{GREEN:#}");
    let stderr_prefix = format!("{RED}stderr{RED:#}");
    let padding = vars.len().to_string().len();

    for (i, (key, value)) in vars.into_iter().enumerate() {
        if let Some(delay) = args.delay {
            sleep(Duration::from_millis(delay)).await;
        }

        let line = format!("{key}={value}");
        match i % 2 {
            0 => println!("{stdout_prefix} {:>padding$}: {line}", i + 1),
            _ => eprintln!("{stderr_prefix} {:>padding$}: {line}", i + 1),
        }
    }

    Ok(())
}

#[derive(Debug, Parser)]
struct Args {
    /// Number of milliseconds to delay between printing lines.
    #[arg(long)]
    delay: Option<u64>,

    /// Optional variable names to print.
    #[arg(value_name = "VARIABLES", trailing_var_arg = true)]
    vars: Vec<String>,
}
