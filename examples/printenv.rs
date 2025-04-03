// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use anstyle::{AnsiColor, Style};
use clap::{ColorChoice, Parser};
use std::{
    env,
    io::{self, Write},
    time::Duration,
};
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
        for k in &args.vars {
            let Some(v) = env::var(k).ok() else {
                continue;
            };
            vars.push((k.clone(), v));
        }
        vars
    };

    // Sort for easy comparison to expected output.
    vars.sort_by(|a, b| a.0.cmp(&b.0));

    // Interleave stdout and stderr for testing purposes.
    let padding = vars.len().to_string().len();
    let mut stdout = anstream::AutoStream::new(io::stdout(), args.color());
    let mut stderr = anstream::AutoStream::new(io::stderr(), args.color());

    for (i, (key, value)) in vars.into_iter().enumerate() {
        if let Some(delay) = args.delay {
            sleep(Duration::from_millis(delay)).await;
        }

        let line = format!("{key}={value}");
        match i % 2 {
            0 => writeln!(stdout, "{GREEN}stdout {:>padding$}{GREEN:#}: {line}", i + 1)?,
            _ => writeln!(stderr, "{RED}stderr {:>padding$}{RED:#}: {line}", i + 1)?,
        }
    }

    Ok(())
}

#[derive(Debug, Parser)]
struct Args {
    /// Print colors.
    #[arg(short = 'c', long, default_value_t)]
    color: ColorChoice,

    /// Number of milliseconds to delay between printing lines.
    #[arg(long)]
    delay: Option<u64>,

    /// Optional variable names to print.
    #[arg(value_name = "VARIABLES", trailing_var_arg = true)]
    vars: Vec<String>,
}

impl Args {
    fn color(&self) -> anstream::ColorChoice {
        match self.color {
            ColorChoice::Always => anstream::ColorChoice::Always,
            ColorChoice::Auto => anstream::ColorChoice::Auto,
            ColorChoice::Never => anstream::ColorChoice::Never,
        }
    }
}
