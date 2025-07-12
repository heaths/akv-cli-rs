// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use anstyle::{AnsiColor, Style};
use clap::{builder::TypedValueParser, ColorChoice, Parser};
use std::{
    env,
    io::{self, Write},
    time::Duration,
};
use tokio::time::sleep;
use wildcard::Wildcard;

const GREEN: Style = Style::new().fg_color(Some(anstyle::Color::Ansi(AnsiColor::Green)));
const RED: Style = Style::new().fg_color(Some(anstyle::Color::Ansi(AnsiColor::Red)));

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut vars: Vec<(String, String)> = env::vars_os()
        .filter_map(|(k, v)| {
            let key = k.as_os_str().to_str()?;
            // First determine if we should include "private" variables.
            if !args.all && key.starts_with("_") {
                return None;
            }

            // Second determine if there are any variables or patterns to match.
            if !args.is_match(key) {
                return None;
            }

            Some((key.to_owned(), v.into_string().ok()?))
        })
        .collect();

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
    /// Include all variables including those starting with "_".
    #[arg(long)]
    all: bool,

    /// Print colors.
    #[arg(short = 'c', long, default_value_t)]
    color: ColorChoice,

    /// Number of milliseconds to delay between printing lines.
    #[arg(long)]
    delay: Option<u64>,

    /// Optional variable names to print. These may contain wildcard symbols `*` and `?`.
    #[arg(value_name = "VARIABLES", value_parser = WildcardValueParser, trailing_var_arg = true)]
    vars: Vec<Wildcard<'static>>,
}

impl Args {
    fn color(&self) -> anstream::ColorChoice {
        match self.color {
            ColorChoice::Always => anstream::ColorChoice::Always,
            ColorChoice::Auto => anstream::ColorChoice::Auto,
            ColorChoice::Never => anstream::ColorChoice::Never,
        }
    }

    fn is_match(&self, s: impl AsRef<str>) -> bool {
        if self.vars.is_empty() {
            return true;
        }

        for var in &self.vars {
            if var.is_match(s.as_ref().as_bytes()) {
                return true;
            }
        }

        false
    }
}

#[derive(Clone)]
struct WildcardValueParser;

impl TypedValueParser for WildcardValueParser {
    type Value = Wildcard<'static>;
    fn parse_ref(
        &self,
        _cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let bytes = value.as_encoded_bytes().to_vec();
        Wildcard::from_owned(bytes)
            .map_err(|_| clap::Error::new(clap::error::ErrorKind::InvalidValue))
    }
}
