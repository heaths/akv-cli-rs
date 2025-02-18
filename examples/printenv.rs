// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use colored::Colorize;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args_os().skip(1);
    let mut vars: Vec<(String, String)> = if args.len() == 0 {
        env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect()
    } else {
        let mut vars = Vec::new();
        for k in args {
            let Some(k) = k.into_string().ok() else {
                continue;
            };
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
    let stdout_prefix = "stdout".green();
    let stderr_prefix = "stderr".red();

    for (i, (key, value)) in vars.into_iter().enumerate() {
        let line = format!("{key}={value}");
        match i % 2 {
            0 => println!("{stdout_prefix}: {line}"),
            _ => eprintln!("{stderr_prefix}: {line}"),
        }
    }

    Ok(())
}
