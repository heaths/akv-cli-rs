// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use akv_cli::{ErrorKind, Result, ResultExt as _};
use serde::Deserialize;
use std::{env, fs::File, io::Read};

const ENV_DIR_NAME: &str = ".azure";

/// Attempt to load a `.env` file created by the Azure Developer CLI (azd).
///
/// If the directory or `.env` file doesn't exist, no error is returned.
/// Errors are only returned in truly exceptional cases like the `.env` file not being in the correct format.
pub fn load() -> Result<()> {
    // Find the directory containing the azure.yaml project file.
    let current_dir = env::current_dir()?;
    let mut project_dir = None;
    for dir in current_dir.ancestors() {
        let path = dir.join("azure.yaml");
        if path.exists() {
            project_dir = Some(dir);
            break;
        }
    }

    let Some(project_dir) = project_dir else {
        return Ok(());
    };

    // Get the environment name, falling back to the .azure/config.json file.
    let Some(environment_name) = env::var("AZURE_ENV_NAME").ok().or_else(|| {
        let config_path = project_dir.join(ENV_DIR_NAME).join("config.json");
        if !config_path.exists() {
            return None;
        }

        let mut content = Vec::new();
        File::open(config_path)
            .ok()?
            .read_to_end(&mut content)
            .ok()?;

        let config: Config = serde_json::from_slice(&content).ok()?;
        config.default_environment
    }) else {
        return Ok(());
    };

    // Try to load the .env file from .azure/{environment-name}.
    let path = project_dir
        .join(ENV_DIR_NAME)
        .join(environment_name)
        .join(".env");
    if !path.exists() {
        return Ok(());
    }

    dotenvy::from_filename(&path)
        .with_context(ErrorKind::Io, format!("failed to load {}", &path.display()))?;
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_environment: Option<String>,
}
