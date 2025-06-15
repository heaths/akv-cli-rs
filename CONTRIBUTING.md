# Contribution Guide

Open issues and submitting pull requests are welcome!
If you'd like to contribute code to this project, you can follow along with this guide to get started.

## Development environment

There are two good ways of getting started:

### Dev container

You can open this repository in either [GitHub Codespaces] or locally in a [Dev container].
All the prerequisite software required to contribute code in this project will be preinstalled.

### Local development

You can also work in this codebase locally. You'll need the following prerequisites:

* [Rust]
* [Azure CLI]
* (Recommended) [Visual Studio Code]
* (Recommended) [Azure Developer CLI]

When you open VSCode, you should be prompted to install additional, recommended extensions,
including rust-analyzer, the LLDB debugger, and more.

## Building

To build the workspace, in the root of the repository just run:

```bash
cargo build
```

## Testing

To run unit tests:

```bash
cargo test
```

Integration and manual tests require a Key Vault. To provision a vault with the [Azure Developer CLI], run:

```bash
azd up
```

This will provision a vault and a few secrets for testing commands e.g.:

```bash
cargo run -- secret list
cargo run -- read --name secret-1
```

If you provision a vault using `azd`, a `.env` file is created under `.azure/dev/.env`, which debug builds
of this project will read automatically. Support for `.env` files is only compiled into debug builds for safety. Release builds require passing the vault URL
to the `--vault` parameter.

To provision secret variables for demonstration, source an appropriate setup script under the `examples/` directory:

### Bash

In bash - or almost any popular shell on linux or macOS:

```bash
# The script is not executable and requires sourcing.
. ./examples/setup.sh
```

### PowerShell

In PowerShell:

```powershell
# You can also invoke the script from within powershell.
. ./examples/setup.ps1
```

## Troubleshooting

To help troubleshoot issues, you can trace information to the terminal:

```bash
RUST_LOG=info,akv=debug cargo run -- secret list
```

The [`RUST_LOG`][RUST_LOG] environment variable here sets the default tracing level to `info`
but `debug` for all `akv` traces.

[Azure CLI]: https://learn.microsoft.com/cli/azure/
[Azure Developer CLI]: https://learn.microsoft.com/azure/developer/azure-developer-cli/install-azd
[Dev container]: https://code.visualstudio.com/docs/devcontainers/create-dev-container
[GitHub Codespaces]: https://github.com/features/codespaces
[Rust]: https://www.rust-lang.org
[RUST_LOG]: https://docs.rs/env_logger/latest/env_logger/#enabling-logging
[Visual Studio Code]: https://code.visualstudio.com
