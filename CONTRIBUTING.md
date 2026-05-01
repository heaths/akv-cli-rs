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
* [Node.js] 22 or later (for spell checking with cspell)
* (Recommended) [Visual Studio Code]
* (Recommended) [Azure Developer CLI]
* (Recommended) [PowerShell]
* (Recommended) [Pester]

When you open VSCode, you should be prompted to install additional, recommended extensions,
including rust-analyzer, the LLDB debugger, and more.

After cloning the repository, install Node.js dependencies:

```bash
npm install
```

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
# Environment name 'dev' recommended.
azd up
```

This will provision a vault and a few secrets for testing commands e.g.:

```bash
cargo run -- secret list
cargo run -- read --name secret-1
```

If you provision a vault using `azd`, a `.env` file is created under `.azure/dev/.env` by default,
which this project will read automatically.

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

### Manual testing

To manually test the CLI, install [Pester] in [PowerShell] and run:

```powershell
azd up # If you haven't already

Invoke-Pester tests/test.ps1
```

## Linting

### Spell Checking

To check spelling:

```bash
npm run spell-check
```

To automatically fix spelling issues where possible:

```bash
npm run spell-check:fix
```

The spell checker uses cspell with configuration in `.cspell.json`. Add custom words to the `words` array in that file.

### Markdown Linting

To lint markdown files:

```bash
npm run markdown-lint
```

To automatically fix markdown issues where possible:

```bash
npm run markdown-lint:fix
```

The markdown linter uses markdownlint-cli2 with configuration in `.markdownlint-cli2.yaml`.

## Examples

### Blobs

The `blobs` example is a simple demo application to list and read blobs. You need to create an app registration for RBAC initially, however:

```bash
az ad sp create-for-rbac -n akv-demo
```

Note the `appId` and `password` fields. You'll want to pass the `appId` when provisioning resources the first time:

```bash
AZURE_CLIENT_ID='{appId}' azd up
```

Once provisioning is complete and because the debug builds of `akv` will automatically read the `azd` environment care of [`dotazure`][dotazure],
you can create client secret and retain the secret reference for `azd`:

```bash
cargo run -- secret create client-secret='{password}'
azd env set AZURE_CLIENT_SECRET '{ID from previous command}'
```

Now you can run the `blobs` example within the `akv run` command:

```bash
cargo run -- run -- cargo run --example blobs
```

## Troubleshooting

To help troubleshoot issues, you can trace information to the terminal:

```bash
RUST_LOG=info,akv=debug cargo run -- secret list
```

The [`RUST_LOG`][RUST_LOG] environment variable here sets the default tracing level to `info`
but `debug` for all `akv` traces.

[Azure Developer CLI]: https://learn.microsoft.com/azure/developer/azure-developer-cli/install-azd
[Dev container]: https://code.visualstudio.com/docs/devcontainers/create-dev-container
[dotazure]: https://github.com/heaths/dotazure-rs
[GitHub Codespaces]: https://github.com/features/codespaces
[Node.js]: https://nodejs.org
[Pester]: https://pester.dev/docs/introduction/installation
[PowerShell]: https://learn.microsoft.com/powershell/scripting/install/install-powershell
[Rust]: https://www.rust-lang.org
[RUST_LOG]: https://docs.rs/env_logger/latest/env_logger/#enabling-logging
[Visual Studio Code]: https://code.visualstudio.com
