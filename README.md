# Azure Key Vault CLI (Unofficial)

[![releases](https://img.shields.io/github/v/release/heaths/akv-cli-rs.svg?logo=github)](https://github.com/heaths/akv-cli-rs/releases/latest)
[![ci](https://github.com/heaths/akv-cli-rs/actions/workflows/ci.yml/badge.svg?event=push)](https://github.com/heaths/akv-cli-rs/actions/workflows/ci.yml)

The Azure Key Vault CLI can be used to read secrets, pass them securely to other commands, or inject them into configuration files.

## Installation

Use [Homebrew] to install binaries for most macOS and Linux platforms, or build source when necessary.

You first need to install the tap, but only the first time:

```bash
brew tap heaths/tap
```

Once the tap is installed, you can install or update the `akv-cli` formulae:

```bash
brew install akv-cli
```

If you have [Rust](https://www.rust-lang.org/tools/install) installed, you can also build the CLI on nearly any platform:

```bash
cargo install akv-cli
```

## Using

Inspired by the [1Password CLI], you can use similar commands to pull secrets from [Azure Key Vault].
Though the crate is named `akv-cli`, note that the actual program is named `akv`.

Some arguments can read environment variables, e.g., `--vault` which reads from `AZURE_KEYVAULT_URL`.
This information can be found in `--help` for commands. This makes it easy to pass just the secret name e.g.,

```bash
export AZURE_KEYVAULT_URL=https://my-vault.vault.azure.net

akv secret list
akv read --name my-secret
```

### Injecting secrets

You can read a templated file or from stdin to inject secrets into the stream.
Any secret ID e.g., `https://my-vault.vault.azure.net/secrets/my-secret` between `{{ }}` will be replaced, if it exists.

```bash
echo "my-secret: {{ https://my-vault.vault.azure.net/secrets/my-secret }}" | akv inject
```

You can also read from stdin, or from files using `--in-file` e.g.,

```bash
cat <<'EOF' | akv inject -o config.json
{
    "token": "{{ https://my-vault.vault.azure.net/secrets/my-secret/746984e474594896aad9aff48aca0849 }}"
}
EOF
```

### Reading a secret

You can pass secrets to terminal applications, though how exactly depends on your shell. For bash,

```bash
cargo login $(akv read https://my-vault.vault.azure.net/secrets/my-secret)
```

Note that secrets in Key Vault are versioned. The example above reads the latest version, but you can also read any version.
It's often important to refer to a specific version until you're ready to rotate to a new secret.

```bash
akv read https://my-vault.vault.azure.net/secrets/my-secret/746984e474594896aad9aff48aca0849
```

### Passing secrets to new processes

You can start a process that reads environment variables containing URLs to secrets instead of keeping secrets in environment variables that any process can read.

Environment variables can contain only a URL to a secret.
Secrets read from Azure Key Vault will be masked in stdout and stderr unless you pass `--no-masking`.

```bash
export SECRET_VAR=https://my-vault.vault.azure.net/secrets/my-secret

akv run -- printenv SECRET_VAR
akv run --no-masking -- printenv SECRET_VAR
```

### Managing secrets

You can create, get, edit, and list secrets e.g.,

```bash
akv secret list --vault https://my-vault.vault.azure.net
```

Read complete usage using `--help`:

```bash
akv secret --help
```

## Background

Though still a work in progress, inspiration was derived from the [1Password CLI].
As the previous primary developer on the [Azure Key Vault SDK for .NET](https://github.com/Azure/azure-sdk-for-net)
and current primary developer on the [Azure SDK for Rust](https://github.com/Azure/azure-sdk-for-rust) - including Key Vault -
I wanted to make something useful to test our initial prerelease of the Rust class libraries.

## License

Licensed under the [MIT](LICENSE.txt) license.

[1Password CLI]: https://developer.1password.com/docs/cli/
[Azure Key Vault]: https://azure.microsoft.com/products/key-vault/
[Homebrew]: https://brew.sh
