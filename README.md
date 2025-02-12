# Azure Key Vault CLI (Unofficial)

[![releases](https://img.shields.io/github/v/release/heaths/akv-cli-rs.svg?logo=github)](https://github.com/heaths/akv-cli-rs/releases/latest)
[![ci](https://github.com/heaths/akv-cli-rs/actions/workflows/ci.yml/badge.svg?event=push)](https://github.com/heaths/akv-cli-rs/actions/workflows/ci.yml)

The Azure Key Vault CLI can be used to read secrets, pass them securely to other commands, or inject them into configuration files.

## Installation

If you have [Rust](https://www.rust-lang.org/tools/install) installed, you can build the CLI on nearly any platform:

```bash
cargo install akv-cli
```

## Using

Inspired by the [1Password CLI], you can use similar commands to pull secrets from [Azure Key Vault].
Though the crate is named `akv-cli`, note that the actual program is named `akv`.

### Listing secrets

Use the `list` command to list secrets.

```bash
akv list https://my-vault.vault.azure.net
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

## Background

Though still a work in progress, inspiration was derived from the [1Password CLI].
As the previous primary developer on the [Azure Key Vault SDK for .NET](https://github.com/Azure/azure-sdk-for-net)
and current primary developer on the [Azure SDK for Rust](https://github.com/Azure/azure-sdk-for-rust) - including Key Vault -
I wanted to make something useful to test our initial prerelease of the Rust class libraries.

## License

Licensed under the [MIT](LICENSE.txt) license.

[1Password CLI]: https://developer.1password.com/docs/cli/
[Azure Key Vault]: https://azure.microsoft.com/products/key-vault/
