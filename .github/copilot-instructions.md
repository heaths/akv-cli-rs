# Azure Key Vault CLI Development Guide

This is an unofficial Azure Key Vault CLI built in Rust that provides secure secret management, encryption/decryption, and Key Vault resource operations.

## Building and Testing

### Build Commands

```bash
# Build the project
cargo build

# Build with all features (includes color support)
cargo build --all-features

# Release build (optimized for size)
cargo build --release --all-features
```

### Test Commands

```bash
# Run all unit tests
cargo test --all-features --workspace

# Run tests for a specific module
cargo test --all-features --workspace <module_name>

# Run a specific test
cargo test --all-features --workspace <test_name>

# Run tests with logging output
RUST_LOG=info,akv=debug cargo test --all-features --workspace
```

### Lint and Format

```bash
# Check code formatting
cargo fmt --all -- --check

# Format code
cargo fmt --all

# Run clippy lints (CI runs with -Dwarnings)
cargo clippy --all-features --all-targets --no-deps --workspace

# Check spelling
npm run spell-check

# Lint markdown files
npm run markdown-lint

# Build documentation
cargo doc --all-features --no-deps --workspace
```

**Always run linting after making changes:**

- Format code with `cargo fmt --all`
- Run `npm run spell-check` and `npm run markdown-lint` for documentation changes
- Fix any issues before committing

### Benchmarks

```bash
# Run benchmarks (uses criterion)
cargo bench
```

## Project Architecture

### Binary Structure

The main binary is `akv` (crate name is `akv-cli`). Structure:

- **src/bin/akv/main.rs** - Entry point, argument parsing with clap, tracing setup
- **src/bin/akv/commands/** - Subcommand implementations (certificate, decrypt, encrypt, inject, key, read, run, secret)
- **src/bin/akv/pty/** - PTY handling for the `run` command to mask secrets in stdout/stderr

### Library Structure

- **src/lib.rs** - Public API surface (minimal; primarily CLI-focused)
- **src/cache.rs** - `ClientCache<T>` for caching Key Vault clients by vault URL
- **src/jose/** - JSON Web Encryption (JWE) implementation for local encrypt/decrypt
- **src/error.rs** - Error types (`Error`, `ErrorKind`, `Result`)
- **src/parsing.rs** - Utility functions for parsing arguments
- **src/json.rs** - JSON utility functions
- **src/color.rs** - Color mode configuration (when `color` feature enabled)

### Key Architectural Patterns

#### Authentication

- Uses Azure identity crates (`azure_identity`) with automatic credential discovery
- If `.azure/dev/.env` exists (created by `azd up`), uses `AzureDeveloperCliCredential` exclusively for consistent auth
- Otherwise falls back to `DeveloperToolsCredential` (tries multiple auth methods)
- Credentials are stored in a static `OnceLock<Arc<dyn TokenCredential>>`

#### Client Caching

The `ClientCache<T>` type caches Azure SDK clients (SecretClient, KeyClient, CertificateClient) by vault URL to avoid recreating clients for the same vault.

#### Secret Masking

The `run` command uses a PTY wrapper to intercept stdout/stderr and mask secrets in real-time. Secrets are identified by:

- Environment variable values that are URLs to Key Vault secrets
- JWE compact tokens in environment variables

#### JWE Implementation

Custom JWE (JSON Web Encryption) implementation in `src/jose/`:

- Generates content encryption keys (CEK) locally
- Wraps CEK using Azure Key Vault keys (RSA-OAEP algorithms)
- Supports AES-GCM for content encryption (128, 192, 256-bit)
- Compact serialization format for easy storage

#### Environment Variable Loading

Uses `dotazure` and `dotenvy` crates to:

1. First try loading `.azure/dev/.env` (created by Azure Developer CLI)
2. Fall back to ancestor directory search for `.env` files
3. Debug builds auto-load these; release builds require explicit `--vault` parameter

## Code Conventions

### Error Handling

- Use `Result<T>` alias defined in `src/error.rs` (maps to `std::result::Result<T, Error>`)
- Use `ErrorKind` enum for error categorization
- Extend errors with context using `ResultExt::context()` trait
- Use `Error::with_message()` or `Error::with_message_fn()` for custom messages

### Tracing

- Use `tracing` crate, not `println!` or `eprintln!` for debug/info logs
- Target specific traces with `target: "akv::module"` for better filtering
- Control verbosity via `RUST_LOG` environment variable (e.g., `RUST_LOG=info,akv=debug`)
- Trace levels: `-v` = INFO, `-vv` = DEBUG, `-vvv` = TRACE

### Features

- Default feature: `["color"]` - enables colored output
- Color support via `clap/color`, `colored_json`, and `yansi` crates
- Guard color-related code with `#[cfg(feature = "color")]`

### Testing

- Unit tests use `#[cfg(test)]` modules
- Integration tests require provisioning a real Key Vault via `azd up`
- Manual testing documented in CONTRIBUTING.md with example scripts in `examples/`

### Documentation

- All public items require `#![deny(missing_docs)]`
- Module-level docs use `//!` at the top of files
- Use doc comments `///` for public APIs

### Toolchain

- Requires nightly Rust (specified in `rust-toolchain.toml`)
- MSRV: 1.85 (specified in Cargo.toml)
- Uses unstable features: `windows_process_extensions_raw_attribute`, `once_cell_try`

## Development Workflow

### Local Development Setup

```bash
# Install Azure Developer CLI (optional but recommended)
brew install azd  # or see https://aka.ms/azure-dev

# Provision a test Key Vault (creates .azure/dev/.env)
azd up

# Run the CLI in development mode (auto-loads .env)
cargo run -- secret list
cargo run -- read --name secret-1

# Set up example environment variables
source ./examples/setup.sh  # bash/zsh
# or
. ./examples/setup.ps1      # PowerShell
```

### Troubleshooting

```bash
# Enable detailed tracing
RUST_LOG=info,akv=debug cargo run -- <command>

# Trace Azure SDK calls
RUST_LOG=azure_core=debug,akv=debug cargo run -- <command>
```

### CI Environment

- Runs on macOS, Ubuntu, and Windows
- Sets `RUSTFLAGS: -Dwarnings` (treat warnings as errors)
- Sets `CARGO_INCREMENTAL: 0` for clean builds
- Windows builds require OpenSSL configuration
