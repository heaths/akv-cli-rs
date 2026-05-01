# Azure Key Vault CLI Development Guide

Unofficial Azure Key Vault CLI built in Rust: secret management, encryption/decryption, Key Vault resource operations.

## Build and Test

```bash
cargo build --all-features          # build
cargo test --all-features --workspace  # test
cargo fmt --all                     # format
cargo clippy --all-features --all-targets --no-deps --workspace  # lint
cargo doc --all-features --no-deps --workspace   # docs
```

- Release build: `cargo build --release --all-features`
- Scoped test: `cargo test --all-features --workspace <name>`
- With logging: `RUST_LOG=info,akv=debug cargo test --all-features --workspace`
- CI sets `RUSTFLAGS: -Dwarnings` and `CARGO_INCREMENTAL: 0`; runs on macOS, Ubuntu, Windows

## Skills

Use these skills when applicable. Read the skill file for full instructions.

| Skill         | File                                      | When to use                           |
|---------------|-------------------------------------------|---------------------------------------|
| spell-check   | `.github/skills/spell-check/SKILL.md`     | Checking or fixing spelling errors    |
| markdown-lint | `.github/skills/markdown-lint/SKILL.md`   | Linting or fixing markdown formatting |

## Workflow

Before marking any request complete:

- Run `cargo test --all-features --workspace` if Rust code changed
- Run the spell-check skill if any text content changed
- Run the markdown-lint skill whenever any markdown file is modified

Commits and PRs:

- Subject line: imperative mood, ≤72 chars (e.g. `Add secret delete command`)
- Blank line between subject and body
- Body: concise, factual — no filler prose
- PR titles follow the same format as commit subjects

## Architecture

### Binary (`src/bin/akv/`)

- `main.rs` — entry point, clap arg parsing, tracing setup
- `commands/` — subcommands: `certificate`, `decrypt`, `encrypt`, `inject`, `key`, `read`, `run`, `secret`
- `pty/` — PTY wrapper for `run` command to mask secrets in stdout/stderr

### Library (`src/`)

- `cache.rs` — `ClientCache<T>`: caches Key Vault clients (Secret/Key/Certificate) by vault URL
- `jose/` — custom JWE: generates CEK locally, wraps with Azure Key Vault RSA-OAEP, AES-GCM content encryption
- `error.rs` — `Error`, `ErrorKind`, `Result` alias
- `parsing.rs` — argument parsing utilities
- `json.rs` — JSON utilities
- `color.rs` — color mode config (feature-gated)

### Authentication

- If `.azure/dev/.env` exists (from `azd up`): uses `AzureDeveloperCliCredential` exclusively
- Otherwise: `DeveloperToolsCredential` (tries multiple methods)
- Credential stored in `static OnceLock<Arc<dyn TokenCredential>>`

### Environment Variable Loading

1. Load `.azure/dev/.env` (Azure Developer CLI)
2. Fall back to ancestor-directory search for `.env`
3. Debug builds auto-load; release builds require explicit `--vault`

### Secret Masking (`run` command)

PTY intercepts stdout/stderr and masks values of env vars that are either Key Vault secret URLs or JWE compact tokens.

## Code Conventions

- **Errors**: `Result<T>` alias from `src/error.rs`; use `ResultExt::context()` for context; `Error::with_message()` for custom messages
- **Logging**: `tracing` crate only — no `println!`/`eprintln!`; use `target: "akv::module"`; `-v` = INFO, `-vv` = DEBUG, `-vvv` = TRACE
- **Features**: default is `["color"]`; guard with `#[cfg(feature = "color")]`
- **Docs**: `#![deny(missing_docs)]`; module docs via `//!`; public APIs via `///`
- **Tests**: unit tests in `#[cfg(test)]` modules; integration tests require `azd up`
- **Toolchain**: nightly Rust (see `rust-toolchain.toml`); MSRV 1.88; unstable features: `windows_process_extensions_raw_attribute`, `once_cell_try`
