---
name: analyze-help
description: Run when CLI commands or arguments change. Analyze commands and arguments for consistent patterns.
---

# Analyze Help

Analyze generated CLI help for **unexpected** inconsistencies only. Accepted differences below should **not** be flagged unless behavior or docs drift beyond these rules.

Generate help from clap:

```bash
RUSTFLAGS='--cfg help_markdown' cargo run -- help-markdown
```

- Analyze stdout directly; do not save generated help into this repo just for review
- Ignore utility commands: `completion`, `help-markdown`

## General commands

- Group: `inject`, `run`, `read`, `encrypt`, `decrypt`
- `run` is process/env oriented and does not need the same selector or file flags as the others
- `decrypt` may differ from `encrypt` because key selection comes from the JWE `kid`
- `inject` may differ from `read` because it transforms templates rather than reading one named secret

## Management commands

- Group: `secret`, `key`, `certificate`
- Shared resource-targeting pattern should stay consistent where applicable:
  - full resource URL
  - or `--name <NAME>` + `--vault <URL>` + optional `--version <VERSION>`
- `secret create` using positional `NAME=VALUE` is acceptable
- `create` commands may otherwise differ by resource-specific properties
- Certificate policy commands are valid exceptions:
  - `edit-policy`, `get-policy`
  - may differ from other certificate commands because policy is distinct from certificate version retrieval
- Certificate commands may have additional options beyond secret/key

## Flag only

- New selector mismatches within a command group
- New required/optional argument mismatches for equivalent operations
- New naming drift for equivalent parameters
- New doc/example path errors, especially resource URL shapes
