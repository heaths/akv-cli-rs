---
name: markdown-lint
description: Guide for linting markdown files using markdownlint-cli2. Use this when asked to lint markdown, fix markdown formatting, or check markdown files.
---

# Markdown Linting with markdownlint-cli2

## Commands

```bash
# Lint markdown files
npm run markdown-lint

# Auto-fix markdown issues
npm run markdown-lint:fix
```

## Configuration

Configuration is in `.markdownlint-cli2.yaml`. See that file for enabled rules and ignored paths.

[Rule reference](https://github.com/DavidAnson/markdownlint/blob/main/doc/Rules.md)

## Workflow

1. Run `npm run markdown-lint` to identify issues
2. Run `npm run markdown-lint:fix` to auto-fix most issues
3. Manually fix remaining issues if needed
4. Verify with `npm run markdown-lint`
