---
name: spell-check
description: Guide for checking spelling using cspell. Use this when asked to check spelling, fix spelling errors, or run spell check.
---

# Spell Checking with cspell

## Commands

```bash
# Check spelling
npm run spell-check

# Auto-fix spelling issues
npm run spell-check:fix
```

## Configuration

Configuration is in `.cspell.json`. See that file for custom dictionaries, ignored paths, and file-specific overrides.

## Adding New Words

When cspell flags a legitimate word:

1. For general technical terms → Add to root-level `words` array in `.cspell.json`
2. For Rust crate names → Add to `dictionaryDefinitions[name="crates"].words` array in `.cspell.json`
3. Run `npm run spell-check` to verify

## Workflow

1. Run `npm run spell-check` to identify issues
2. For legitimate terms, add them to `.cspell.json`
3. For real errors, run `npm run spell-check:fix` or fix manually
4. Verify with `npm run spell-check`
