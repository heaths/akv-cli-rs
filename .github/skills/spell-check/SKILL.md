---
name: spell-check
description: Run before marking any request complete if docs, comments, or text content changed. Use when checking or fixing spelling errors.
---

# Spell Check

```bash
npm run spell-check        # check
npm run spell-check:fix    # auto-fix
```

- Config: `.cspell.json` (custom dictionaries, ignored paths, file overrides)
- Legitimate terms: add to `words` (general) or `dictionaryDefinitions[name="crates"].words` (Rust crates)
- Run `npm run spell-check` to verify after adding words
