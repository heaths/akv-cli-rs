---
name: check-spelling
description: Run before marking any request complete if docs, comments, or text content changed. Use when checking or fixing spelling errors.
---

# Check Spelling

Install: `npm i`

Check changed files:

```bash
git diff --name-only --diff-filter=d HEAD | npx cspell lint --config .cspell.json --file-list stdin
```

Auto-fix obvious misspellings:

```bash
git diff --name-only --diff-filter=d HEAD | npx cspell lint --config .cspell.json --fix --file-list stdin
```

- Unknown words: ask whether to correct the spelling or add to the nearest config
- **Finding the config**: walk up ancestor directories looking for `.cspell.json`, then `cspell.json` in each directory; if you reach the git root without finding one, also check `.vscode/cspell.json`
- **Adding words**: edit the config file directly — add to the `words` array (general terms) or `dictionaryDefinitions[name="crates"].words` (Rust crates)
- Verify after adding words: rerun the check command
