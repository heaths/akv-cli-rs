---
name: markdown-lint
description: Run automatically whenever any markdown file is modified. Use when linting or fixing markdown formatting.
---

# Markdown Lint

```bash
npm run markdown-lint        # check
npm run markdown-lint:fix    # auto-fix
```

- Config: `.markdownlint-cli2.yaml` (enabled rules, ignored paths)
- [Rule reference](https://github.com/DavidAnson/markdownlint/blob/main/doc/Rules.md)
- Auto-fix handles most issues; fix remaining ones manually and verify
