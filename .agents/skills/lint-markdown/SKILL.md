---
name: lint-markdown
description: Run automatically whenever any markdown file is modified. Use when linting or fixing markdown formatting.
---

# Lint Markdown

Install: `npm i`

Fix changed markdown files:

```bash
npx markdownlint-cli2 --no-globs --fix $(git diff --name-only --diff-filter=d HEAD -- '*.md' '*.markdown')
```

- `--no-globs` prevents falling back to config globs when no files changed
- Auto-fix handles most issues
- Unfixable issues: show the output to the user and ask what to do
- Config: `.markdownlint-cli2.yaml` · [Rules](https://github.com/DavidAnson/markdownlint/blob/main/doc/Rules.md)
