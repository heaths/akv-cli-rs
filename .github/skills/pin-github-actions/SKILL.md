---
name: pin-github-actions
description: Run when adding or updating GitHub Actions workflow steps. Pin every action to a commit SHA with the resolved version tag as a trailing comment.
---

# Pin GitHub Actions

Every `uses:` step in a workflow must reference an exact commit SHA, not a tag or branch.
Append the resolved version tag as a trailing comment so the intent is clear.

**Format:**

```yaml
uses: owner/action@<commit-sha> # vX.Y.Z
```

**Example:**

```yaml
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
```

## Resolving the SHA

Given a tag like `v4`:

```bash
# Resolve the tag to a commit SHA (dereference annotated tags with ^{})
git ls-remote https://github.com/<owner>/<action>.git "refs/tags/v4" "refs/tags/v4^{}"
# Use the ^{} SHA if present (annotated tag), otherwise use the direct SHA.

# Find the exact semver tag that points to the same commit
git ls-remote https://github.com/<owner>/<action>.git "refs/tags/v4.*"
# Dereference each candidate with ^{} and match against the commit SHA above.
# Use the highest matching semver tag as the comment (e.g., # v4.1.0).
```

## Rules

- Never reference a mutable tag (e.g., `@v4`, `@main`).
- Never omit the version comment — it is the only human-readable clue to the pinned version.
- Dependabot keeps SHAs current; do not manually update SHAs unless Dependabot cannot reach the action.
- Internal workflow references (`uses: ./.github/workflows/...`) are exempt.
