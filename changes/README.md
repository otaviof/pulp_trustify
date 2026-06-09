# Changelog Fragments

Each pull request should include a changelog fragment file in this directory.

## Naming Convention

`<identifier>.<type>.md`

- **identifier**: issue number, PR number, or `+short-slug` for changes
  without an associated issue
- **type**: `added`, `changed`, `fixed`, `removed`, `security`, or `deprecated`

## Examples

```
changes/42.added.md
changes/+gate-advisory-model.added.md
```

Content is a single bullet point describing the change for end users.

Run `poe changelog-draft` to preview the compiled output.
