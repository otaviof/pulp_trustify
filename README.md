# pulp_trustify

Pulp plugin integrating Trustify CVE intelligence for vulnerability-gated artifact serving.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Tasks

All project tasks are managed via [Poe the Poet](https://poethepoet.naez.com/):

| Task | Command | Description |
|:-----|:--------|:------------|
| Lint | `poe lint` | Run ruff linter checks |
| Fix | `poe fix` | Auto-fix lint violations |
| Format check | `poe fmt-check` | Verify code formatting |
| Format | `poe fmt` | Apply code formatting |
| Test | `poe test` | Run unit tests |
| **All checks** | `poe check` | Lint + format + test |

### Test Layout

Unit tests live side-by-side with source files using `*_test.py` naming (e.g.,
`app/models.py` and `app/models_test.py`).
