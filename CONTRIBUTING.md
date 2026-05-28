# Contributing Guide

Development workflow and tooling for `pulp_trustify`.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

If dependencies or dev tools are missing after updates, reinstall:

```bash
pip install -e '.[dev]'
```

## Task Runner

All project tasks are managed via [Poe the Poet](https://poethepoet.naez.com/):

| Task | Command | Description |
|:-----|:--------|:------------|
| Lint | `poe lint` | Run ruff linter checks |
| Fix | `poe fix` | Auto-fix lint violations |
| Format check | `poe fmt-check` | Verify code formatting |
| Format | `poe fmt` | Apply code formatting |
| Test | `poe test` | Run unit tests |
| **All checks** | `poe check` | Lint + format + test (run before committing) |
| Image build | `poe image-build` | Build the plugin container image |
| Image push | `poe image-push` | Push image to the dev registry |
| Deploy | `poe deploy` | Deploy to Kubernetes (see [deploy/README.md](deploy/README.md)) |

## Before Submitting

Run the full check suite to verify lint, format, and tests:

```bash
poe check
```

This command runs:
1. `ruff check .` — linter checks
2. `ruff format --check .` — format verification
3. `pytest` — unit tests

All three must pass before opening a pull request.

## Code Style

- **Line length:** 82 characters max
- **Imports:** Absolute only. Use `pulpcore.plugin`, never `pulpcore.app`.
- **Formatting:** Managed by `ruff format` (no manual enforcement needed)
- **Comments:** Only when the *why* is non-obvious. Avoid comments that restate the code.

## Testing

Unit tests live side-by-side with source files using `*_test.py` naming. Run all unit tests with `poe test` or `pytest` directly. Integration tests require a live Trustify instance and are marked with `@pytest.mark.integration` (run with `pytest -m integration`).

## Architecture

This is a `pulpcore` plugin — a Django app discovered at runtime via the `pulpcore.plugin` entry point. The entry point resolves to `PulpTrustifyPluginAppConfig` in `pulp_trustify/app/__init__.py`.

All configuration (version, package name, dependencies) is derived from `importlib.metadata` at runtime. `pyproject.toml` is the single source of truth — never hardcode values that can be read from it.

## Configuration

All tool configuration lives in `pyproject.toml`. Before changing build, lint, or test behavior, read the section comments in that file.

Key sections:

- `[build-system]` — PEP 517/518 backend (setuptools)
- `[project]` — PEP 621 metadata (dependencies, entry points)
- `[tool.ruff]` — Linter and formatter config
- `[tool.pytest.ini_options]` — Test discovery and options
- `[tool.poe]` — Task definitions and environment variables

## Deployment

See [deploy/README.md](deploy/README.md).