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
| Fix | `poe format-fix` | Auto-fix lint violations |
| Format check | `poe format-check` | Verify code formatting |
| Format | `poe fmt` | Apply code formatting |
| Unit tests | `poe test-unit` | Run unit tests (`not e2e`) |
| **All checks** | `poe check` | Lint + format + unit tests |
| E2E tests | `poe test-e2e` | Phase 1: status, scan, guard |
| E2E gate | `poe test-e2e-gate` | Phase 2: upload gate |
| **Full E2E** | `poe e2e` | Two-phase pipeline (up → test → gate → down) |
| E2E up | `poe e2e-up` | Start compose stack |
| E2E down | `poe e2e-down` | Stop compose stack |
| E2E restart | `poe e2e-restart-pulp` | Restart Pulp with gate on |
| Image build | `poe image-build` | Build the plugin container image |
| Image tag | `poe image-tag` | Tag image with project version |
| Image push | `poe image-push` | Push image to the dev registry |
| Deploy | `poe deploy` | Deploy to Kubernetes (see [deploy/README.md](deploy/README.md)) |
| Release | `poe release` | Validate, tag, push, and create GitHub release |
| Version | `poe version` | Print project version |

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

Unit tests live side-by-side with source files using `*_test.py` naming. Run with `poe test-unit`. E2E tests require a compose environment (PostgreSQL + Trustify + Pulp) and are selected by feature markers (`e2e`, `gate`, `guard`, `scan`, `status`).

To run the full E2E pipeline locally:

```bash
# Two-phase test (gate disabled → gate enabled)
poe e2e

# For Docker users (CI default)
COMPOSE="docker compose" poe e2e
```

See [tests/README.md](tests/README.md) for E2E testing details, including the two-phase testing strategy, infrastructure setup, and troubleshooting.

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

## CI/CD

GitHub Actions runs lint, test, build, E2E, and publish on every push to `main` and PR. See `.github/workflows/` for workflow definitions.

## Deployment

See [deploy/README.md](deploy/README.md).

## Releasing

The release workflow is automated via `poe release`, which delegates to `hack/release.py`. The script validates the working directory, version, and changelog, then creates a git tag and GitHub release. The tag push triggers the CI pipeline to build and publish the container image.

Before releasing:

1. Ensure `main` is up to date: `git pull origin main`
2. Verify the version in `pyproject.toml` is correct
3. Run checks: `poe check`
4. Compile the changelog: `poe changelog`
5. Commit: `git add CHANGELOG.md changes/ && git commit -m "release(vX.Y.Z): compile changelog"`

To release:

```bash
poe release
```

Or dry-run first:

```bash
VERSION=$(poe -q version) python hack/release.py --dry-run
```

After release, verify the GitHub release appears at https://github.com/otaviof/pulp_trustify/releases and the container image is pushed to `ghcr.io/otaviof/pulp_trustify:<version>`.

For details on what the script does, run `python hack/release.py --help` or read the source at `hack/release.py`.
