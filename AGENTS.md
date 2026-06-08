# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Quick Start

Activate the virtualenv before running any tool:

```bash
source .venv/bin/activate
```

If dependencies or dev tools are missing, reinstall:

```bash
pip install -e '.[dev]'
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and `poe` tasks. Tool configuration lives in [pyproject.toml](pyproject.toml).

## Architecture

`pulpcore` plugin — Django app discovered via the `pulpcore.plugin` entry point. `pulp_trustify/__init__.py` exposes `default_app_config`, resolving to `PulpTrustifyPluginAppConfig` in `pulp_trustify/app/__init__.py`.

All AppConfig attributes (version, label, package name) come from `importlib.metadata` — `pyproject.toml` is the single source of truth.

## Documentation

Read broad to narrow. Start at the top, stop when you have enough context.

| Doc | Scope |
|-----|-------|
| [README.md](README.md) | project overview, quick start |
| [docs/architecture.md](docs/architecture.md) | protection layers, PURL extraction, auth |
| [docs/detection.md](docs/detection.md) | detection pipeline, severity filtering, importers |
| [docs/settings.md](docs/settings.md) | all Dynaconf settings, observability, debugging |
| [docs/known-limitations.md](docs/known-limitations.md) | constraints, trade-offs, edge cases |

**Feature deep-dives** — one doc per protection layer:

| Doc | Feature |
|-----|---------|
| [docs/guard.md](docs/guard.md) | download guard (ContentGuard) |
| [docs/upload-gate.md](docs/upload-gate.md) | upload gate (pre_save signal) |
| [docs/scanner.md](docs/scanner.md) | scanner task, quarantine, advisories |
| [docs/yank.md](docs/yank.md) | PEP 592 yank middleware |
| [docs/deprecate.md](docs/deprecate.md) | NPM deprecation (content_handler patch) |

**Operations:** [CONTRIBUTING.md](CONTRIBUTING.md) · [deploy/README.md](deploy/README.md)

## Rules

- **Imports**: absolute only. Use `pulpcore.plugin`, never `pulpcore.app`.
- **DRY**: derive, don't duplicate. Read values from `pyproject.toml` at runtime.
- **Tests**: co-located `*_test.py` files.
- **Line length**: 82 (Python code only, not markdown).
- **Comments**: only when the *why* is non-obvious.
- **Versioning**: bump the version in `pyproject.toml` on every project change, following [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`). Drop the `.dev` suffix on first real release.
- **Task runner**: `poe`, not raw tool commands. Run `poe check` before submitting.
