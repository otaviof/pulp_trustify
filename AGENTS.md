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

Progressive disclosure — start broad, drill into specifics:

1. **README.md** — project overview and quick start
2. **docs/architecture.md** — protection layers, PURL extraction, authentication
3. **docs/detection.md** — detection pipeline, analyze + search fallback, severity filtering
4. **docs/\<feature\>.md** — per-feature deep-dives (guard, upload-gate, scanner, yank)
5. **docs/settings.md** — full configuration reference and observability
6. **docs/known-limitations.md** — all caveats and constraints

When answering questions about a specific feature, read its dedicated doc first. For cross-cutting concerns (detection modes, severity threshold), read docs/detection.md. For "why doesn't X work" questions, check docs/known-limitations.md.

Each doc has one job — create links, don't repeat:

- [README.md](README.md): overview, architecture diagram, quick start
- [CONTRIBUTING.md](CONTRIBUTING.md): dev setup, poe tasks, code style, testing
- [deploy/README.md](deploy/README.md): deployment, env vars, script flags
- [docs/architecture.md](docs/architecture.md): protection layers, PURL extraction, authentication
- [docs/detection.md](docs/detection.md): detection pipeline, severity filtering, importer requirements
- [docs/guard.md](docs/guard.md): download guard (ContentGuard)
- [docs/upload-gate.md](docs/upload-gate.md): upload gate (pre_save signal)
- [docs/scanner.md](docs/scanner.md): scanner task, actions, quarantine, advisories
- [docs/yank.md](docs/yank.md): PEP 592 yank middleware
- [docs/settings.md](docs/settings.md): all Dynaconf settings, observability, debugging
- [docs/known-limitations.md](docs/known-limitations.md): constraints, trade-offs, edge cases

## Deployment

See [deploy/README.md](deploy/README.md).

## Rules

- **Imports**: absolute only. Use `pulpcore.plugin`, never `pulpcore.app`.
- **DRY**: derive, don't duplicate. Read values from `pyproject.toml` at runtime.
- **Tests**: co-located `*_test.py` files.
- **Line length**: 82 (Python code only, not markdown).
- **Comments**: only when the *why* is non-obvious.
- **Task runner**: `poe`, not raw tool commands. Run `poe check` before submitting.
