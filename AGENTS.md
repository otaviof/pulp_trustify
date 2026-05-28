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

Each doc has one job, create links, don't repeat:

- [README.md](README.md): overview, architecture, settings, usage
- [CONTRIBUTING.md](CONTRIBUTING.md): dev setup, poe tasks, code style, testing
- [deploy/README.md](deploy/README.md): deployment, env vars, script flags

## Deployment

See [deploy/README.md](deploy/README.md).

## Rules

- **Imports**: absolute only. Use `pulpcore.plugin`, never `pulpcore.app`.
- **DRY**: derive, don't duplicate. Read values from `pyproject.toml` at runtime.
- **Tests**: co-located `*_test.py` files.
- **Line length**: 82 (Python code only, not markdown).
- **Comments**: only when the *why* is non-obvious.
- **Task runner**: `poe`, not raw tool commands. Run `poe check` before submitting.
