# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Quick Start

See [README.md § Development](README.md#development) for setup and available `poe` tasks. All tool configuration lives in [pyproject.toml](pyproject.toml) — read its section comments before changing build, lint, or test behavior.

## Architecture

This is a `pulpcore` plugin — a Django app discovered at runtime via the `pulpcore.plugin` entry point. `pulp_trustify/__init__.py` exposes `default_app_config`, which pulpcore resolves to `PulpTrustifyPluginAppConfig` in `pulp_trustify/app/__init__.py`.

All AppConfig attributes (version, label, package name) are derived from `importlib.metadata` — `pyproject.toml` is the single source of truth. Never hardcode values that can be read from it.

## Rules

- **Imports**: absolute only. Use `pulpcore.plugin`, never `pulpcore.app`.
- **DRY**: derive, don't duplicate. If a value exists in `pyproject.toml`, read it at runtime.
- **Tests**: co-located `*_test.py` files, not a separate `tests/` directory.
- **Line length**: 82.
- **Comments**: only when the *why* is non-obvious.
- **Task runner**: `poe`, not raw tool commands. Run `poe check` before submitting.
