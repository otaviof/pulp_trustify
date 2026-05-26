from __future__ import annotations

import os

import pytest

from pulp_trustify.client.client import TrustifyClient

_PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..")


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers",
        "integration: mark test as integration test requiring network",
    )


@pytest.fixture()
def trustify_env() -> dict[str, str]:
    """Load Trustify connection settings from .env file."""
    env: dict[str, str] = {}
    env_path = os.path.join(_PROJECT_ROOT, ".env")
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                env[key.strip()] = value.strip()
    return env


@pytest.fixture()
def trustify_client(trustify_env) -> TrustifyClient:
    """Build a TrustifyClient from .env credentials."""
    ca = os.path.join(
        _PROJECT_ROOT,
        trustify_env["PULP_TRUSTIFY_CA_BUNDLE"],
    )
    return TrustifyClient(
        url=trustify_env["PULP_TRUSTIFY_URL"],
        client_id=trustify_env["PULP_TRUSTIFY_CLIENT_ID"],
        client_secret=trustify_env["PULP_TRUSTIFY_CLIENT_SECRET"],
        issuer_url=trustify_env["PULP_TRUSTIFY_ISSUER_URL"],
        ca_bundle=ca,
    )
