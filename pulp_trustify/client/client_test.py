from __future__ import annotations

import os

import pytest

from pulp_trustify.client.client import (
    TrustifyClient,
    TrustifyError,
)

_PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")


@pytest.fixture()
def trustify_env() -> dict[str, str]:
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


@pytest.mark.integration
def test_analyze_with_real_oidc_token(
    trustify_client,
):
    result = trustify_client.analyze(["pkg:pypi/requests@2.28.0"])
    assert isinstance(result, dict)


@pytest.mark.integration
def test_analyze_response_structure(
    trustify_client,
):
    result = trustify_client.analyze(["pkg:pypi/requests@2.28.0"])
    assert isinstance(result, dict)


def test_no_auth_header_when_issuer_url_empty():
    client = TrustifyClient(url="https://example.com", issuer_url="")
    headers = client._get_headers()
    assert "Authorization" not in headers
    assert headers["Content-Type"] == "application/json"


def test_trustify_error_on_connection_failure():
    client = TrustifyClient(
        url="https://nonexistent.invalid.domain.local",
        issuer_url="",
    )
    with pytest.raises(
        TrustifyError,
        match="Trustify API request failed",
    ):
        client.analyze(["pkg:pypi/requests@2.28.0"])


def test_oidc_error_on_invalid_issuer():
    client = TrustifyClient(
        url="https://example.com",
        client_id="test",
        client_secret="test",
        issuer_url="https://nonexistent.invalid.domain.local/realms/x",
    )
    with pytest.raises(
        TrustifyError,
        match="Failed to fetch OIDC token",
    ):
        client.analyze(["pkg:pypi/requests@2.28.0"])
