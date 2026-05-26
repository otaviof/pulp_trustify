from __future__ import annotations

import pytest

from pulp_trustify.client.client import TrustifyClient, TrustifyError


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
