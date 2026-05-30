from __future__ import annotations

import pytest


@pytest.mark.e2e
def test_analyze_with_real_oidc_token(
    trustify_client,
):
    result = trustify_client.analyze(["pkg:pypi/requests@2.28.0"])
    assert isinstance(result, dict)


@pytest.mark.e2e
def test_analyze_response_structure(
    trustify_client,
):
    result = trustify_client.analyze(["pkg:pypi/requests@2.28.0"])
    assert isinstance(result, dict)
