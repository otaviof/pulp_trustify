from __future__ import annotations

import pytest

CLEAN_PURL = "pkg:pypi/requests@2.28.0"


@pytest.mark.e2e
@pytest.mark.guard
def test_analyze_with_real_oidc_token(
    trustify_client,
):
    result = trustify_client.analyze([CLEAN_PURL])
    assert isinstance(result, dict)


@pytest.mark.e2e
@pytest.mark.guard
def test_analyze_response_structure(
    trustify_client,
):
    result = trustify_client.analyze([CLEAN_PURL])
    assert isinstance(result, dict)
