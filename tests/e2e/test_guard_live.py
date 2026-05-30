from __future__ import annotations

import pytest

from pulp_trustify.guard import permit_request

VULNERABLE_PATH = "urllib3-2.6.2.tar.gz"


@pytest.mark.e2e
@pytest.mark.guard
def test_permit_allows_clean_package(trustify_client):
    """Allow request for a known-clean package."""
    permit_request(
        client=trustify_client,
        path="requests-2.32.0.tar.gz",
        threshold="critical",
        fail_open=False,
    )


@pytest.mark.e2e
@pytest.mark.guard
def test_permit_blocks_vulnerable_package(
    trustify_client,
):
    """Block urllib3@2.6.2 via analyze (OSV-PyPA data)."""
    with pytest.raises(PermissionError):
        permit_request(
            client=trustify_client,
            path=VULNERABLE_PATH,
            threshold="medium",
            fail_open=False,
        )


@pytest.mark.e2e
@pytest.mark.guard
def test_fallback_blocks_vulnerable_urllib3(
    trustify_client,
):
    """Block vulnerable urllib3 via search fallback."""
    with pytest.raises(PermissionError):
        permit_request(
            client=trustify_client,
            path=VULNERABLE_PATH,
            threshold="high",
            fail_open=False,
        )


@pytest.mark.e2e
@pytest.mark.guard
def test_fallback_allows_fixed_urllib3(
    trustify_client,
):
    """Allow fixed urllib3 via search fallback.

    2.7.0 is the fixed version for CVE-2026-44431 and
    CVE-2026-44432 (both "From X to before 2.7.0").
    """
    permit_request(
        client=trustify_client,
        path="urllib3-2.7.0.tar.gz",
        threshold="high",
        fail_open=False,
    )


@pytest.mark.e2e
@pytest.mark.guard
def test_search_and_version_matching(
    trustify_client,
):
    """Verify search + version parsing against live data.

    Exercises the fallback pipeline (text search, regex
    extraction, version comparison) independently of the
    analyze endpoint.
    """
    from pulp_trustify.version import (
        extract_version_ranges,
        is_version_affected,
    )

    response = trustify_client.search_vulnerabilities("urllib3")
    if response["total"] == 0:
        pytest.skip("No CVE data in search index (OSV-only environment)")

    for item in response["items"]:
        ranges = extract_version_ranges(item.get("description", ""))
        if ranges and is_version_affected("2.6.2", ranges):
            assert not is_version_affected("2.7.0", ranges)
            return

    pytest.fail("No CVE with parseable version ranges affecting urllib3 2.6.2")
