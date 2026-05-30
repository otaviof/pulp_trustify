from __future__ import annotations

import logging

import pytest

from pulp_trustify.client.client import TrustifyError
from pulp_trustify.guard import permit_request

BASE_URL = "https://trustify.example.com"


class _FakeClient:
    def __init__(
        self,
        response=None,
        error=None,
        search_response=None,
        search_error=None,
    ):
        self._response = response
        self._error = error
        self._search_response = search_response
        self._search_error = search_error

    def analyze(self, purls):
        if self._error:
            raise self._error
        return self._response or {"items": []}

    def search_vulnerabilities(self, query, offset=0, limit=10):
        if self._search_error:
            raise self._search_error
        return self._search_response or {
            "items": [],
            "total": 0,
        }


def test_blocks_vulnerable_package():
    """Raise PermissionError when analyze returns critical CVE."""
    response = {
        "items": [
            {
                "purl": "pkg:pypi/requests@2.28.0",
                "details": [
                    {
                        "entry": {"cve": "CVE-2023-1234"},
                        "base_score": {"severity": "critical"},
                    }
                ],
            }
        ],
    }
    client = _FakeClient(response=response)

    with pytest.raises(PermissionError) as exc_info:
        permit_request(
            client=client,
            path="requests-2.28.0.tar.gz",
            threshold="critical",
            fail_open=False,
            base_url=BASE_URL,
        )

    error_msg = str(exc_info.value)
    assert "CVE-2023-1234" in error_msg
    assert "\n" not in error_msg


def test_allows_clean_package():
    """Allow request when analyze returns empty details."""
    response = {
        "items": [
            {
                "purl": "pkg:pypi/requests@2.32.0",
                "details": [],
            }
        ],
    }
    client = _FakeClient(response=response)

    permit_request(
        client=client,
        path="requests-2.32.0.tar.gz",
        threshold="critical",
        fail_open=False,
        base_url=BASE_URL,
    )


def test_allows_non_package_path():
    """Allow request when path does not resolve to a PURL."""
    client = _FakeClient()

    permit_request(
        client=client,
        path="/simple/requests/",
        threshold="critical",
        fail_open=False,
        base_url=BASE_URL,
    )


def test_fail_open_on_trustify_error():
    """Allow request when Trustify fails and fail_open is True."""
    client = _FakeClient(error=TrustifyError("API unavailable"))

    permit_request(
        client=client,
        path="requests-2.32.0.tar.gz",
        threshold="critical",
        fail_open=True,
        base_url=BASE_URL,
    )


def test_fail_closed_on_trustify_error():
    """Raise PermissionError when Trustify fails and fail_open is False."""
    client = _FakeClient(error=TrustifyError("API unavailable"))

    with pytest.raises(PermissionError, match="Trustify API unavailable"):
        permit_request(
            client=client,
            path="requests-2.32.0.tar.gz",
            threshold="critical",
            fail_open=False,
            base_url=BASE_URL,
        )


def test_ignores_low_severity_below_threshold():
    """Allow request when severity is below threshold."""
    response = {
        "items": [
            {
                "purl": "pkg:pypi/requests@2.28.0",
                "details": [
                    {
                        "entry": {"cve": "CVE-2023-5678"},
                        "base_score": {"severity": "medium"},
                    }
                ],
            }
        ],
    }
    client = _FakeClient(response=response)

    permit_request(
        client=client,
        path="requests-2.28.0.tar.gz",
        threshold="critical",
        fail_open=False,
        base_url=BASE_URL,
    )


def test_unknown_severity_not_blocked():
    """Allow request when base_score severity is None."""
    response = {
        "items": [
            {
                "purl": "pkg:pypi/requests@2.28.0",
                "details": [
                    {
                        "entry": {"cve": "CVE-2023-9999"},
                        "base_score": {"severity": None},
                    }
                ],
            }
        ],
    }
    client = _FakeClient(response=response)

    permit_request(
        client=client,
        path="requests-2.28.0.tar.gz",
        threshold="critical",
        fail_open=False,
        base_url=BASE_URL,
    )


def test_fallback_blocks_vulnerable_package():
    """Block vulnerable package via search fallback."""
    search_response = {
        "items": [
            {
                "identifier": "CVE-2026-21441",
                "title": "urllib3 vulnerable to ...",
                "description": (
                    "Starting in version 1.22 and prior to version 2.6.3"
                ),
                "average_severity": "high",
                "average_score": 8.9,
                "advisories": [],
            }
        ],
        "total": 1,
    }
    client = _FakeClient(
        response={},
        search_response=search_response,
    )

    with pytest.raises(PermissionError) as exc_info:
        permit_request(
            client=client,
            path="urllib3-2.6.2.tar.gz",
            threshold="high",
            fail_open=False,
            base_url=BASE_URL,
        )

    error_msg = str(exc_info.value)
    assert "CVE-2026-21441" in error_msg
    assert "\n" not in error_msg


def test_fallback_allows_fixed_version():
    """Allow fixed version via search fallback."""
    search_response = {
        "items": [
            {
                "identifier": "CVE-2026-21441",
                "title": "urllib3 vulnerable to ...",
                "description": (
                    "Starting in version 1.22 and prior to version 2.6.3"
                ),
                "average_severity": "high",
                "average_score": 8.9,
                "advisories": [],
            }
        ],
        "total": 1,
    }
    client = _FakeClient(
        response={},
        search_response=search_response,
    )

    permit_request(
        client=client,
        path="urllib3-2.6.3.tar.gz",
        threshold="high",
        fail_open=False,
        base_url=BASE_URL,
    )


def test_fallback_allows_no_version_ranges():
    """Allow when CVE has no parseable version ranges."""
    search_response = {
        "items": [
            {
                "identifier": "CVE-2026-12345",
                "title": "Some vulnerability",
                "description": "No version info here",
                "average_severity": "high",
                "average_score": 8.5,
                "advisories": [],
            }
        ],
        "total": 1,
    }
    client = _FakeClient(
        response={},
        search_response=search_response,
    )

    permit_request(
        client=client,
        path="urllib3-2.6.2.tar.gz",
        threshold="high",
        fail_open=False,
        base_url=BASE_URL,
    )


def test_fallback_allows_empty_search():
    """Allow when search returns no results."""
    search_response = {
        "items": [],
        "total": 0,
    }
    client = _FakeClient(
        response={},
        search_response=search_response,
    )

    permit_request(
        client=client,
        path="urllib3-2.6.2.tar.gz",
        threshold="high",
        fail_open=False,
        base_url=BASE_URL,
    )


def test_fallback_fail_open_on_search_error():
    """Allow when search fails and fail_open is True."""
    client = _FakeClient(
        response={},
        search_error=TrustifyError("Search API unavailable"),
    )

    permit_request(
        client=client,
        path="urllib3-2.6.2.tar.gz",
        threshold="high",
        fail_open=True,
        base_url=BASE_URL,
    )


def test_fallback_fail_closed_on_search_error():
    """Block when search fails and fail_open is False."""
    client = _FakeClient(
        response={},
        search_error=TrustifyError("Search API unavailable"),
    )

    with pytest.raises(PermissionError, match="Trustify API unavailable"):
        permit_request(
            client=client,
            path="urllib3-2.6.2.tar.gz",
            threshold="high",
            fail_open=False,
            base_url=BASE_URL,
        )


def test_analyze_preferred_over_fallback():
    """Use analyze path when it returns results."""
    response = {
        "items": [
            {
                "purl": "pkg:pypi/requests@2.28.0",
                "details": [
                    {
                        "entry": {"cve": "CVE-2023-1234"},
                        "base_score": {"severity": "critical"},
                    }
                ],
            }
        ],
    }
    client = _FakeClient(
        response=response,
        search_error=AssertionError("fallback should not be called"),
    )

    with pytest.raises(PermissionError) as exc_info:
        permit_request(
            client=client,
            path="requests-2.28.0.tar.gz",
            threshold="critical",
            fail_open=False,
            base_url=BASE_URL,
        )

    error_msg = str(exc_info.value)
    assert "CVE-2023-1234" in error_msg
    assert "\n" not in error_msg


def test_fallback_respects_severity_threshold():
    """Allow when search returns CVE below threshold."""
    search_response = {
        "items": [
            {
                "identifier": "CVE-2026-21441",
                "title": "urllib3 vulnerable to ...",
                "description": (
                    "Starting in version 1.22 and prior to version 2.6.3"
                ),
                "average_severity": "medium",
                "average_score": 5.5,
                "advisories": [],
            }
        ],
        "total": 1,
    }
    client = _FakeClient(
        response={},
        search_response=search_response,
    )

    permit_request(
        client=client,
        path="urllib3-2.6.2.tar.gz",
        threshold="critical",
        fail_open=False,
        base_url=BASE_URL,
    )


def test_blocks_with_enriched_log(caplog):
    """Verify enriched URLs appear in log output."""
    response = {
        "items": [
            {
                "purl": "pkg:pypi/requests@2.28.0",
                "details": [
                    {
                        "entry": {"cve": "CVE-2023-1234"},
                        "base_score": {"severity": "critical"},
                    }
                ],
            }
        ],
    }
    client = _FakeClient(response=response)

    with caplog.at_level(logging.INFO, logger="pulp_trustify"):
        with pytest.raises(PermissionError) as exc_info:
            permit_request(
                client=client,
                path="requests-2.28.0.tar.gz",
                threshold="critical",
                fail_open=False,
                base_url=BASE_URL,
            )

    error_msg = str(exc_info.value)
    assert "CVE-2023-1234" in error_msg
    assert "\n" not in error_msg

    log_text = caplog.text
    assert f"{BASE_URL}/vulnerabilities/CVE-2023-1234" in log_text


def test_passes_base_url_to_gate():
    """Verify base_url flows through to gate_purl."""
    response = {
        "items": [
            {
                "purl": "pkg:pypi/requests@2.28.0",
                "details": [],
            }
        ],
    }
    client = _FakeClient(response=response)

    permit_request(
        client=client,
        path="requests-2.32.0.tar.gz",
        threshold="critical",
        fail_open=False,
        base_url=BASE_URL,
    )
