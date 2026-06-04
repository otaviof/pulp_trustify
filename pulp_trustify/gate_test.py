from __future__ import annotations

import logging

import pytest

from pulp_trustify.client.client import TrustifyError, build_trustify_url
from pulp_trustify.gate import check_purls, gate_purl

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


def test_blocks_vulnerable_purl():
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
        gate_purl(
            client=client,
            purl="pkg:pypi/requests@2.28.0",
            threshold="critical",
            fail_open=False,
            base_url=BASE_URL,
        )

    error_msg = str(exc_info.value)
    assert "CVE-2023-1234" in error_msg
    assert "\n" not in error_msg


def test_allows_clean_purl():
    """Allow PURL when analyze returns empty details."""
    response = {
        "items": [
            {
                "purl": "pkg:pypi/requests@2.32.0",
                "details": [],
            }
        ],
    }
    client = _FakeClient(response=response)

    gate_purl(
        client=client,
        purl="pkg:pypi/requests@2.32.0",
        threshold="critical",
        fail_open=False,
        base_url=BASE_URL,
    )


def test_fail_open_on_api_error():
    """Allow PURL when Trustify fails and fail_open is True."""
    client = _FakeClient(error=TrustifyError("API unavailable"))

    gate_purl(
        client=client,
        purl="pkg:pypi/requests@2.28.0",
        threshold="critical",
        fail_open=True,
        base_url=BASE_URL,
    )


def test_fail_closed_on_api_error():
    """Raise PermissionError when Trustify fails and fail_open is False."""
    client = _FakeClient(error=TrustifyError("API unavailable"))

    with pytest.raises(PermissionError, match="Trustify API unavailable"):
        gate_purl(
            client=client,
            purl="pkg:pypi/requests@2.28.0",
            threshold="critical",
            fail_open=False,
            base_url=BASE_URL,
        )


def test_below_threshold_not_blocked():
    """Allow PURL when severity is below threshold."""
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

    gate_purl(
        client=client,
        purl="pkg:pypi/requests@2.28.0",
        threshold="critical",
        fail_open=False,
        base_url=BASE_URL,
    )


def test_fallback_blocks_vulnerable():
    """Block vulnerable PURL via search fallback."""
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
        response={"items": []},
        search_response=search_response,
    )

    with pytest.raises(PermissionError) as exc_info:
        gate_purl(
            client=client,
            purl="pkg:pypi/urllib3@2.6.2",
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
        response={"items": []},
        search_response=search_response,
    )

    gate_purl(
        client=client,
        purl="pkg:pypi/urllib3@2.6.3",
        threshold="high",
        fail_open=False,
        base_url=BASE_URL,
    )


def testbuild_trustify_url():
    """Build Trustify URL from base URL and CVE ID."""
    url = build_trustify_url("https://trustify.example.com", "CVE-2023-1234")
    assert url == "https://trustify.example.com/vulnerabilities/CVE-2023-1234"


def test_build_trustify_url_strips_trailing_slash():
    """Handle trailing slash on base URL."""
    url = build_trustify_url(
        "https://trustify.example.com/",
        "CVE-2023-1234",
    )
    assert url == "https://trustify.example.com/vulnerabilities/CVE-2023-1234"


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
                    },
                    {
                        "entry": {"cve": "CVE-2023-5678"},
                        "base_score": {"severity": "high"},
                    },
                ],
            }
        ],
    }
    client = _FakeClient(response=response)

    with caplog.at_level(logging.INFO, logger="pulp_trustify"):
        with pytest.raises(PermissionError) as exc_info:
            gate_purl(
                client=client,
                purl="pkg:pypi/requests@2.28.0",
                threshold="high",
                fail_open=False,
                base_url=BASE_URL,
            )

    error_msg = str(exc_info.value)
    assert "CVE-2023-1234" in error_msg
    assert "CVE-2023-5678" in error_msg
    assert "\n" not in error_msg

    log_text = caplog.text
    assert f"{BASE_URL}/vulnerabilities/CVE-2023-1234" in log_text
    assert f"{BASE_URL}/vulnerabilities/CVE-2023-5678" in log_text


def test_blocks_without_base_url():
    """Verify original format when base_url is empty."""
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
        gate_purl(
            client=client,
            purl="pkg:pypi/requests@2.28.0",
            threshold="critical",
            fail_open=False,
            base_url="",
        )

    error_msg = str(exc_info.value)
    assert "CVE-2023-1234" in error_msg
    assert "Details:" not in error_msg
    assert "vulnerabilities" not in error_msg


def test_check_purls_all_clean():
    """Return empty dict when analyze returns items with empty details."""
    response = {
        "items": [
            {"purl": "pkg:pypi/requests@2.32.0", "details": []},
            {"purl": "pkg:pypi/urllib3@2.6.3", "details": []},
        ],
    }
    client = _FakeClient(response=response)

    result = check_purls(
        client=client,
        purls=["pkg:pypi/requests@2.32.0", "pkg:pypi/urllib3@2.6.3"],
        threshold="critical",
        fail_open=False,
    )

    assert result == {}


def test_check_purls_all_vulnerable():
    """Return dict mapping vulnerable PURLs to CVE IDs."""
    response = {
        "items": [
            {
                "purl": "pkg:pypi/requests@2.28.0",
                "details": [
                    {
                        "entry": {"cve": "CVE-2023-1234"},
                        "base_score": {"severity": "critical"},
                    },
                    {
                        "entry": {"cve": "CVE-2023-5678"},
                        "base_score": {"severity": "high"},
                    },
                ],
            },
            {
                "purl": "pkg:pypi/urllib3@2.6.2",
                "details": [
                    {
                        "entry": {"cve": "CVE-2026-21441"},
                        "base_score": {"severity": "high"},
                    }
                ],
            },
        ],
    }
    client = _FakeClient(response=response)

    result = check_purls(
        client=client,
        purls=["pkg:pypi/requests@2.28.0", "pkg:pypi/urllib3@2.6.2"],
        threshold="high",
        fail_open=False,
    )

    assert result == {
        "pkg:pypi/requests@2.28.0": ["CVE-2023-1234", "CVE-2023-5678"],
        "pkg:pypi/urllib3@2.6.2": ["CVE-2026-21441"],
    }


def test_check_purls_mixed():
    """Return only vulnerable PURLs when some are clean."""
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
            },
            {
                "purl": "pkg:pypi/urllib3@2.6.3",
                "details": [
                    {
                        "entry": {"cve": "CVE-2023-9999"},
                        "base_score": {"severity": "low"},
                    }
                ],
            },
        ],
    }
    client = _FakeClient(response=response)

    result = check_purls(
        client=client,
        purls=[
            "pkg:pypi/requests@2.28.0",
            "pkg:pypi/urllib3@2.6.3",
        ],
        threshold="critical",
        fail_open=False,
    )

    assert result == {
        "pkg:pypi/requests@2.28.0": ["CVE-2023-1234"],
    }


def test_check_purls_fallback_triggered():
    """Fall back to check_purl when analyze returns empty."""
    search_response = {
        "items": [
            {
                "identifier": "CVE-2026-21441",
                "description": (
                    "Starting in version 1.22 and prior to version 2.6.3"
                ),
                "average_severity": "high",
            }
        ],
        "total": 1,
    }
    client = _FakeClient(
        response={"items": []},
        search_response=search_response,
    )

    result = check_purls(
        client=client,
        purls=["pkg:pypi/urllib3@2.6.2"],
        threshold="high",
        fail_open=False,
    )

    assert result == {"pkg:pypi/urllib3@2.6.2": ["CVE-2026-21441"]}


def test_check_purls_fail_open():
    """Return empty dict when analyze raises TrustifyError with fail_open."""
    client = _FakeClient(error=TrustifyError("API unavailable"))

    result = check_purls(
        client=client,
        purls=["pkg:pypi/requests@2.28.0"],
        threshold="critical",
        fail_open=True,
    )

    assert result == {}


def test_check_purls_fail_closed():
    """Re-raise TrustifyError when analyze fails with fail_open=False."""
    client = _FakeClient(error=TrustifyError("API unavailable"))

    with pytest.raises(TrustifyError, match="API unavailable"):
        check_purls(
            client=client,
            purls=["pkg:pypi/requests@2.28.0"],
            threshold="critical",
            fail_open=False,
        )


def test_check_purls_empty_input():
    """Return empty dict when no PURLs provided."""
    client = _FakeClient()

    result = check_purls(
        client=client,
        purls=[],
        threshold="critical",
        fail_open=False,
    )

    assert result == {}
