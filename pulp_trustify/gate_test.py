from __future__ import annotations

import pytest

from pulp_trustify.client.client import TrustifyError
from pulp_trustify.gate import gate_purl


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

    with pytest.raises(PermissionError, match="CVE-2023-1234"):
        gate_purl(
            client=client,
            purl="pkg:pypi/requests@2.28.0",
            threshold="critical",
            fail_open=False,
        )


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
    )


def test_fail_open_on_api_error():
    """Allow PURL when Trustify fails and fail_open is True."""
    client = _FakeClient(error=TrustifyError("API unavailable"))

    gate_purl(
        client=client,
        purl="pkg:pypi/requests@2.28.0",
        threshold="critical",
        fail_open=True,
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

    with pytest.raises(PermissionError, match="CVE-2026-21441"):
        gate_purl(
            client=client,
            purl="pkg:pypi/urllib3@2.6.2",
            threshold="high",
            fail_open=False,
        )


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
    )
