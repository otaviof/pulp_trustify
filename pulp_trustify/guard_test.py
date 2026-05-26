from __future__ import annotations

import pytest

from pulp_trustify.client.client import TrustifyError
from pulp_trustify.guard import permit_request


class _FakeClient:
    """Mock TrustifyClient for unit tests."""

    def __init__(self, response=None, error=None):
        """Initialize the fake client.

        Args:
            response: dict to return from analyze(), or None.
            error: exception to raise from analyze(), or None.
        """
        self._response = response
        self._error = error

    def analyze(self, purls):
        """Simulate TrustifyClient.analyze() method.

        Args:
            purls: list of PURL strings to analyze.

        Returns:
            The response dict provided at initialization.

        Raises:
            The error provided at initialization, if any.
        """
        if self._error:
            raise self._error
        return self._response or {"items": []}


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

    with pytest.raises(PermissionError, match="CVE-2023-1234"):
        permit_request(
            client=client,
            path="requests-2.28.0.tar.gz",
            threshold="critical",
            fail_open=False,
        )


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
    )


def test_allows_non_package_path():
    """Allow request when path does not resolve to a PURL."""
    client = _FakeClient()

    permit_request(
        client=client,
        path="/simple/requests/",
        threshold="critical",
        fail_open=False,
    )


def test_fail_open_on_trustify_error():
    """Allow request when Trustify fails and fail_open is True."""
    client = _FakeClient(error=TrustifyError("API unavailable"))

    permit_request(
        client=client,
        path="requests-2.32.0.tar.gz",
        threshold="critical",
        fail_open=True,
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
    )


@pytest.mark.integration
def test_permit_allows_clean_package(trustify_client):
    """Allow request for a known-clean package via live Trustify API."""
    permit_request(
        client=trustify_client,
        path="requests-2.32.0.tar.gz",
        threshold="critical",
        fail_open=False,
    )


@pytest.mark.integration
def test_permit_blocks_vulnerable_package(trustify_client):
    """Block request for a known-vulnerable package via live Trustify API."""
    with pytest.raises(PermissionError):
        permit_request(
            client=trustify_client,
            path="requests-2.28.0.tar.gz",
            threshold="critical",
            fail_open=False,
        )
