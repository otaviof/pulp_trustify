from __future__ import annotations

from unittest.mock import patch

import pytest

from pulp_trustify.client.client import TrustifyError, build_trustify_url
from pulp_trustify.scanner import (
    VulnerabilityDetail,
    scan_content,
)

BASE_URL = "https://trustify.example.com"


class _FakeClient:
    def __init__(
        self,
        analyze_response=None,
        analyze_error=None,
        search_response=None,
    ):
        self._analyze_response = analyze_response
        self._analyze_error = analyze_error
        self._search_response = search_response

    def analyze(self, purls):
        if self._analyze_error:
            raise self._analyze_error
        return self._analyze_response or {"items": []}

    def search_vulnerabilities(self, query, offset=0, limit=10):
        return self._search_response or {"items": [], "total": 0}


def test_all_clean_via_analyze():
    """Return all clean when analyze finds no vulnerabilities."""
    response = {
        "items": [
            {
                "purl": "pkg:pypi/requests@2.32.0",
                "details": [],
            },
            {
                "purl": "pkg:pypi/urllib3@2.0.0",
                "details": [],
            },
        ],
    }
    client = _FakeClient(analyze_response=response)
    content_purls = [
        ("1", "pkg:pypi/requests@2.32.0"),
        ("2", "pkg:pypi/urllib3@2.0.0"),
    ]

    results = scan_content(
        client=client,
        content_purls=content_purls,
        threshold="critical",
        fail_open=False,
        batch_size=100,
        base_url=BASE_URL,
    )

    assert len(results) == 2
    assert all(not r.blocked for r in results)
    assert results[0].content_pk == "1"
    assert results[1].content_pk == "2"
    assert results[0].details == []
    assert results[1].details == []


def test_all_vulnerable_via_analyze():
    """Return all blocked when analyze finds critical CVEs."""
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
                "purl": "pkg:pypi/urllib3@1.26.5",
                "details": [
                    {
                        "entry": {"cve": "CVE-2023-5678"},
                        "base_score": {"severity": "critical"},
                    }
                ],
            },
        ],
    }
    client = _FakeClient(analyze_response=response)
    content_purls = [
        ("1", "pkg:pypi/requests@2.28.0"),
        ("2", "pkg:pypi/urllib3@1.26.5"),
    ]

    results = scan_content(
        client=client,
        content_purls=content_purls,
        threshold="critical",
        fail_open=False,
        batch_size=100,
        base_url=BASE_URL,
    )

    assert len(results) == 2
    assert all(r.blocked for r in results)
    assert "CVE-2023-1234" in results[0].cve_ids
    assert "CVE-2023-5678" in results[1].cve_ids
    assert results[0].detection_mode == "analyze"
    assert results[1].detection_mode == "analyze"
    assert len(results[0].details) == 1
    assert results[0].details[0].cve_id == "CVE-2023-1234"
    assert results[0].details[0].severity == "critical"
    assert results[0].details[0].trustify_url == (
        f"{BASE_URL}/vulnerabilities/CVE-2023-1234"
    )
    assert len(results[1].details) == 1
    assert results[1].details[0].cve_id == "CVE-2023-5678"
    assert results[1].details[0].severity == "critical"
    assert results[1].details[0].trustify_url == (
        f"{BASE_URL}/vulnerabilities/CVE-2023-5678"
    )


@patch("pulp_trustify.scanner.check_purl")
def test_mixed_results(mock_check):
    """Return correct blocked status per PURL."""
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
        ],
    }
    client = _FakeClient(analyze_response=response)
    content_purls = [
        ("1", "pkg:pypi/requests@2.28.0"),
        ("2", "pkg:pypi/safe-pkg@1.0.0"),
    ]

    mock_check.return_value = []

    results = scan_content(
        client=client,
        content_purls=content_purls,
        threshold="critical",
        fail_open=False,
        batch_size=100,
        base_url=BASE_URL,
    )

    assert len(results) == 2
    assert results[0].blocked is True
    assert results[1].blocked is False


def test_below_threshold():
    """Return clean when CVEs are below threshold."""
    response = {
        "items": [
            {
                "purl": "pkg:pypi/requests@2.28.0",
                "details": [
                    {
                        "entry": {"cve": "CVE-2023-1234"},
                        "base_score": {"severity": "medium"},
                    }
                ],
            },
        ],
    }
    client = _FakeClient(analyze_response=response)
    content_purls = [("1", "pkg:pypi/requests@2.28.0")]

    results = scan_content(
        client=client,
        content_purls=content_purls,
        threshold="critical",
        fail_open=False,
        batch_size=100,
        base_url=BASE_URL,
    )

    assert len(results) == 1
    assert results[0].blocked is False


@patch("pulp_trustify.scanner.check_purl")
def test_fallback_triggered(mock_check):
    """Use check_purl fallback when analyze returns no items."""
    client = _FakeClient(analyze_response={"items": []})
    content_purls = [("1", "pkg:pypi/requests@2.28.0")]

    mock_check.return_value = ["CVE-2023-1234"]

    results = scan_content(
        client=client,
        content_purls=content_purls,
        threshold="critical",
        fail_open=False,
        batch_size=100,
        base_url=BASE_URL,
    )

    assert len(results) == 1
    assert results[0].blocked is True
    assert results[0].cve_ids == ["CVE-2023-1234"]
    assert results[0].detection_mode == "search_fallback"
    assert len(results[0].details) == 1
    assert results[0].details[0].cve_id == "CVE-2023-1234"
    assert results[0].details[0].severity == "unknown"
    assert results[0].details[0].trustify_url == (
        f"{BASE_URL}/vulnerabilities/CVE-2023-1234"
    )
    mock_check.assert_called_once()


@patch("pulp_trustify.scanner.check_purl")
def test_fallback_clean(mock_check):
    """Return clean via fallback when no CVEs found."""
    client = _FakeClient(analyze_response={"items": []})
    content_purls = [("1", "pkg:pypi/requests@2.32.0")]

    mock_check.return_value = []

    results = scan_content(
        client=client,
        content_purls=content_purls,
        threshold="critical",
        fail_open=False,
        batch_size=100,
        base_url=BASE_URL,
    )

    assert len(results) == 1
    assert results[0].blocked is False
    assert results[0].cve_ids == []
    assert results[0].detection_mode == ""


def test_fail_open_on_batch_error():
    """Return all clean when TrustifyError occurs and fail_open=True."""
    client = _FakeClient(analyze_error=TrustifyError("API unavailable"))
    content_purls = [
        ("1", "pkg:pypi/requests@2.28.0"),
        ("2", "pkg:pypi/urllib3@1.26.5"),
    ]

    results = scan_content(
        client=client,
        content_purls=content_purls,
        threshold="critical",
        fail_open=True,
        batch_size=100,
        base_url=BASE_URL,
    )

    assert len(results) == 2
    assert all(not r.blocked for r in results)


def test_fail_closed_on_batch_error():
    """Raise TrustifyError when fail_open=False."""
    client = _FakeClient(analyze_error=TrustifyError("API unavailable"))
    content_purls = [("1", "pkg:pypi/requests@2.28.0")]

    with pytest.raises(TrustifyError, match="API unavailable"):
        scan_content(
            client=client,
            content_purls=content_purls,
            threshold="critical",
            fail_open=False,
            batch_size=100,
            base_url=BASE_URL,
        )


def test_empty_input():
    """Return empty list when no content provided."""
    client = _FakeClient()

    results = scan_content(
        client=client,
        content_purls=[],
        threshold="critical",
        fail_open=False,
        batch_size=100,
        base_url=BASE_URL,
    )

    assert results == []


def test_batch_boundary():
    """Handle single batch correctly."""
    response = {
        "items": [
            {"purl": f"pkg:pypi/pkg{i}@1.0.0", "details": []} for i in range(100)
        ],
    }
    client = _FakeClient(analyze_response=response)
    content_purls = [(str(i), f"pkg:pypi/pkg{i}@1.0.0") for i in range(100)]

    results = scan_content(
        client=client,
        content_purls=content_purls,
        threshold="critical",
        fail_open=False,
        batch_size=100,
        base_url=BASE_URL,
    )

    assert len(results) == 100
    assert all(not r.blocked for r in results)


@patch("pulp_trustify.scanner.check_purl")
def test_multiple_batches(mock_check):
    """Collect results across multiple batches."""
    client = _FakeClient()

    calls = []

    def mock_analyze(purls):
        calls.append(len(purls))
        return {"items": []}

    client.analyze = mock_analyze
    mock_check.return_value = []

    content_purls = [(str(i), f"pkg:pypi/pkg{i}@1.0.0") for i in range(5)]

    results = scan_content(
        client=client,
        content_purls=content_purls,
        threshold="critical",
        fail_open=False,
        batch_size=2,
        base_url=BASE_URL,
    )

    assert len(results) == 5
    assert calls == [2, 2, 1]


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


def test_vulnerability_detail_fields():
    """Verify VulnerabilityDetail dataclass fields."""
    detail = VulnerabilityDetail(
        cve_id="CVE-2023-1234",
        severity="critical",
        trustify_url="https://trustify.example.com/vulnerabilities/CVE-2023-1234",
        description="Test vulnerability",
    )
    assert detail.cve_id == "CVE-2023-1234"
    assert detail.severity == "critical"
    assert (
        detail.trustify_url
        == "https://trustify.example.com/vulnerabilities/CVE-2023-1234"
    )
    assert detail.description == "Test vulnerability"


def test_vulnerability_detail_default_description():
    """Verify VulnerabilityDetail has empty description by default."""
    detail = VulnerabilityDetail(
        cve_id="CVE-2023-1234",
        severity="critical",
        trustify_url="https://trustify.example.com/vulnerabilities/CVE-2023-1234",
    )
    assert detail.description == ""


def test_details_populated_via_analyze():
    """Verify details list has VulnerabilityDetail objects from analyze."""
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
        ],
    }
    client = _FakeClient(analyze_response=response)
    content_purls = [("1", "pkg:pypi/requests@2.28.0")]

    results = scan_content(
        client=client,
        content_purls=content_purls,
        threshold="high",
        fail_open=False,
        batch_size=100,
        base_url=BASE_URL,
    )

    assert len(results) == 1
    assert results[0].blocked is True
    assert len(results[0].details) == 2
    assert results[0].details[0].cve_id == "CVE-2023-1234"
    assert results[0].details[0].severity == "critical"
    assert results[0].details[0].trustify_url == (
        f"{BASE_URL}/vulnerabilities/CVE-2023-1234"
    )
    assert results[0].details[1].cve_id == "CVE-2023-5678"
    assert results[0].details[1].severity == "high"
    assert results[0].details[1].trustify_url == (
        f"{BASE_URL}/vulnerabilities/CVE-2023-5678"
    )


@patch("pulp_trustify.scanner.check_purl")
def test_details_populated_via_fallback(mock_check):
    """Verify details for fallback path with severity=unknown."""
    client = _FakeClient(analyze_response={"items": []})
    content_purls = [("1", "pkg:pypi/requests@2.28.0")]

    mock_check.return_value = ["CVE-2023-1234", "CVE-2023-5678"]

    results = scan_content(
        client=client,
        content_purls=content_purls,
        threshold="critical",
        fail_open=False,
        batch_size=100,
        base_url=BASE_URL,
    )

    assert len(results) == 1
    assert results[0].blocked is True
    assert len(results[0].details) == 2
    assert results[0].details[0].cve_id == "CVE-2023-1234"
    assert results[0].details[0].severity == "unknown"
    assert results[0].details[0].trustify_url == (
        f"{BASE_URL}/vulnerabilities/CVE-2023-1234"
    )
    assert results[0].details[1].cve_id == "CVE-2023-5678"
    assert results[0].details[1].severity == "unknown"
    assert results[0].details[1].trustify_url == (
        f"{BASE_URL}/vulnerabilities/CVE-2023-5678"
    )


def test_details_empty_when_clean():
    """Verify details=[] for clean results."""
    response = {
        "items": [
            {
                "purl": "pkg:pypi/requests@2.32.0",
                "details": [],
            },
        ],
    }
    client = _FakeClient(analyze_response=response)
    content_purls = [("1", "pkg:pypi/requests@2.32.0")]

    results = scan_content(
        client=client,
        content_purls=content_purls,
        threshold="critical",
        fail_open=False,
        batch_size=100,
        base_url=BASE_URL,
    )

    assert len(results) == 1
    assert results[0].blocked is False
    assert results[0].details == []
