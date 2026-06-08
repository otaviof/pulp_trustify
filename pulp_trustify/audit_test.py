from __future__ import annotations

from unittest.mock import patch

import pytest

from pulp_trustify.audit import (
    audit_packages,
    build_npm_purls,
    is_scoped_purl,
    purl_to_npm_name,
    severity_to_npm,
    vulnerability_to_advisory,
)
from pulp_trustify.client.client import TrustifyError
from pulp_trustify.scanner import VulnerabilityDetail

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
        return self._search_response or {
            "items": [],
            "total": 0,
        }


def test_build_npm_purls_unscoped():
    """Build PURLs for unscoped packages."""
    result = build_npm_purls({"lodash": ["4.17.20", "4.17.21"]})
    assert result == [
        "pkg:npm/lodash@4.17.20",
        "pkg:npm/lodash@4.17.21",
    ]


def test_build_npm_purls_scoped():
    """Build PURLs for scoped packages with %40 encoding."""
    result = build_npm_purls({"@angular/core": ["17.0.0"]})
    assert result == ["pkg:npm/%40angular/core@17.0.0"]


def test_build_npm_purls_empty():
    """Return empty list for empty input."""
    assert build_npm_purls({}) == []


def test_build_npm_purls_mixed():
    """Build PURLs for mixed scoped and unscoped packages."""
    result = build_npm_purls(
        {
            "lodash": ["4.17.21"],
            "@angular/core": ["17.0.0"],
        }
    )
    assert "pkg:npm/lodash@4.17.21" in result
    assert "pkg:npm/%40angular/core@17.0.0" in result
    assert len(result) == 2


def test_purl_to_npm_name_unscoped():
    """Extract unscoped npm name from PURL."""
    assert purl_to_npm_name("pkg:npm/lodash@4.17.21") == "lodash"


def test_purl_to_npm_name_scoped():
    """Extract scoped npm name from PURL."""
    assert purl_to_npm_name("pkg:npm/%40angular/core@17.0.0") == "@angular/core"


def test_purl_to_npm_name_invalid():
    """Return empty string for invalid PURL."""
    assert purl_to_npm_name("not-a-purl") == ""


def test_is_scoped_purl_true():
    """Detect scoped PURL."""
    assert is_scoped_purl("pkg:npm/%40angular/core@17.0.0")


def test_is_scoped_purl_false():
    """Detect unscoped PURL."""
    assert not is_scoped_purl("pkg:npm/lodash@4.17.21")


def test_severity_to_npm_medium():
    """Map medium to moderate."""
    assert severity_to_npm("medium") == "moderate"


def test_severity_to_npm_passthrough():
    """Pass through non-medium severities."""
    assert severity_to_npm("critical") == "critical"
    assert severity_to_npm("high") == "high"
    assert severity_to_npm("low") == "low"


def test_vulnerability_to_advisory_critical():
    """Convert critical VulnerabilityDetail to npm advisory."""
    detail = VulnerabilityDetail(
        cve_id="CVE-2023-1234",
        severity="critical",
        trustify_url=(f"{BASE_URL}/vulnerabilities/CVE-2023-1234"),
    )
    result = vulnerability_to_advisory(detail, "pkg:npm/lodash@4.17.20", 1)
    assert result["id"] == 1
    assert result["title"] == "CVE-2023-1234"
    assert result["severity"] == "critical"
    assert result["vulnerable_versions"] == "=4.17.20"
    assert result["cwe"] == []
    assert result["cvss"] == {"score": 9.0}
    assert "CVE-2023-1234" in result["url"]


def test_vulnerability_to_advisory_high():
    """Convert high severity to CVSS 7.0."""
    detail = VulnerabilityDetail(
        cve_id="CVE-2023-5678",
        severity="high",
        trustify_url=(f"{BASE_URL}/vulnerabilities/CVE-2023-5678"),
    )
    result = vulnerability_to_advisory(detail, "pkg:npm/lodash@4.17.20", 2)
    assert result["severity"] == "high"
    assert result["cvss"] == {"score": 7.0}


def test_vulnerability_to_advisory_medium():
    """Convert medium severity to moderate with CVSS 5.0."""
    detail = VulnerabilityDetail(
        cve_id="CVE-2023-9999",
        severity="medium",
        trustify_url=(f"{BASE_URL}/vulnerabilities/CVE-2023-9999"),
    )
    result = vulnerability_to_advisory(detail, "pkg:npm/lodash@4.17.20", 3)
    assert result["severity"] == "moderate"
    assert result["cvss"] == {"score": 5.0}


def test_audit_packages_all_clean():
    """Return empty dict when all packages are clean."""
    response = {
        "items": [
            {
                "purl": "pkg:npm/lodash@4.17.21",
                "details": [],
            },
        ],
    }
    client = _FakeClient(analyze_response=response)
    result = audit_packages(
        client=client,
        packages={"lodash": ["4.17.21"]},
        threshold="critical",
        fail_open=False,
        base_url=BASE_URL,
    )
    assert result == {}


def test_audit_packages_vulnerable_via_analyze():
    """Return advisories when analyze finds CVEs."""
    response = {
        "items": [
            {
                "purl": "pkg:npm/lodash@4.17.20",
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
    result = audit_packages(
        client=client,
        packages={"lodash": ["4.17.20"]},
        threshold="critical",
        fail_open=False,
        base_url=BASE_URL,
    )
    assert "lodash" in result
    assert len(result["lodash"]) == 1
    adv = result["lodash"][0]
    assert adv["title"] == "CVE-2023-1234"
    assert adv["severity"] == "critical"
    assert adv["vulnerable_versions"] == "=4.17.20"


@patch("pulp_trustify.audit.fallback_search")
def test_audit_scoped_skips_fallback(mock_fallback):
    """Skip fallback_search for scoped packages."""
    client = _FakeClient(analyze_response={"items": []})
    result = audit_packages(
        client=client,
        packages={"@angular/core": ["17.0.0"]},
        threshold="critical",
        fail_open=False,
        base_url=BASE_URL,
    )
    assert result == {}
    mock_fallback.assert_not_called()


@patch("pulp_trustify.audit.fallback_search")
def test_audit_unscoped_uses_fallback(mock_fallback):
    """Call fallback_search for unscoped non-analyzed PURLs."""
    mock_fallback.return_value = [
        {
            "entry": {"cve": "CVE-2023-1234"},
            "base_score": {"severity": "high"},
        }
    ]
    client = _FakeClient(analyze_response={"items": []})
    result = audit_packages(
        client=client,
        packages={"lodash": ["4.17.20"]},
        threshold="high",
        fail_open=False,
        base_url=BASE_URL,
    )
    assert "lodash" in result
    assert len(result["lodash"]) == 1
    mock_fallback.assert_called_once()


def test_audit_packages_fail_open():
    """Return empty dict on TrustifyError with fail_open."""
    client = _FakeClient(analyze_error=TrustifyError("API unavailable"))
    result = audit_packages(
        client=client,
        packages={"lodash": ["4.17.20"]},
        threshold="critical",
        fail_open=True,
        base_url=BASE_URL,
    )
    assert result == {}


def test_audit_packages_fail_closed():
    """Raise TrustifyError when fail_open is False."""
    client = _FakeClient(analyze_error=TrustifyError("API unavailable"))
    with pytest.raises(TrustifyError, match="API unavailable"):
        audit_packages(
            client=client,
            packages={"lodash": ["4.17.20"]},
            threshold="critical",
            fail_open=False,
            base_url=BASE_URL,
        )


def test_audit_packages_empty_input():
    """Return empty dict for empty input."""
    client = _FakeClient()
    result = audit_packages(
        client=client,
        packages={},
        threshold="critical",
        fail_open=False,
        base_url=BASE_URL,
    )
    assert result == {}


def test_audit_packages_multiple_cves_grouped():
    """Group multiple CVEs under one package name."""
    response = {
        "items": [
            {
                "purl": "pkg:npm/lodash@4.17.20",
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
    result = audit_packages(
        client=client,
        packages={"lodash": ["4.17.20"]},
        threshold="high",
        fail_open=False,
        base_url=BASE_URL,
    )
    assert "lodash" in result
    assert len(result["lodash"]) == 2
    titles = [a["title"] for a in result["lodash"]]
    assert "CVE-2023-1234" in titles
    assert "CVE-2023-5678" in titles


def test_audit_packages_sequential_ids():
    """Advisory IDs are sequential across packages."""
    response = {
        "items": [
            {
                "purl": "pkg:npm/lodash@4.17.20",
                "details": [
                    {
                        "entry": {"cve": "CVE-2023-1234"},
                        "base_score": {"severity": "critical"},
                    },
                ],
            },
            {
                "purl": "pkg:npm/express@4.17.1",
                "details": [
                    {
                        "entry": {"cve": "CVE-2023-5678"},
                        "base_score": {"severity": "high"},
                    },
                ],
            },
        ],
    }
    client = _FakeClient(analyze_response=response)
    result = audit_packages(
        client=client,
        packages={
            "lodash": ["4.17.20"],
            "express": ["4.17.1"],
        },
        threshold="high",
        fail_open=False,
        base_url=BASE_URL,
    )
    all_ids = []
    for advisories in result.values():
        for adv in advisories:
            all_ids.append(adv["id"])
    assert len(all_ids) == len(set(all_ids))
