from __future__ import annotations

import pytest

from pulp_trustify.policy import (
    SEVERITY_ORDER,
    exceeds_threshold,
    filter_vulnerabilities,
)


@pytest.mark.parametrize(
    "severity,threshold,expected",
    [
        ("critical", "critical", True),
        ("high", "critical", False),
        ("high", "high", True),
        ("medium", "high", False),
        ("medium", "low", True),
        ("low", "low", True),
        ("critical", "low", True),
        (None, "critical", False),
        (None, "low", False),
        ("unknown", "low", False),
        ("low", "unknown", False),
    ],
)
def test_exceeds_threshold(severity: str | None, threshold: str, expected: bool):
    """Test severity threshold comparison logic."""
    assert exceeds_threshold(severity, threshold) == expected


def test_severity_order_contains_all_levels():
    """Verify SEVERITY_ORDER defines all expected severity levels."""
    expected_levels = {"low", "medium", "high", "critical"}
    assert set(SEVERITY_ORDER.keys()) == expected_levels


def test_severity_order_is_ascending():
    """Verify severity levels are ordered from low to critical."""
    assert SEVERITY_ORDER["low"] < SEVERITY_ORDER["medium"]
    assert SEVERITY_ORDER["medium"] < SEVERITY_ORDER["high"]
    assert SEVERITY_ORDER["high"] < SEVERITY_ORDER["critical"]


def test_filter_vulnerabilities_returns_matching_entries():
    """Verify filter returns only entries meeting threshold."""
    details = [
        {"base_score": {"severity": "critical"}, "id": "CVE-1"},
        {"base_score": {"severity": "high"}, "id": "CVE-2"},
        {"base_score": {"severity": "medium"}, "id": "CVE-3"},
        {"base_score": {"severity": "low"}, "id": "CVE-4"},
    ]

    result = filter_vulnerabilities(details, "high")

    assert len(result) == 2
    assert result[0]["id"] == "CVE-1"
    assert result[1]["id"] == "CVE-2"


def test_filter_vulnerabilities_with_missing_base_score():
    """Verify entries without base_score are excluded."""
    details = [
        {"base_score": {"severity": "high"}, "id": "CVE-1"},
        {"id": "CVE-2"},
        {"base_score": {}, "id": "CVE-3"},
    ]

    result = filter_vulnerabilities(details, "high")

    assert len(result) == 1
    assert result[0]["id"] == "CVE-1"


def test_filter_vulnerabilities_empty_list():
    """Verify empty list returns empty list."""
    assert filter_vulnerabilities([], "critical") == []


def test_filter_vulnerabilities_all_below_threshold():
    """Verify no matches when all entries are below threshold."""
    details = [
        {"base_score": {"severity": "low"}, "id": "CVE-1"},
        {"base_score": {"severity": "medium"}, "id": "CVE-2"},
    ]

    result = filter_vulnerabilities(details, "critical")

    assert len(result) == 0


def test_filter_vulnerabilities_all_above_threshold():
    """Verify all entries returned when all exceed threshold."""
    details = [
        {"base_score": {"severity": "critical"}, "id": "CVE-1"},
        {"base_score": {"severity": "high"}, "id": "CVE-2"},
    ]

    result = filter_vulnerabilities(details, "high")

    assert len(result) == 2
