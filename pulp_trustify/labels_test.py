from __future__ import annotations

from unittest.mock import Mock

import pytest

from pulp_trustify.labels import (
    REASON_PREFIX,
    build_reason,
    labels_to_reasons,
    lookup_vulnerable,
)

TRUSTIFY_URL = "https://trustify.example.com"
CVE_1 = "CVE-2026-21441"
CVE_2 = "CVE-2026-44432"
CVE_3 = "CVE-2026-99999"

URL_1 = f"{TRUSTIFY_URL}/vulnerabilities/{CVE_1}"
URL_2 = f"{TRUSTIFY_URL}/vulnerabilities/{CVE_2}"
URL_3 = f"{TRUSTIFY_URL}/vulnerabilities/{CVE_3}"


@pytest.mark.parametrize(
    "cve_ids,expected",
    [
        ([CVE_1, CVE_2], f"{REASON_PREFIX}:\n- {URL_1}\n- {URL_2}"),
        ([CVE_1], f"{REASON_PREFIX}: {URL_1}"),
        ([], None),
    ],
)
def test_build_reason(cve_ids: list[str], expected: str | None):
    result = build_reason(cve_ids, TRUSTIFY_URL)
    assert result == expected


def test_build_reason_with_trailing_slash():
    result = build_reason([CVE_1], f"{TRUSTIFY_URL}/")
    assert result == f"{REASON_PREFIX}: {URL_1}"


def test_build_reason_max_cves_limits_output():
    result = build_reason(
        [CVE_1, CVE_2, CVE_3],
        TRUSTIFY_URL,
        max_cves=2,
    )
    assert result == (f"{REASON_PREFIX} (2 of 3 CVEs):\n- {URL_1}\n- {URL_2}")


def test_build_reason_max_cves_single():
    result = build_reason([CVE_1, CVE_2], TRUSTIFY_URL, max_cves=1)
    assert result == f"{REASON_PREFIX} (1 of 2 CVEs): {URL_1}"


def test_labels_to_reasons_single_vulnerable():
    """Single row with vulnerable label returns reason."""
    rows = [
        ("file1.whl", {"trustify.vulnerable": "true", "trustify.cves": CVE_1}),
    ]
    result = labels_to_reasons(rows, TRUSTIFY_URL, max_cves=3)
    expected = {
        "file1.whl": f"{REASON_PREFIX}: {URL_1}",
    }
    assert result == expected


def test_labels_to_reasons_multiple_vulnerable():
    """Multiple vulnerable rows returned."""
    rows = [
        ("file1.whl", {"trustify.vulnerable": "true", "trustify.cves": CVE_1}),
        (
            "file2.whl",
            {"trustify.vulnerable": "true", "trustify.cves": f"{CVE_2} {CVE_3}"},
        ),
    ]
    result = labels_to_reasons(rows, TRUSTIFY_URL, max_cves=3)
    assert "file1.whl" in result
    assert "file2.whl" in result
    assert CVE_1 in result["file1.whl"]
    assert CVE_2 in result["file2.whl"]


def test_labels_to_reasons_not_vulnerable_skipped():
    """Rows with vulnerable != 'true' are skipped."""
    rows = [
        ("file1.whl", {"trustify.vulnerable": "false", "trustify.cves": CVE_1}),
        ("file2.whl", {"trustify.cves": CVE_2}),
    ]
    result = labels_to_reasons(rows, TRUSTIFY_URL, max_cves=3)
    assert result == {}


def test_labels_to_reasons_empty_labels_skipped():
    """Rows with empty labels dict are skipped."""
    rows = [
        ("file1.whl", {}),
    ]
    result = labels_to_reasons(rows, TRUSTIFY_URL, max_cves=3)
    assert result == {}


def test_labels_to_reasons_none_labels_skipped():
    """Rows with None labels are skipped."""
    rows = [
        ("file1.whl", None),
    ]
    result = labels_to_reasons(rows, TRUSTIFY_URL, max_cves=3)
    assert result == {}


def test_labels_to_reasons_mixed_vulnerable_and_clean():
    """Returns only vulnerable subset from mixed rows."""
    rows = [
        ("vuln.whl", {"trustify.vulnerable": "true", "trustify.cves": CVE_1}),
        ("clean.whl", {"trustify.vulnerable": "false"}),
        ("unknown.whl", {}),
    ]
    result = labels_to_reasons(rows, TRUSTIFY_URL, max_cves=3)
    assert "vuln.whl" in result
    assert "clean.whl" not in result
    assert "unknown.whl" not in result


def test_lookup_vulnerable_no_trustify_url_uses_fallback():
    """When trustify_url is empty, calls fallback_fn directly."""
    live_fn = Mock()
    fallback_fn = Mock(return_value={"id1": "reason1"})

    result = lookup_vulnerable(
        ["id1", "id2"],
        live_fn,
        fallback_fn,
        trustify_url="",
    )

    assert result == {"id1": "reason1"}
    live_fn.assert_not_called()
    fallback_fn.assert_called_once_with(["id1", "id2"])


def test_lookup_vulnerable_live_success():
    """When trustify_url is set and live_fn succeeds, uses live result."""
    live_fn = Mock(return_value={"id1": "reason1"})
    fallback_fn = Mock()

    result = lookup_vulnerable(
        ["id1", "id2"],
        live_fn,
        fallback_fn,
        trustify_url=TRUSTIFY_URL,
    )

    assert result == {"id1": "reason1"}
    live_fn.assert_called_once_with(["id1", "id2"])
    fallback_fn.assert_not_called()


def test_lookup_vulnerable_live_fails_fallback():
    """When live_fn raises exception, falls back to fallback_fn."""
    live_fn = Mock(side_effect=ValueError("API error"))
    fallback_fn = Mock(return_value={"id1": "reason1"})

    result = lookup_vulnerable(
        ["id1", "id2"],
        live_fn,
        fallback_fn,
        trustify_url=TRUSTIFY_URL,
    )

    assert result == {"id1": "reason1"}
    live_fn.assert_called_once_with(["id1", "id2"])
    fallback_fn.assert_called_once_with(["id1", "id2"])
