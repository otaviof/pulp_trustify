from __future__ import annotations

import logging

from pulp_trustify.client.client import (
    TrustifyError,
    VulnerabilityChecker,
)
from pulp_trustify.policy import filter_vulnerabilities
from pulp_trustify.version import (
    extract_version_ranges,
    is_version_affected,
    purl_package_name,
    purl_version,
)

logger = logging.getLogger(__name__)

MSG_API_UNAVAILABLE = "Trustify API unavailable"
MSG_BLOCKED_CVE = "Blocked due to CVE"


def check_purl(
    client: VulnerabilityChecker,
    purl: str,
    threshold: str,
    fail_open: bool,
) -> list[str]:
    """Check a PURL against Trustify. Returns list of CVE IDs above
    threshold.

    Tries analyze first, falls back to search-based
    detection if analyze returns empty results.
    """
    logger.debug("Checking PURL '%s' against threshold='%s'", purl, threshold)
    try:
        response = client.analyze([purl])
    except TrustifyError as exc:
        if fail_open:
            logger.warning(
                "Trustify analysis failed (fail_open=True): %s",
                exc,
            )
            return []
        raise PermissionError(MSG_API_UNAVAILABLE) from exc

    all_details: list[dict] = []
    for item in response.get("items", []):
        all_details.extend(item.get("details", []))

    logger.debug("Analyze returned %d items for '%s'", len(all_details), purl)

    if all_details:
        matching = filter_vulnerabilities(all_details, threshold)
        if matching:
            cve_ids = [
                entry.get("entry", {}).get("cve", "unknown") for entry in matching
            ]
            logger.info(
                "PURL '%s' has %d CVEs at or above '%s': %s",
                purl,
                len(cve_ids),
                threshold,
                ", ".join(cve_ids),
            )
            return cve_ids
        logger.debug("PURL '%s' clean via analyze", purl)
        return []

    logger.debug("Analyze empty for '%s', falling back to search", purl)
    try:
        matching = fallback_search(client, purl, threshold)
    except TrustifyError as exc:
        if fail_open:
            logger.warning(
                "Trustify search fallback failed (fail_open=True): %s",
                exc,
            )
            return []
        raise PermissionError(MSG_API_UNAVAILABLE) from exc

    if matching:
        cve_ids = [
            entry.get("entry", {}).get("cve", "unknown") for entry in matching
        ]
        logger.info(
            "PURL '%s' blocked via fallback: %s",
            purl,
            ", ".join(cve_ids),
        )
        return cve_ids
    return []


def gate_purl(
    client: VulnerabilityChecker,
    purl: str,
    threshold: str,
    fail_open: bool,
) -> None:
    """Check a PURL against Trustify; raise on vulnerability.

    Tries analyze first, falls back to search-based
    detection if analyze returns empty results.

    Raises:
        PermissionError: if the PURL has vulnerabilities
            at or above threshold.
    """
    cve_ids = check_purl(client, purl, threshold, fail_open)
    if cve_ids:
        logger.info("Blocking '%s': %s", purl, ", ".join(cve_ids))
        raise PermissionError(f"{MSG_BLOCKED_CVE}: {', '.join(cve_ids)}")
    logger.debug("Allowing '%s' (no CVEs above '%s')", purl, threshold)


def fallback_search(
    client: VulnerabilityChecker,
    purl: str,
    threshold: str,
) -> list[dict]:
    """Search Trustify for vulnerabilities affecting a PURL.

    Extracts package name, searches Trustify, filters by
    version range match, then by severity threshold.
    """
    pkg_name = purl_package_name(purl)
    pkg_version = purl_version(purl)
    if pkg_name is None or pkg_version is None:
        return []

    response = client.search_vulnerabilities(pkg_name)
    results: list[dict] = []

    for item in response.get("items", []):
        description = item.get("description", "")
        ranges = extract_version_ranges(description)
        if not ranges:
            continue
        if not is_version_affected(pkg_version, ranges):
            continue

        severity = item.get("average_severity")
        results.append(
            {
                "entry": {
                    "cve": item.get("identifier", "unknown"),
                },
                "base_score": {"severity": severity},
            }
        )

    return filter_vulnerabilities(results, threshold)
