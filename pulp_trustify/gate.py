from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pulp_trustify.client.client import (
    TrustifyError,
    VulnerabilityChecker,
    build_trustify_url,
)
from pulp_trustify.labels import build_reason_inline
from pulp_trustify.policy import filter_vulnerabilities
from pulp_trustify.version import (
    extract_version_ranges,
    is_version_affected,
    purl_full_name,
    purl_version,
)

if TYPE_CHECKING:
    from pulp_trustify.scanner import VulnerabilityDetail

logger = logging.getLogger(__name__)

MSG_API_UNAVAILABLE = "Trustify API unavailable"
MSG_BLOCKED_CVE = "Blocked due to CVE"


@dataclass(frozen=True)
class GateResult:
    cve_ids: list[str] = field(default_factory=list)
    all_findings: list[dict] = field(default_factory=list)
    details: list[VulnerabilityDetail] = field(default_factory=list)
    detection_mode: str = ""


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


def check_purls(
    client: VulnerabilityChecker,
    purls: list[str],
    threshold: str,
    fail_open: bool,
) -> dict[str, list[str]]:
    """Check multiple PURLs against Trustify. Returns dict mapping
    vulnerable PURL -> CVE IDs.

    Tries batch analyze first, falls back to per-PURL check_purl()
    for PURLs not returned by analyze (search-based detection).
    """
    logger.debug(
        "Checking %d PURLs against threshold='%s'",
        len(purls),
        threshold,
    )
    try:
        response = client.analyze(purls)
    except TrustifyError as exc:
        if fail_open:
            logger.warning(
                "Trustify batch analysis failed (fail_open=True): %s",
                exc,
            )
            return {}
        raise

    result: dict[str, list[str]] = {}
    analyzed_purls: set[str] = set()

    for item in response.get("items", []):
        purl = item.get("purl")
        if not purl:
            continue

        details = item.get("details", [])
        if details:
            analyzed_purls.add(purl)
            matching = filter_vulnerabilities(details, threshold)
            if matching:
                cve_ids = [
                    entry.get("entry", {}).get("cve", "unknown")
                    for entry in matching
                ]
                result[purl] = cve_ids
                logger.info(
                    "PURL '%s' has %d CVEs at or above '%s': %s",
                    purl,
                    len(cve_ids),
                    threshold,
                    ", ".join(cve_ids),
                )

    logger.debug(
        "Batch analyze: %d analyzed, %d vulnerable, %d fallback",
        len(analyzed_purls),
        len(result),
        len(purls) - len(analyzed_purls),
    )

    for purl in purls:
        if purl not in analyzed_purls:
            cve_ids = check_purl(client, purl, threshold, fail_open)
            if cve_ids:
                result[purl] = cve_ids

    return result


def gate_purl(
    client: VulnerabilityChecker,
    purl: str,
    threshold: str,
    fail_open: bool,
    base_url: str = "",
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
        reason = build_reason_inline(cve_ids, base_url) if base_url else None
        msg = reason or f"{MSG_BLOCKED_CVE}: {', '.join(cve_ids)}"
        if base_url:
            urls = "\n  ".join(
                build_trustify_url(base_url, cve) for cve in cve_ids
            )
            logger.info(
                "Blocking '%s': %s\nDetails:\n  %s",
                purl,
                ", ".join(cve_ids),
                urls,
            )
        else:
            logger.info(
                "Blocking '%s': %s",
                purl,
                ", ".join(cve_ids),
            )
        raise PermissionError(msg)
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
    pkg_name = purl_full_name(purl)
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


def check_purl_with_mode(
    client: VulnerabilityChecker,
    purl: str,
    threshold: str,
    fail_open: bool,
    base_url: str = "",
) -> GateResult:
    """Check a PURL against Trustify. Returns GateResult with all
    findings and metadata.

    Tries analyze first, falls back to search-based detection if
    analyze returns empty results. Tracks detection mode and builds
    VulnerabilityDetail objects for above-threshold findings.
    """
    from pulp_trustify.scanner import VulnerabilityDetail

    logger.debug(
        "Checking PURL '%s' against threshold='%s'",
        purl,
        threshold,
    )
    try:
        response = client.analyze([purl])
    except TrustifyError as exc:
        if fail_open:
            logger.warning(
                "Trustify analysis failed (fail_open=True): %s",
                exc,
            )
            return GateResult()
        raise PermissionError(MSG_API_UNAVAILABLE) from exc

    all_details: list[dict] = []
    for item in response.get("items", []):
        all_details.extend(item.get("details", []))

    logger.debug(
        "Analyze returned %d items for '%s'",
        len(all_details),
        purl,
    )

    if all_details:
        matching = filter_vulnerabilities(all_details, threshold)
        if matching:
            cve_ids = [
                entry.get("entry", {}).get("cve", "unknown") for entry in matching
            ]
            details = [
                VulnerabilityDetail(
                    cve_id=entry.get("entry", {}).get("cve", "unknown"),
                    severity=(
                        entry.get("base_score", {}).get("severity", "unknown")
                    ),
                    trustify_url=build_trustify_url(
                        base_url,
                        entry.get("entry", {}).get("cve", "unknown"),
                    ),
                )
                for entry in matching
            ]
            logger.info(
                "PURL '%s' has %d CVEs at or above '%s': %s",
                purl,
                len(cve_ids),
                threshold,
                ", ".join(cve_ids),
            )
            return GateResult(
                cve_ids=cve_ids,
                all_findings=all_details,
                details=details,
                detection_mode="analyze",
            )
        logger.debug("PURL '%s' clean via analyze", purl)
        return GateResult(
            all_findings=all_details,
            detection_mode="analyze",
        )

    logger.debug("Analyze empty for '%s', falling back to search", purl)
    try:
        matching = fallback_search(client, purl, threshold)
    except TrustifyError as exc:
        if fail_open:
            logger.warning(
                "Trustify search fallback failed (fail_open=True): %s",
                exc,
            )
            return GateResult()
        raise PermissionError(MSG_API_UNAVAILABLE) from exc

    if matching:
        cve_ids = [
            entry.get("entry", {}).get("cve", "unknown") for entry in matching
        ]
        details = [
            VulnerabilityDetail(
                cve_id=entry.get("entry", {}).get("cve", "unknown"),
                severity=(entry.get("base_score", {}).get("severity", "unknown")),
                trustify_url=build_trustify_url(
                    base_url,
                    entry.get("entry", {}).get("cve", "unknown"),
                ),
            )
            for entry in matching
        ]
        logger.info(
            "PURL '%s' blocked via fallback: %s",
            purl,
            ", ".join(cve_ids),
        )
        return GateResult(
            cve_ids=cve_ids,
            all_findings=matching,
            details=details,
            detection_mode="search_fallback",
        )
    return GateResult()
