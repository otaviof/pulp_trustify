from __future__ import annotations

import logging
from dataclasses import dataclass, field

from pulp_trustify.client.client import (
    TrustifyError,
    VulnerabilityChecker,
    build_trustify_url,
)
from pulp_trustify.gate import check_purl
from pulp_trustify.policy import filter_vulnerabilities

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class VulnerabilityDetail:
    cve_id: str
    severity: str
    trustify_url: str
    description: str = ""


@dataclass(frozen=True)
class ScanResult:
    content_pk: str
    purl: str
    cve_ids: list[str] = field(default_factory=list)
    details: list[VulnerabilityDetail] = field(default_factory=list)
    blocked: bool = False
    detection_mode: str = ""


def scan_content(
    client: VulnerabilityChecker,
    content_purls: list[tuple[str, str]],
    threshold: str,
    fail_open: bool,
    batch_size: int = 100,
    base_url: str = "",
) -> list[ScanResult]:
    """Scan content for vulnerabilities. Returns list of ScanResults."""
    logger.debug(
        "Scanning %d PURLs in batches of %d",
        len(content_purls),
        batch_size,
    )
    results: list[ScanResult] = []

    total_batches = (len(content_purls) + batch_size - 1) // batch_size

    for i in range(0, len(content_purls), batch_size):
        batch = content_purls[i : i + batch_size]
        batch_purls = [purl for _, purl in batch]
        batch_num = (i // batch_size) + 1

        logger.debug(
            "Processing batch %d/%d (%d PURLs)",
            batch_num,
            total_batches,
            len(batch),
        )

        vuln_map, analyzed_purls = analyze_batch(
            client,
            batch_purls,
            threshold,
            fail_open,
            base_url,
        )

        for pk, purl in batch:
            if purl in vuln_map:
                details = vuln_map[purl]
                results.append(
                    ScanResult(
                        content_pk=pk,
                        purl=purl,
                        cve_ids=[d.cve_id for d in details],
                        details=details,
                        blocked=bool(details),
                        detection_mode="analyze",
                    )
                )
            elif purl not in analyzed_purls:
                cve_ids = check_purl(client, purl, threshold, fail_open)
                details = [
                    VulnerabilityDetail(
                        cve_id=cve,
                        severity="unknown",
                        trustify_url=build_trustify_url(base_url, cve),
                    )
                    for cve in cve_ids
                ]
                results.append(
                    ScanResult(
                        content_pk=pk,
                        purl=purl,
                        cve_ids=cve_ids,
                        details=details,
                        blocked=bool(cve_ids),
                        detection_mode=("search_fallback" if cve_ids else ""),
                    )
                )
            else:
                results.append(
                    ScanResult(
                        content_pk=pk,
                        purl=purl,
                        cve_ids=[],
                        details=[],
                        blocked=False,
                        detection_mode="analyze",
                    )
                )

    return results


def analyze_batch(
    client: VulnerabilityChecker,
    purls: list[str],
    threshold: str,
    fail_open: bool,
    base_url: str,
) -> tuple[dict[str, list[VulnerabilityDetail]], set[str]]:
    """Analyze a batch of PURLs. Returns (vuln_map, analyzed_purls)."""
    try:
        response = client.analyze(purls)
    except TrustifyError as exc:
        if fail_open:
            logger.warning(
                "Trustify batch analysis failed (fail_open=True): %s",
                exc,
            )
            return {}, set()
        raise

    vuln_map: dict[str, list[VulnerabilityDetail]] = {}
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
                vuln_map[purl] = [
                    VulnerabilityDetail(
                        cve_id=entry.get("entry", {}).get("cve", "unknown"),
                        severity=(
                            entry.get("base_score", {}).get(
                                "severity",
                                "unknown",
                            )
                        ),
                        trustify_url=build_trustify_url(
                            base_url,
                            entry.get("entry", {}).get("cve", "unknown"),
                        ),
                    )
                    for entry in matching
                ]

    logger.debug(
        "Batch analysis: %d vulnerable, %d analyzed, %d fallback",
        len(vuln_map),
        len(analyzed_purls),
        len(purls) - len(analyzed_purls),
    )

    return vuln_map, analyzed_purls
