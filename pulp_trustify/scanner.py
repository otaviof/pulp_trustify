from __future__ import annotations

import logging
from dataclasses import dataclass, field

from pulp_trustify.client.client import (
    TrustifyError,
    VulnerabilityChecker,
)
from pulp_trustify.gate import check_purl
from pulp_trustify.policy import filter_vulnerabilities

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScanResult:
    content_pk: str
    purl: str
    cve_ids: list[str] = field(default_factory=list)
    blocked: bool = False


def scan_content(
    client: VulnerabilityChecker,
    content_purls: list[tuple[str, str]],
    threshold: str,
    fail_open: bool,
    batch_size: int = 100,
) -> list[ScanResult]:
    """Scan content for vulnerabilities. Returns list of ScanResults."""
    results: list[ScanResult] = []

    for i in range(0, len(content_purls), batch_size):
        batch = content_purls[i : i + batch_size]
        batch_purls = [purl for _, purl in batch]

        vuln_map, analyzed_purls = _analyze_batch(
            client,
            batch_purls,
            threshold,
            fail_open,
        )

        for pk, purl in batch:
            if purl in vuln_map:
                cve_ids = vuln_map[purl]
                results.append(
                    ScanResult(
                        content_pk=pk,
                        purl=purl,
                        cve_ids=cve_ids,
                        blocked=bool(cve_ids),
                    )
                )
            elif purl not in analyzed_purls:
                cve_ids = check_purl(client, purl, threshold, fail_open)
                results.append(
                    ScanResult(
                        content_pk=pk,
                        purl=purl,
                        cve_ids=cve_ids,
                        blocked=bool(cve_ids),
                    )
                )
            else:
                results.append(
                    ScanResult(
                        content_pk=pk,
                        purl=purl,
                        cve_ids=[],
                        blocked=False,
                    )
                )

    return results


def _analyze_batch(
    client: VulnerabilityChecker,
    purls: list[str],
    threshold: str,
    fail_open: bool,
) -> tuple[dict[str, list[str]], set[str]]:
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

    vuln_map: dict[str, list[str]] = {}
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
                    entry.get("entry", {}).get("cve", "unknown")
                    for entry in matching
                ]

    return vuln_map, analyzed_purls
