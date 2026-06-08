from __future__ import annotations

import logging

from pulp_trustify.client.client import (
    TrustifyError,
    VulnerabilityChecker,
    build_trustify_url,
)
from pulp_trustify.gate import fallback_search
from pulp_trustify.scanner import VulnerabilityDetail, analyze_batch
from pulp_trustify.version import purl_full_name, purl_version

logger = logging.getLogger(__name__)


def build_npm_purls(packages: dict[str, list[str]]) -> list[str]:
    """Convert {name: [versions]} to flat PURL list.

    Scoped packages: '@scope/name' → 'pkg:npm/%40scope/name@version'
    Unscoped: 'lodash' → 'pkg:npm/lodash@version'
    """
    purls: list[str] = []
    for name, versions in packages.items():
        if name.startswith("@"):
            encoded_name = "%40" + name[1:]
        else:
            encoded_name = name
        for version in versions:
            purls.append(f"pkg:npm/{encoded_name}@{version}")
    return purls


def purl_to_npm_name(purl: str) -> str:
    """Inverse of build_npm_purls.

    'pkg:npm/%40scope/name@ver' → '@scope/name'
    'pkg:npm/lodash@4.17.21' → 'lodash'
    """
    name = purl_full_name(purl)
    return name if name else ""


def is_scoped_purl(purl: str) -> bool:
    """Check if PURL contains %40 (scoped NPM package)."""
    return "%40" in purl


def severity_to_npm(severity: str) -> str:
    """Map 'medium' → 'moderate' (npm's naming)."""
    lower = severity.lower()
    if lower == "medium":
        return "moderate"
    return lower


def vulnerability_to_advisory(
    detail: VulnerabilityDetail,
    purl: str,
    advisory_id: int,
) -> dict:
    """Convert VulnerabilityDetail to npm advisory format.

    Fields: id, url, title, severity, vulnerable_versions, cwe, cvss
    """
    version = purl_version(purl) or ""

    severity_lower = detail.severity.lower()
    cvss_map = {
        "critical": 9.0,
        "high": 7.0,
        "medium": 5.0,
        "moderate": 5.0,
        "low": 3.0,
    }
    cvss_score = cvss_map.get(severity_lower, 0.0)

    return {
        "id": advisory_id,
        "url": detail.trustify_url,
        "title": detail.cve_id,
        "severity": severity_to_npm(detail.severity),
        "vulnerable_versions": f"={version}",
        "cwe": [],
        "cvss": {"score": cvss_score},
    }


def audit_packages(
    client: VulnerabilityChecker,
    packages: dict[str, list[str]],
    threshold: str,
    fail_open: bool,
    batch_size: int = 100,
    base_url: str = "",
) -> dict[str, list[dict]]:
    """Audit NPM packages for vulnerabilities.

    Returns dict mapping npm package name → list of advisories.
    """
    purls = build_npm_purls(packages)
    if not purls:
        return {}

    logger.debug(
        "Auditing %d PURLs (threshold=%s, fail_open=%s)",
        len(purls),
        threshold,
        fail_open,
    )

    vuln_map, analyzed_purls = analyze_batch(
        client,
        purls,
        threshold,
        fail_open,
        base_url,
    )

    for purl in purls:
        if purl in analyzed_purls or is_scoped_purl(purl):
            continue

        try:
            fallback_results = fallback_search(client, purl, threshold)
        except TrustifyError as exc:
            if fail_open:
                logger.warning(
                    "Fallback search failed for '%s' (fail_open=True): %s",
                    purl,
                    exc,
                )
                continue
            raise

        if fallback_results:
            details = [
                VulnerabilityDetail(
                    cve_id=entry.get("entry", {}).get("cve", "unknown"),
                    severity=entry.get("base_score", {}).get(
                        "severity",
                        "unknown",
                    ),
                    trustify_url=build_trustify_url(
                        base_url,
                        entry.get("entry", {}).get("cve", "unknown"),
                    ),
                )
                for entry in fallback_results
            ]
            vuln_map[purl] = details

    result: dict[str, list[dict]] = {}
    advisory_id = 1

    for purl, details in vuln_map.items():
        npm_name = purl_to_npm_name(purl)
        if not npm_name:
            continue

        advisories = [
            vulnerability_to_advisory(detail, purl, advisory_id + idx)
            for idx, detail in enumerate(details)
        ]
        advisory_id += len(details)

        if npm_name not in result:
            result[npm_name] = []
        result[npm_name].extend(advisories)

    logger.debug(
        "Audit complete: %d packages with advisories",
        len(result),
    )

    return result
