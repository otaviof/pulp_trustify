"""Shared label constants and helpers for vulnerability tracking.

Provides label keys used across scanner, yank, and NPM modules,
plus utilities for building reason strings and querying vulnerable
packages from dual sources (live Trustify API or scanner labels).
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Iterable

from pulp_trustify.client.client import build_trustify_url

logger = logging.getLogger(__name__)

LABEL_VULNERABLE = "trustify.vulnerable"
LABEL_CVES = "trustify.cves"
LABEL_SEVERITY = "trustify.severity"
LABEL_DETECTED_BY = "trustify.detected_by"
LABEL_SCANNED = "trustify.scanned"
LABEL_SOURCE_REPO = "trustify.source_repo"
REASON_PREFIX = "Vulnerable package flagged by Trustify"


def build_reason(
    cve_ids: list[str],
    base_url: str,
    max_cves: int = 3,
) -> str | None:
    """Build human-readable reason string with Trustify CVE URLs.

    Formats up to max_cves CVE IDs as Trustify vulnerability URLs.
    If there are more CVEs than shown, includes "(shown of total)"
    annotation. Single CVE gets inline format; multiple CVEs get
    bulleted list.

    Args:
        cve_ids: List of CVE identifiers (e.g., ["CVE-2024-1234"]).
        base_url: Trustify base URL for building CVE links.
        max_cves: Maximum number of CVE URLs to include (default 3).

    Returns:
        Formatted reason string or None if cve_ids is empty.
    """
    if not cve_ids:
        return None
    total = len(cve_ids)
    shown = cve_ids[: max(max_cves, 1)]
    urls = [build_trustify_url(base_url, c) for c in shown]
    count = f" ({len(shown)} of {total} CVEs)" if total > len(shown) else ""
    if len(urls) == 1:
        return f"{REASON_PREFIX}{count}: {urls[0]}"
    lines = "\n".join(f"- {u}" for u in urls)
    return f"{REASON_PREFIX}{count}:\n{lines}"


def build_reason_inline(
    cve_ids: list[str],
    base_url: str,
    max_cves: int = 3,
) -> str | None:
    """Single-line reason string for HTTP error messages."""
    if not cve_ids:
        return None
    shown = cve_ids[: max(max_cves, 1)]
    urls = [build_trustify_url(base_url, c) for c in shown]
    overflow = (
        f" (+{len(cve_ids) - len(shown)} more)"
        if len(cve_ids) > len(shown)
        else ""
    )
    return f"{REASON_PREFIX}: {', '.join(urls)}{overflow}"


def labels_to_reasons(
    label_rows: Iterable[tuple[str, dict[str, Any]]],
    base_url: str,
    max_cves: int,
) -> dict[str, str]:
    """Convert (identifier, pulp_labels) pairs to {identifier: reason}.

    Filters rows to those marked vulnerable, extracts CVE IDs from
    labels, and calls build_reason() to produce human-readable strings.

    Args:
        label_rows: Iterable of (identifier, pulp_labels) tuples from
            a Django .values_list() query.
        base_url: Trustify base URL for CVE link generation.
        max_cves: Maximum CVE URLs per reason string.

    Returns:
        Dict mapping identifiers to formatted reason strings.
        Only includes rows where LABEL_VULNERABLE is "true".
    """
    result: dict[str, str] = {}
    for identifier, labels in label_rows:
        if not labels:
            continue
        if labels.get(LABEL_VULNERABLE) != "true":
            continue
        cve_ids = labels.get(LABEL_CVES, "").split()
        reason = build_reason(cve_ids, base_url, max_cves)
        if reason:
            result[identifier] = reason
    return result


def lookup_vulnerable(
    identifiers: list[str],
    live_fn: Callable[[list[str]], dict[str, str]],
    fallback_fn: Callable[[list[str]], dict[str, str]],
    trustify_url: str = "",
) -> dict[str, str]:
    """Dual-source vulnerability lookup with live API + label fallback.

    When trustify_url is empty, calls fallback_fn directly (scanner
    labels). Otherwise tries live_fn (Trustify API) first; if it raises
    any exception, logs a warning and falls back to labels. Logs the
    chosen source and result count at debug level.

    Args:
        identifiers: List of package identifiers (filenames, PURLs, etc).
        live_fn: Callable that queries Trustify API for vulnerabilities.
        fallback_fn: Callable that reads scanner labels from DB.
        trustify_url: Trustify base URL. If empty, skips live lookup.

    Returns:
        Dict mapping identifiers to human-readable reason strings.
    """
    if not trustify_url:
        result = fallback_fn(identifiers)
        logger.debug(
            "Lookup via labels (%d identifiers): %d vulnerable",
            len(identifiers),
            len(result),
        )
        return result
    try:
        result = live_fn(identifiers)
        logger.debug(
            "Lookup via live API (%d identifiers): %d vulnerable",
            len(identifiers),
            len(result),
        )
        return result
    except Exception as exc:
        logger.warning(
            "Live lookup failed (%s), falling back to scanner labels",
            exc,
        )
        result = fallback_fn(identifiers)
        logger.debug(
            "Lookup via labels (%d identifiers): %d vulnerable",
            len(identifiers),
            len(result),
        )
        return result
