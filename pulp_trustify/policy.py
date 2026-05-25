from __future__ import annotations

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def exceeds_threshold(severity: str | None, threshold: str) -> bool:
    """Return True if severity is at or above threshold."""
    if severity is None:
        return False
    sev_level = SEVERITY_ORDER.get(severity.lower())
    thresh_level = SEVERITY_ORDER.get(threshold.lower())
    if sev_level is None or thresh_level is None:
        return False
    return sev_level >= thresh_level


def filter_vulnerabilities(
    details: list[dict],
    threshold: str,
) -> list[dict]:
    """Filter Trustify analyze response details by severity threshold."""
    return [
        entry
        for entry in details
        if exceeds_threshold(
            entry.get("base_score", {}).get("severity"),
            threshold,
        )
    ]
