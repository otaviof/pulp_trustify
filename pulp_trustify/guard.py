from __future__ import annotations

import logging

from pulp_trustify.client.client import TrustifyClient, TrustifyError
from pulp_trustify.policy import filter_vulnerabilities
from pulp_trustify.purl import url_to_purl

logger = logging.getLogger(__name__)


def permit_request(
    client: TrustifyClient,
    path: str,
    threshold: str,
    fail_open: bool,
) -> None:
    """Gate a request based on Trustify vulnerability analysis.

    Raises:
        PermissionError: if the PURL has vulnerabilities at or
            above threshold, or if the Trustify API fails and
            fail_open is False.
    """
    purl = url_to_purl(path)
    if purl is None:
        return

    try:
        response = client.analyze([purl])
    except TrustifyError as exc:
        if fail_open:
            logger.warning(
                "Trustify analysis failed (fail_open=True): %s",
                exc,
            )
            return
        raise PermissionError("Trustify API unavailable") from exc

    all_details: list[dict] = []
    for item in response.get("items", []):
        all_details.extend(item.get("details", []))

    matching = filter_vulnerabilities(all_details, threshold)
    if matching:
        cve_ids = [
            entry.get("entry", {}).get("cve", "unknown") for entry in matching
        ]
        raise PermissionError(f"Blocked due to CVE: {', '.join(cve_ids)}")
