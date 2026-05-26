from __future__ import annotations

from pulp_trustify.client.client import TrustifyClient
from pulp_trustify.gate import gate_purl
from pulp_trustify.purl import url_to_purl


def permit_request(
    client: TrustifyClient,
    path: str,
    threshold: str,
    fail_open: bool,
) -> None:
    """Gate a download request by URL path.

    Extracts a PURL from the path, then delegates
    to gate_purl().

    Raises:
        PermissionError: if the PURL has vulnerabilities
            at or above threshold.
    """
    purl = url_to_purl(path)
    if purl is None:
        return
    gate_purl(client, purl, threshold, fail_open)
