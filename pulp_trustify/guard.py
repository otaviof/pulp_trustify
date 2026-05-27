from __future__ import annotations

import logging

from pulp_trustify.client.client import VulnerabilityChecker
from pulp_trustify.gate import gate_purl
from pulp_trustify.purl import url_to_purl

logger = logging.getLogger(__name__)


def permit_request(
    client: VulnerabilityChecker,
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
    logger.debug("Guard checking path: '%s'", path)
    purl = url_to_purl(path)
    if purl is None:
        logger.debug("No PURL for path '%s', allowing", path)
        return
    logger.debug("Resolved PURL: '%s' from path: '%s'", purl, path)
    logger.debug(
        "Delegating to gate_purl: '%s' threshold='%s' fail_open=%s",
        purl,
        threshold,
        fail_open,
    )
    gate_purl(client, purl, threshold, fail_open)
