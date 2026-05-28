from __future__ import annotations

import logging
import threading

from django.db.models import (
    CASCADE,
    CharField,
    DateTimeField,
    ForeignKey,
    Index,
    JSONField,
    Model,
    UUIDField,
)
from pulpcore.plugin.models import ContentGuard, Repository

from pulp_trustify.client.client import TrustifyClient
from pulp_trustify.guard import permit_request

logger = logging.getLogger(__name__)

_client: TrustifyClient | None = None
_client_lock = threading.Lock()


def _get_client() -> TrustifyClient:
    """Lazy-initialize a global TrustifyClient from Django settings.

    Thread-safe double-checked locking ensures exactly one client
    instance is created across all guard permit() calls.
    """
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                from django.conf import settings

                _client = TrustifyClient(
                    url=settings.TRUSTIFY_URL,
                    api_version=settings.TRUSTIFY_API_VERSION,
                    client_id=settings.TRUSTIFY_CLIENT_ID,
                    client_secret=settings.TRUSTIFY_CLIENT_SECRET,
                    issuer_url=settings.TRUSTIFY_ISSUER_URL,
                    ca_bundle=settings.TRUSTIFY_CA_BUNDLE,
                )
                logger.info(
                    "TrustifyClient initialized for '%s'",
                    settings.TRUSTIFY_URL,
                )
    return _client


class TrustifyGuard(ContentGuard):
    """ContentGuard that blocks downloads of vulnerable packages.

    Consults Trustify's vulnerability analysis API at download time;
    raises PermissionError if the requested artifact has CVEs at or
    above the configured severity threshold.
    """

    TYPE = "trustify"

    def permit(self, request):
        """Check the request path against Trustify and deny
        if vulnerabilities exceed the severity threshold."""
        from django.conf import settings

        logger.debug("TrustifyGuard.permit() called")
        permit_request(
            client=_get_client(),
            path=request.path,
            threshold=settings.TRUSTIFY_SEVERITY_THRESHOLD,
            fail_open=settings.TRUSTIFY_FAIL_OPEN,
        )

    class Meta(ContentGuard.Meta):
        default_related_name = "%(app_label)s_%(model_name)s"


class ScanAdvisory(Model):
    """Records a vulnerability finding from a scanner run."""

    repository = ForeignKey(
        Repository,
        on_delete=CASCADE,
        related_name="scan_advisories",
    )
    content_pk = UUIDField()
    purl = CharField(max_length=512)
    cve_ids = JSONField(default=list)
    severity = CharField(max_length=16)
    detection_mode = CharField(max_length=16)
    action = CharField(max_length=64)
    scanned_at = DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            Index(fields=["repository", "scanned_at"]),
            Index(fields=["purl"]),
        ]
