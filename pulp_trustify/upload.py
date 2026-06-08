from __future__ import annotations

import logging

from rest_framework.exceptions import ValidationError

logger = logging.getLogger(__name__)


def _purl_from_content(instance) -> str | None:
    """Build a PURL from content using the PURL registry."""
    from pulp_trustify.purl import content_to_purl

    return content_to_purl(instance)


def _build_block_message(result, purl, base_url):
    """Format a human-readable error for blocked uploads.

    With a base_url, produces an inline reason with Trustify
    vulnerability URLs plus a Details block; without one,
    falls back to a plain CVE list.
    """
    from pulp_trustify.client.client import build_trustify_url
    from pulp_trustify.labels import build_reason_inline

    if base_url and result.cve_ids:
        reason = build_reason_inline(result.cve_ids, base_url)
        if reason:
            urls = "\n  ".join(
                build_trustify_url(base_url, cve) for cve in result.cve_ids
            )
            return f"{reason}\nDetails:\n  {urls}"
    from pulp_trustify.gate import MSG_BLOCKED_CVE

    return f"{MSG_BLOCKED_CVE}: {', '.join(result.cve_ids)}"


def upload_gate(sender, instance, **kwargs) -> None:
    """pre_save handler: block uploads of vulnerable packages."""
    from django.conf import settings

    logger.debug(
        "Upload gate checking '%s'=='%s'",
        instance.name,
        instance.version,
    )

    if not getattr(settings, "TRUSTIFY_GATE_UPLOADS", True):
        logger.debug("Upload gating disabled, skipping")
        return

    url = getattr(settings, "TRUSTIFY_URL", "")
    if not url:
        logger.debug("TRUSTIFY_URL not set, skipping upload gate")
        return

    purl = _purl_from_content(instance)
    if purl is None:
        logger.debug(
            "Cannot build PURL for '%s', skipping",
            instance.name or "unknown",
        )
        return

    logger.debug("Built PURL '%s' for upload", purl)

    from pulp_trustify.app.models import _get_client
    from pulp_trustify.gate import check_purl_with_mode

    enrich = getattr(settings, "TRUSTIFY_ENRICH_DETAILS", True)
    base = url if enrich else ""

    result = check_purl_with_mode(
        client=_get_client(),
        purl=purl,
        threshold=settings.TRUSTIFY_SEVERITY_THRESHOLD,
        fail_open=settings.TRUSTIFY_FAIL_OPEN,
        base_url=base,
    )

    if not hasattr(instance, "pulp_labels") or instance.pulp_labels is None:
        instance.pulp_labels = {}

    if getattr(settings, "TRUSTIFY_GATE_LABEL_CONTENT", True):
        from datetime import UTC, datetime

        now = (
            datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
        )
        instance.pulp_labels["trustify.scanned"] = "true"
        instance.pulp_labels["trustify.scanned_at"] = now
        instance.pulp_labels["trustify.detected_by"] = (
            result.detection_mode or "analyze"
        )

        if result.cve_ids:
            instance.pulp_labels["trustify.cves"] = " ".join(result.cve_ids)
            instance.pulp_labels["trustify.clean"] = "false"
        elif result.all_findings:
            below_cves = [
                f.get("entry", {}).get("cve", "unknown")
                for f in result.all_findings
            ]
            instance.pulp_labels["trustify.cves"] = " ".join(below_cves)
            instance.pulp_labels["trustify.clean"] = "false"
        else:
            instance.pulp_labels["trustify.clean"] = "true"

    if result.cve_ids:
        msg = _build_block_message(result, purl, base)
        logger.warning("Upload blocked for '%s': %s", purl, msg)
        raise ValidationError(detail=msg)

    if getattr(settings, "TRUSTIFY_GATE_ADVISORY", True):
        try:
            from pulp_trustify.app.models import GateAdvisory

            GateAdvisory.objects.create(
                purl=purl,
                cve_ids=[
                    f.get("entry", {}).get("cve", "unknown")
                    for f in result.all_findings
                ],
                details=[
                    {
                        "cve_id": d.cve_id,
                        "severity": d.severity,
                        "trustify_url": d.trustify_url,
                        "description": d.description,
                    }
                    for d in result.details
                ],
                severity=settings.TRUSTIFY_SEVERITY_THRESHOLD,
                detection_mode=result.detection_mode or "analyze",
                action="allowed",
            )
        except (ImportError, AttributeError):
            logger.debug("GateAdvisory model not available, skipping")

    logger.debug("Upload allowed for '%s'", purl)


def connect_signal():
    """Connect upload gate to PythonPackageContent pre_save.

    Gracefully handles missing pulp_python.
    """
    try:
        from pulp_python.app.models import (  # type: ignore[import-not-found]
            PythonPackageContent,
        )
    except ImportError:
        logger.debug("pulp_python not installed, upload gate not connected")
        return

    from django.db.models.signals import pre_save

    pre_save.connect(
        upload_gate,
        sender=PythonPackageContent,
        dispatch_uid="trustify_upload_gate",
    )
    logger.info("Connected upload gate signal for PythonPackageContent")


def connect_npm_signal():
    """Connect upload gate to pulp_npm Package pre_save.

    Gracefully handles missing pulp_npm.
    """
    try:
        from pulp_npm.app.models import (  # type: ignore[import-not-found]
            Package,
        )
    except ImportError:
        logger.debug("pulp_npm not installed, NPM upload gate not connected")
        return

    from django.db.models.signals import pre_save

    pre_save.connect(
        upload_gate,
        sender=Package,
        dispatch_uid="trustify_npm_upload_gate",
    )
    logger.info("Connected upload gate signal for NPM Package")
