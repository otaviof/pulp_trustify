from __future__ import annotations

import logging
import re

from rest_framework.exceptions import ValidationError

logger = logging.getLogger(__name__)


def _normalize(name: str) -> str:
    """PEP 503 package name normalization."""
    return re.sub(r"[-_.]+", "-", str(name)).lower()


_CVE_RE = re.compile(r"CVE-\d{4}-\d+")


def _extract_cve_ids(msg: str) -> list[str]:
    return _CVE_RE.findall(msg)


def _purl_from_content(instance) -> str | None:
    """Build a PyPI PURL from PythonPackageContent fields."""
    if not instance.name or not instance.version:
        return None
    name = _normalize(instance.name)
    return f"pkg:pypi/{name}@{instance.version}"


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
    from pulp_trustify.gate import gate_purl

    enrich = getattr(settings, "TRUSTIFY_ENRICH_DETAILS", True)
    base = url if enrich else ""

    try:
        gate_purl(
            client=_get_client(),
            purl=purl,
            threshold=settings.TRUSTIFY_SEVERITY_THRESHOLD,
            fail_open=settings.TRUSTIFY_FAIL_OPEN,
            base_url=base,
        )
        logger.debug("Upload allowed for '%s'", purl)
    except PermissionError as exc:
        msg = str(exc)
        if base and exc.args:
            from pulp_trustify.client.client import build_trustify_url

            cve_ids = _extract_cve_ids(msg)
            if cve_ids:
                urls = "\n  ".join(
                    build_trustify_url(base, cve) for cve in cve_ids
                )
                msg += f"\nDetails:\n  {urls}"
        logger.warning("Upload blocked for '%s': %s", purl, msg)
        raise ValidationError(detail=msg) from exc


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
