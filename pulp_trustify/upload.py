from __future__ import annotations

import logging
import re

from rest_framework.exceptions import ValidationError

logger = logging.getLogger(__name__)


def _normalize(name: str) -> str:
    """PEP 503 package name normalization."""
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def _purl_from_content(instance) -> str | None:
    """Build a PyPI PURL from PythonPackageContent fields."""
    if not instance.name or not instance.version:
        return None
    name = _normalize(instance.name)
    return f"pkg:pypi/{name}@{instance.version}"


def upload_gate(sender, instance, **kwargs) -> None:
    """pre_save handler: block uploads of vulnerable packages."""
    from django.conf import settings

    if not getattr(settings, "TRUSTIFY_GATE_UPLOADS", True):
        return

    url = getattr(settings, "TRUSTIFY_URL", "")
    if not url:
        return

    purl = _purl_from_content(instance)
    if purl is None:
        return

    from pulp_trustify.app.models import _get_client
    from pulp_trustify.gate import gate_purl

    try:
        gate_purl(
            client=_get_client(),
            purl=purl,
            threshold=settings.TRUSTIFY_SEVERITY_THRESHOLD,
            fail_open=settings.TRUSTIFY_FAIL_OPEN,
        )
    except PermissionError as exc:
        raise ValidationError(detail=str(exc)) from exc


def connect_signal():
    """Connect upload gate to PythonPackageContent pre_save.

    Gracefully handles missing pulp_python.
    """
    try:
        from pulp_python.app.models import (  # type: ignore[import-not-found]
            PythonPackageContent,
        )
    except ImportError:
        return

    from django.db.models.signals import pre_save

    pre_save.connect(
        upload_gate,
        sender=PythonPackageContent,
        dispatch_uid="trustify_upload_gate",
    )
