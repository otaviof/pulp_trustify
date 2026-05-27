from __future__ import annotations

import logging

from pulp_trustify.purl import content_to_purl
from pulp_trustify.scanner import scan_content

logger = logging.getLogger(__name__)

PROGRESS_SCANNING = "Scanning content for vulnerabilities"
PROGRESS_REMOVING = "Removing vulnerable content"


def scan_repository(repository_pk: str) -> None:
    """Scan a repository for vulnerable content and create new version
    without blocked items."""
    from django.conf import settings

    if not getattr(settings, "TRUSTIFY_SCAN_ENABLED", True):
        return

    from pulp_trustify.app.models import _get_client

    repository = _get_repository(repository_pk)
    latest_version = repository.latest_version()

    if latest_version is None:
        logger.info(
            "Repository %s has no content, skipping scan",
            repository.pk,
        )
        return

    content_list = list(latest_version.content.all())
    content_purls = _enumerate_content(content_list)

    if not content_purls:
        logger.info("No scannable content in repository %s", repository.pk)
        return

    logger.info(PROGRESS_SCANNING)
    client = _get_client()
    results = scan_content(
        client=client,
        content_purls=content_purls,
        threshold=settings.TRUSTIFY_SEVERITY_THRESHOLD,
        fail_open=settings.TRUSTIFY_FAIL_OPEN,
        batch_size=settings.TRUSTIFY_BATCH_SIZE,
    )

    blocked_pks = {r.content_pk for r in results if r.blocked}

    if not blocked_pks:
        logger.info(
            "No vulnerable content found in repository %s",
            repository.pk,
        )
        return

    logger.info(
        "%s: removing %d vulnerable items",
        PROGRESS_REMOVING,
        len(blocked_pks),
    )

    blocked_qs = latest_version.content.filter(pk__in=blocked_pks)

    with repository.new_version() as new_version:
        new_version.remove_content(content=blocked_qs)


def _get_repository(pk: str):
    """Load a repository by primary key."""
    from pulpcore.plugin.models import Repository

    try:
        from pulp_python.app.models import (  # type: ignore[import-not-found]
            PythonRepository,
        )
    except ImportError:
        return Repository.objects.get(pk=pk)

    try:
        return PythonRepository.objects.get(pk=pk)
    except PythonRepository.DoesNotExist:
        return Repository.objects.get(pk=pk)


def _enumerate_content(
    content_list: list,
) -> list[tuple[str, str]]:
    """Build (pk, purl) pairs from a content list.

    Casts base Content objects to their concrete type
    so that attributes like name/version are available.
    """
    result: list[tuple[str, str]] = []
    for content in content_list:
        concrete = content.cast()
        purl = content_to_purl(concrete)
        if purl:
            result.append((str(concrete.pk), purl))
    return result
