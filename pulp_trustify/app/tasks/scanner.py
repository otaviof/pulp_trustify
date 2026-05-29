from __future__ import annotations

import logging
from datetime import UTC, datetime

from pulp_trustify.purl import content_to_purl
from pulp_trustify.scanner import scan_content

logger = logging.getLogger(__name__)

PROGRESS_SCANNING = "Scanning content for vulnerabilities"
PROGRESS_REMOVING = "Removing vulnerable content"


def _label_content(results, content_qs, threshold, source_repo):
    """Tag vulnerable content with CVE metadata labels."""
    now = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    blocked = [r for r in results if r.blocked]
    blocked_pks = [r.content_pk for r in blocked]
    content_map = {str(c.pk): c for c in content_qs.filter(pk__in=blocked_pks)}
    for result in blocked:
        content = content_map.get(result.content_pk)
        if content is None:
            continue
        content.pulp_labels.update(
            {
                "trustify.vulnerable": "true",
                "trustify.cves": " ".join(result.cve_ids),
                "trustify.severity": threshold,
                "trustify.detected_by": result.detection_mode,
                "trustify.scanned": now,
                "trustify.source_repo": source_repo,
            }
        )
        content.save(update_fields=["pulp_labels"])


def _quarantine_content(blocked_qs, repo_prefix, source_repo):
    """Copy vulnerable content to a typed quarantine repository."""
    repo_cls = type(source_repo)
    if not repo_cls.CONTENT_TYPES:
        logger.warning(
            "Quarantine skipped: repository type '%s' has no CONTENT_TYPES",
            source_repo.pulp_type,
        )
        return
    type_suffix = source_repo.pulp_type.split(".")[-1]
    repo_name = f"{repo_prefix}-{type_suffix}"
    repository, _ = repo_cls.objects.get_or_create(
        name=repo_name,
        defaults={
            "description": f"Quarantined vulnerable {type_suffix} content",
        },
    )
    with repository.new_version() as version:
        version.add_content(content=blocked_qs)


def _record_advisories(results, repository, threshold, actions):
    """Persist ScanAdvisory records for each finding."""
    from pulp_trustify.app.models import ScanAdvisory

    action = ",".join(actions)
    advisories = [
        ScanAdvisory(
            repository=repository,
            content_pk=r.content_pk,
            purl=r.purl,
            cve_ids=r.cve_ids,
            severity=threshold,
            detection_mode=r.detection_mode,
            action=action,
            details=[
                {
                    "cve_id": d.cve_id,
                    "severity": d.severity,
                    "trustify_url": d.trustify_url,
                    "description": d.description,
                }
                for d in r.details
            ],
        )
        for r in results
        if r.blocked
    ]
    ScanAdvisory.objects.bulk_create(advisories)


def scan_repository(repository_pk: str) -> None:
    """Scan a repository for vulnerable content and create new version
    without blocked items."""
    from django.conf import settings

    logger.info("Scan task started for repository '%s'", repository_pk)

    if not settings.TRUSTIFY_SCAN_ENABLED:
        logger.info("Scanning disabled via TRUSTIFY_SCAN_ENABLED")
        return

    logger.debug(
        "Scan settings: threshold='%s', fail_open=%s, batch_size=%d",
        settings.TRUSTIFY_SEVERITY_THRESHOLD,
        settings.TRUSTIFY_FAIL_OPEN,
        settings.TRUSTIFY_BATCH_SIZE,
    )

    from pulp_trustify.app.models import _get_client

    repository = _get_repository(repository_pk)
    latest_version = repository.latest_version()

    if latest_version is None:
        logger.info(
            "Repository '%s' has no content, skipping scan",
            repository.pk,
        )
        return

    content_list = list(latest_version.content.all())
    content_purls = _enumerate_content(content_list)

    logger.debug(
        "Enumerated %d content items, %d with PURLs",
        len(content_list),
        len(content_purls),
    )

    if not content_purls:
        logger.info("No scannable content in repository '%s'", repository.pk)
        return

    logger.info(PROGRESS_SCANNING)
    client = _get_client()
    results = scan_content(
        client=client,
        content_purls=content_purls,
        threshold=settings.TRUSTIFY_SEVERITY_THRESHOLD,
        fail_open=settings.TRUSTIFY_FAIL_OPEN,
        batch_size=settings.TRUSTIFY_BATCH_SIZE,
        base_url=(
            settings.TRUSTIFY_URL if settings.TRUSTIFY_ENRICH_DETAILS else ""
        ),
    )

    blocked = [r for r in results if r.blocked]
    blocked_pks = {r.content_pk for r in blocked}

    if not blocked_pks:
        logger.info(
            "No vulnerable content found in repository '%s'",
            repository.pk,
        )
        return

    for r in blocked:
        if r.details:
            cve_lines = "\n  ".join(
                f"{d.cve_id} ({d.severity})\n    {d.trustify_url}"
                for d in r.details
            )
            logger.info(
                "PURL '%s' has %d CVEs at or above '%s':\n  %s",
                r.purl,
                len(r.details),
                settings.TRUSTIFY_SEVERITY_THRESHOLD,
                cve_lines,
            )
        else:
            logger.info(
                "PURL '%s' blocked: %s",
                r.purl,
                ", ".join(r.cve_ids),
            )

    blocked_qs = latest_version.content.filter(pk__in=blocked_pks)
    actions: list[str] = []

    if settings.TRUSTIFY_SCAN_LABEL_CONTENT:
        _label_content(
            blocked,
            latest_version.content,
            settings.TRUSTIFY_SEVERITY_THRESHOLD,
            repository.name,
        )
        actions.append("labeled")

    if settings.TRUSTIFY_SCAN_QUARANTINE_REPO:
        _quarantine_content(
            blocked_qs,
            settings.TRUSTIFY_SCAN_QUARANTINE_REPO,
            repository,
        )
        actions.append("quarantined")

    if settings.TRUSTIFY_SCAN_REMOVE_CONTENT:
        logger.info(
            "%s: removing %d vulnerable items",
            PROGRESS_REMOVING,
            len(blocked_pks),
        )
        with repository.new_version() as new_version:
            new_version.remove_content(content=blocked_qs)
        actions.append("removed")

    if settings.TRUSTIFY_SCAN_ADVISORY:
        _record_advisories(
            blocked,
            repository,
            settings.TRUSTIFY_SEVERITY_THRESHOLD,
            actions,
        )


def _get_repository(pk: str):
    """Load a repository by primary key."""
    from pulpcore.plugin.models import Repository

    return Repository.objects.get(pk=pk).cast()


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
