from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def on_repository_version_created(sender, instance, **kwargs):
    """Dispatch a scan when a repository version is finalized."""
    if not instance.complete:
        return

    from django.conf import settings

    if not getattr(settings, "TRUSTIFY_SCAN_ON_CONTENT_CHANGE", False):
        return
    if not getattr(settings, "TRUSTIFY_SCAN_ENABLED", True):
        return

    from pulpcore.app.contexts import _current_task  # noqa: TID251

    task = _current_task.get()
    if task and "scan_repository" in (task.name or ""):
        logger.debug(
            "Skipping scan trigger: current task is '%s'",
            task.name,
        )
        return

    from pulpcore.plugin.tasking import dispatch

    from pulp_trustify.app.tasks.scanner import scan_repository

    repository = instance.repository

    logger.info(
        "Content change detected in '%s', dispatching scan",
        repository.name,
    )
    dispatch(
        scan_repository,
        exclusive_resources=[repository],
        kwargs={"repository_pk": str(repository.pk)},
    )
