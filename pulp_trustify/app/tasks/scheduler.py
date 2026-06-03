from __future__ import annotations

import logging
import re
from datetime import timedelta

logger = logging.getLogger(__name__)

_DURATION_RE = re.compile(r"(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?$")


def _parse_duration(value: str) -> timedelta:
    """Parse a duration string into a timedelta.

    Accepted formats: ``"6h"``, ``"1d"``, ``"30m"``,
    ``"1d12h"``, ``"1d6h30m"``.
    """
    m = _DURATION_RE.match(value.strip())
    if not m or not any(m.groups()):
        raise ValueError(
            f"Invalid duration {value!r}; expected format like '6h', '1d', '30m'"
        )
    days = int(m.group(1) or 0)
    hours = int(m.group(2) or 0)
    minutes = int(m.group(3) or 0)
    return timedelta(days=days, hours=hours, minutes=minutes)


def scan_all_repositories() -> None:
    """Dispatch scan_repository for every repository."""
    from pulpcore.plugin.models import Repository
    from pulpcore.plugin.tasking import dispatch

    from pulp_trustify.app.tasks.scanner import scan_repository

    repos = list(Repository.objects.all())
    logger.info(
        "Periodic scan: dispatching scans for %d repositories",
        len(repos),
    )
    for repo in repos:
        dispatch(
            scan_repository,
            exclusive_resources=[repo],
            kwargs={"repository_pk": str(repo.pk)},
        )
