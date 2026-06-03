import logging
from importlib.metadata import metadata

from pulpcore.plugin import PulpPluginAppConfig

_meta = metadata(__name__.split(".")[0])

logger = logging.getLogger(__name__)


class PulpTrustifyPluginAppConfig(PulpPluginAppConfig):
    name = "pulp_trustify.app"
    label = _meta["Name"].split("_", 1)[-1]
    version = _meta["Version"]
    python_package_name = _meta["Name"]
    domain_compatible = True

    def ready(self):
        super().ready()
        from django.conf import settings

        from pulp_trustify.upload import connect_signal

        level = getattr(settings, "TRUSTIFY_LOG_LEVEL", "INFO")
        logging.getLogger("pulp_trustify").setLevel(
            getattr(logging, level.upper(), logging.INFO)
        )
        connect_signal()
        self._connect_content_change_signal()
        self._register_scan_schedule(settings)
        logger.info("pulp_trustify ready (version '%s')", self.version)

    @staticmethod
    def _connect_content_change_signal():
        from django.db.models.signals import post_save
        from pulpcore.plugin.models import RepositoryVersion

        from pulp_trustify.app.signals import (
            on_repository_version_created,
        )

        post_save.connect(
            on_repository_version_created,
            sender=RepositoryVersion,
            dispatch_uid="trustify_scan_on_version_created",
        )

    @staticmethod
    def _register_scan_schedule(settings):
        interval = getattr(settings, "TRUSTIFY_SCAN_SCHEDULE", "")
        if not interval:
            _remove_scan_schedule()
            return

        from pulp_trustify.app.tasks.scheduler import (
            _parse_duration,
        )

        try:
            duration = _parse_duration(interval)
        except ValueError:
            logger.error("Invalid TRUSTIFY_SCAN_SCHEDULE: %r", interval)
            return

        from pulpcore.app.models import TaskSchedule  # noqa: TID251

        TaskSchedule.objects.update_or_create(
            name="trustify-scan-all",
            defaults={
                "task_name": (
                    "pulp_trustify.app.tasks.scheduler.scan_all_repositories"
                ),
                "dispatch_interval": duration,
            },
        )
        logger.info("Registered periodic scan schedule: %s", interval)


def _remove_scan_schedule():
    try:
        from pulpcore.app.models import TaskSchedule  # noqa: TID251

        TaskSchedule.objects.filter(name="trustify-scan-all").delete()
    except Exception:
        pass
