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
        logger.info("pulp_trustify ready (version '%s')", self.version)
