from importlib.metadata import metadata

from pulpcore.plugin import PulpPluginAppConfig

_meta = metadata(__name__.split(".")[0])


class PulpTrustifyPluginAppConfig(PulpPluginAppConfig):
    name = __name__
    label = _meta["Name"].split("_", 1)[-1]
    version = _meta["Version"]
    python_package_name = _meta["Name"]
    domain_compatible = True

    def ready(self):
        super().ready()
        from pulp_trustify.upload import connect_signal

        connect_signal()
