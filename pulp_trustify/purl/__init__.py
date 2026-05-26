from pulp_trustify.purl.registry import register, url_to_purl

__all__ = ["register", "url_to_purl"]

import pulp_trustify.purl.pypi  # noqa: F401, E402
