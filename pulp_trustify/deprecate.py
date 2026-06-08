"""NPM deprecation warnings for vulnerable packages.

Monkey-patches NpmDistribution.content_handler to inject
``deprecated`` fields in packument JSON responses for
versions found vulnerable by Trustify or scanner labels.

Controlled by ``TRUSTIFY_DEPRECATE_VULNERABLE`` setting.
"""

from __future__ import annotations

import json
import logging

from pulp_trustify.labels import (
    build_reason,
    labels_to_reasons,
    lookup_vulnerable,
)

logger = logging.getLogger(__name__)


def _npm_live_lookup(
    package_name: str,
    versions: list[str],
) -> dict[str, str]:
    """Query Trustify live for vulnerability status of NPM versions.

    Returns dict mapping version -> reason string.
    """
    from django.conf import settings

    from pulp_trustify.app.models import _get_client
    from pulp_trustify.gate import check_purls

    base_url = getattr(settings, "TRUSTIFY_URL", "")
    max_cves = getattr(settings, "TRUSTIFY_YANK_MAX_CVES", 3)
    threshold = getattr(settings, "TRUSTIFY_SEVERITY_THRESHOLD", "critical")

    purls: list[str] = []
    version_to_purl: dict[str, str] = {}

    for version in versions:
        if package_name.startswith("@"):
            encoded_name = package_name.replace("@", "%40", 1)
            purl = f"pkg:npm/{encoded_name}@{version}"
        else:
            purl = f"pkg:npm/{package_name}@{version}"
        purls.append(purl)
        version_to_purl[version] = purl

    vuln_map = check_purls(
        client=_get_client(),
        purls=purls,
        threshold=threshold,
        fail_open=True,
    )

    result: dict[str, str] = {}
    for version, purl in version_to_purl.items():
        cve_ids = vuln_map.get(purl, [])
        if cve_ids:
            reason = build_reason(cve_ids, base_url, max_cves)
            if reason:
                result[version] = reason

    return result


def _npm_label_fallback(
    package_name: str,
    versions: list[str],
) -> dict[str, str]:
    """Read scanner labels from pulp_npm.app.models.Package.

    Returns dict mapping version -> reason string.
    """
    from django.conf import settings
    from pulp_npm.app.models import Package  # type: ignore[import-not-found]

    qs = Package.objects.filter(
        name=package_name,
        version__in=versions,
    ).values_list("version", "pulp_labels")

    base_url = getattr(settings, "TRUSTIFY_URL", "")
    max_cves = getattr(settings, "TRUSTIFY_YANK_MAX_CVES", 3)

    return labels_to_reasons(qs, base_url, max_cves)


def _inject_deprecated(body: bytes, package_name: str) -> bytes | None:
    """Inject deprecated fields into packument versions.

    Returns modified JSON bytes, or None if no modifications made.
    """
    from django.conf import settings

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None

    versions = data.get("versions")
    if not isinstance(versions, dict) or not versions:
        return None

    name = data.get("name", package_name)
    version_keys = list(versions.keys())

    def live_fn(vers: list[str]) -> dict[str, str]:
        return _npm_live_lookup(name, vers)

    def fallback_fn(vers: list[str]) -> dict[str, str]:
        return _npm_label_fallback(name, vers)

    vulnerable = lookup_vulnerable(
        version_keys,
        live_fn,
        fallback_fn,
        getattr(settings, "TRUSTIFY_URL", ""),
    )

    if not vulnerable:
        return None

    for ver, reason in vulnerable.items():
        if ver in versions:
            versions[ver]["deprecated"] = reason

    return json.dumps(data, separators=(",", ":")).encode("utf-8")


def wrap_npm_content_handler() -> None:
    """Install monkey-patch wrapper on NpmDistribution.content_handler.

    Wrapper intercepts packument responses and injects deprecated
    fields for vulnerable versions.
    """
    from django.conf import settings

    if not getattr(settings, "TRUSTIFY_DEPRECATE_VULNERABLE", True):
        logger.debug("NPM deprecation disabled")
        return

    try:
        from pulp_npm.app.models import (  # type: ignore[import-not-found]
            NpmDistribution,
        )
    except ImportError:
        logger.debug("pulp_npm not installed, deprecation wrapper not applied")
        return

    original = NpmDistribution.content_handler

    def _wrapped_content_handler(self, path):
        response = original(self, path)
        if response is None:
            return response
        try:
            body = response.body
            if not body:
                return response

            content_type = getattr(response, "content_type", "")
            if "application/json" not in content_type:
                return response

            pkg_name = ""
            segs = path.strip("/").split("/")
            if len(segs) >= 2 and segs[-2].startswith("@"):
                pkg_name = f"{segs[-2]}/{segs[-1]}"
            elif segs:
                pkg_name = segs[-1]

            result = _inject_deprecated(body, pkg_name)
            if result is None:
                return response

            import aiohttp.web

            return aiohttp.web.Response(
                body=result,
                status=response.status,
                content_type="application/json",
            )
        except Exception:
            logger.exception(
                "Deprecation wrapper failed for '%s'",
                path,
            )
            return response

    NpmDistribution.content_handler = _wrapped_content_handler
    logger.info("Installed NPM deprecation wrapper")
