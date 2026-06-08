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

    base_url = settings.TRUSTIFY_URL
    max_cves = settings.TRUSTIFY_YANK_MAX_CVES
    threshold = settings.TRUSTIFY_SEVERITY_THRESHOLD

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

    base_url = settings.TRUSTIFY_URL
    max_cves = settings.TRUSTIFY_YANK_MAX_CVES

    return labels_to_reasons(qs, base_url, max_cves)


def _parse_semver(ver: str) -> tuple[int, ...]:
    """Best-effort semver parse for sorting."""
    try:
        parts = ver.split("-")[0].split(".")
        return tuple(int(p) for p in parts)
    except (ValueError, AttributeError):
        return (0,)


def _retarget_dist_tags(
    data: dict,
    remaining_versions: dict,
) -> None:
    """Update dist-tags to point to remaining versions."""
    dist_tags = data.get("dist-tags", {})
    if not dist_tags:
        return
    sorted_versions = sorted(
        remaining_versions.keys(),
        key=_parse_semver,
        reverse=True,
    )
    for tag, ver in list(dist_tags.items()):
        if ver not in remaining_versions:
            if sorted_versions:
                dist_tags[tag] = sorted_versions[0]
            else:
                del dist_tags[tag]


def _modify_packument(
    body: bytes,
    package_name: str,
    block_downloads: bool = False,
) -> bytes | None:
    """Modify packument for vulnerable versions.

    When block_downloads is False, injects deprecated fields.
    When True, removes vulnerable versions from the packument
    and re-targets dist-tags.  Falls back to deprecation when
    all versions are vulnerable to avoid empty packuments.

    Returns modified JSON bytes, or None if no changes needed.
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
        settings.TRUSTIFY_URL,
    )

    if not vulnerable:
        return None

    if block_downloads:
        if set(vulnerable) >= set(version_keys):
            for ver, reason in vulnerable.items():
                if ver in versions:
                    versions[ver]["deprecated"] = reason
        else:
            for ver in vulnerable:
                versions.pop(ver, None)
            _retarget_dist_tags(data, versions)
    else:
        for ver, reason in vulnerable.items():
            if ver in versions:
                versions[ver]["deprecated"] = reason

    return json.dumps(data, separators=(",", ":")).encode("utf-8")


def wrap_npm_content_handler() -> None:
    """Install monkey-patch wrapper on NpmDistribution.content_handler.

    Wrapper intercepts packument responses and modifies them
    based on settings: deprecation warnings, version filtering,
    or both.
    """
    from django.conf import settings

    deprecate = settings.TRUSTIFY_DEPRECATE_VULNERABLE
    block = settings.TRUSTIFY_NPM_BLOCK_DOWNLOADS
    if not deprecate and not block:
        logger.debug("NPM deprecation and blocking disabled")
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
            raw_body = response.body
            if not raw_body:
                return response
            if hasattr(raw_body, "_value"):
                body = raw_body._value
            else:
                body = raw_body
            if not body:
                return response

            content_type = getattr(response, "content_type", "")
            is_json = (
                "application/json" in content_type or "text/plain" in content_type
            )
            if not is_json:
                return response

            pkg_name = ""
            segs = path.strip("/").split("/")
            if len(segs) >= 2 and segs[-2].startswith("@"):
                pkg_name = f"{segs[-2]}/{segs[-1]}"
            elif segs:
                pkg_name = segs[-1]

            block_dl = settings.TRUSTIFY_NPM_BLOCK_DOWNLOADS
            result = _modify_packument(body, pkg_name, block_downloads=block_dl)
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
    logger.info("Installed NPM packument wrapper")
