"""PEP 592 yanked-version warnings for vulnerable packages.

Django middleware that intercepts pulp_python's Simple API
responses and injects ``data-yanked`` attributes (HTML) or
``"yanked"`` fields (JSON) on vulnerable packages.  pip then
shows an inline warning with the CVE ID and Trustify URL
before attempting the download — giving operators context
that the bare 403 from the download guard cannot provide.

The middleware queries Trustify live via the analyze API
(batch + fallback), with scanner labels as a fallback if the
live query fails or ``TRUSTIFY_URL`` is unset.  Builds a
one-line reason string with Trustify URLs (up to
``TRUSTIFY_YANK_MAX_CVES``), and rewrites the response
in-place.  Only ``/simple/`` paths with HTTP 200 are
processed; all other requests pass through untouched.

Controlled by ``TRUSTIFY_YANK_VULNERABLE`` (default True).
"""

from __future__ import annotations

import html as html_mod
import json
import logging
import posixpath
import re

from django.conf import settings

from pulp_trustify.client.client import build_trustify_url
from pulp_trustify.purl import url_to_purl

logger = logging.getLogger(__name__)

_ANCHOR_RE = re.compile(r"(<a\s+[^>]*href=\"([^\"#]+)(?:#[^\"]*)?\")([^>]*>)")


def _build_yanked_reason(
    cve_ids: list[str],
    base_url: str,
    max_cves: int = 3,
) -> str | None:
    if not cve_ids:
        return None
    total = len(cve_ids)
    shown = cve_ids[: max(max_cves, 1)]
    _P = "Vulnerable package flagged by Trustify"
    urls = [build_trustify_url(base_url, c) for c in shown]
    count = f" ({len(shown)} of {total} CVEs)" if total > len(shown) else ""
    if len(urls) == 1:
        return f"{_P}{count}: {urls[0]}"
    lines = "\n".join(f"- {u}" for u in urls)
    return f"{_P}{count}:\n{lines}"


def _live_lookup(
    filenames: list[str],
) -> dict[str, str]:
    """Query Trustify live for vulnerability status of filenames.
    Returns dict mapping filename -> yanked reason string.
    """
    filename_to_purl: dict[str, str] = {}
    for filename in filenames:
        purl = url_to_purl(filename)
        if purl:
            filename_to_purl[filename] = purl

    if not filename_to_purl:
        return {}

    from pulp_trustify.app.models import _get_client
    from pulp_trustify.gate import check_purls

    base_url = getattr(settings, "TRUSTIFY_URL", "")
    max_cves = getattr(settings, "TRUSTIFY_YANK_MAX_CVES", 3)
    threshold = getattr(settings, "TRUSTIFY_SEVERITY_THRESHOLD", "critical")

    purls = list(filename_to_purl.values())
    vuln_map = check_purls(
        client=_get_client(),
        purls=purls,
        threshold=threshold,
        fail_open=True,
    )

    result: dict[str, str] = {}
    for filename, purl in filename_to_purl.items():
        cve_ids = vuln_map.get(purl, [])
        if cve_ids:
            reason = _build_yanked_reason(cve_ids, base_url, max_cves)
            if reason:
                result[filename] = reason

    logger.debug(
        "Live yank query: %d PURLs, %d vulnerable",
        len(purls),
        len(result),
    )

    return result


def _label_fallback(
    filenames: list[str],
) -> dict[str, str]:
    from pulp_python.app.models import (  # type: ignore[import-not-found]
        PythonPackageContent,
    )

    qs = PythonPackageContent.objects.filter(
        filename__in=filenames,
    ).values_list("filename", "pulp_labels")
    base_url = getattr(settings, "TRUSTIFY_URL", "")
    max_cves = getattr(settings, "TRUSTIFY_YANK_MAX_CVES", 3)
    result: dict[str, str] = {}
    for filename, labels in qs:
        if not labels:
            continue
        if labels.get("trustify.vulnerable") != "true":
            continue
        cve_ids = labels.get("trustify.cves", "").split()
        reason = _build_yanked_reason(cve_ids, base_url, max_cves)
        if reason:
            result[filename] = reason
    return result


def _href_to_filename(href: str) -> str:
    """Extract bare filename from an href that may be a full URL."""
    return posixpath.basename(href.split("?")[0])


def _inject_yanked_html(
    content_bytes: bytes,
    repo_path: str,
) -> bytes:
    html = content_bytes.decode("utf-8")

    hrefs = {m.group(2) for m in _ANCHOR_RE.finditer(html)}
    if not hrefs:
        return content_bytes

    href_map = {h: _href_to_filename(h) for h in hrefs}
    filenames = list({v for v in href_map.values() if v})
    if not filenames:
        return content_bytes

    if not getattr(settings, "TRUSTIFY_URL", ""):
        yanked = _label_fallback(filenames)
        source = "labels"
    else:
        try:
            yanked = _live_lookup(filenames)
            source = "live"
        except Exception as exc:
            logger.warning(
                "Live yank query failed (%s), falling back to scanner labels",
                exc,
            )
            yanked = _label_fallback(filenames)
            source = "labels"

    logger.debug(
        "Yank lookup for %d files via %s: %d vulnerable",
        len(filenames),
        source,
        len(yanked),
    )

    if not yanked:
        return content_bytes

    def _rewrite(match: re.Match) -> str:
        prefix = match.group(1)
        href = match.group(2)
        suffix = match.group(3)
        fn = href_map.get(href, "")
        reason = yanked.get(fn)
        if not reason or "data-yanked=" in match.group(0):
            return match.group(0)
        escaped = html_mod.escape(reason, quote=True)
        return f'{prefix} data-yanked="{escaped}"{suffix}'

    return _ANCHOR_RE.sub(_rewrite, html).encode("utf-8")


def _inject_yanked_json(
    content_bytes: bytes,
    repo_path: str,
) -> bytes:
    data = json.loads(content_bytes)
    files = data.get("files", [])
    if not files:
        return content_bytes

    filenames = [f["filename"] for f in files if f.get("filename")]
    if not filenames:
        return content_bytes

    if not getattr(settings, "TRUSTIFY_URL", ""):
        yanked = _label_fallback(filenames)
        source = "labels"
    else:
        try:
            yanked = _live_lookup(filenames)
            source = "live"
        except Exception as exc:
            logger.warning(
                "Live yank query failed (%s), falling back to scanner labels",
                exc,
            )
            yanked = _label_fallback(filenames)
            source = "labels"

    logger.debug(
        "Yank lookup for %d files via %s: %d vulnerable",
        len(filenames),
        source,
        len(yanked),
    )

    if not yanked:
        return content_bytes

    for entry in files:
        reason = yanked.get(entry.get("filename"))
        if reason:
            entry["yanked"] = reason

    return json.dumps(data, separators=(",", ":")).encode("utf-8")


class YankMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        try:
            from pulp_python.app.models import (  # type: ignore[import-not-found]
                PythonPackageContent,  # noqa: F401
            )

            self._available = True
        except ImportError:
            self._available = False
            logger.info("pulp_python not installed; YankMiddleware disabled")

    def __call__(self, request):
        response = self.get_response(request)

        if not self._available:
            return response
        if not getattr(settings, "TRUSTIFY_YANK_VULNERABLE", False):
            return response
        if "/simple/" not in request.path:
            return response
        if response.status_code != 200:
            return response

        content_type = response.get("Content-Type", "")

        try:
            if "text/html" in content_type:
                response.content = _inject_yanked_html(
                    response.content, request.path
                )
            elif "application/vnd.pypi.simple" in content_type:
                response.content = _inject_yanked_json(
                    response.content, request.path
                )
        except Exception:
            logger.exception("Failed to inject yanked attributes")

        return response
