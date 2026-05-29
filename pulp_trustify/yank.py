"""PEP 592 yanked-version warnings for vulnerable packages.

Django middleware that intercepts pulp_python's Simple API
responses and injects ``data-yanked`` attributes (HTML) or
``"yanked"`` fields (JSON) on packages whose ``pulp_labels``
mark them as vulnerable.  pip then shows an inline warning
with the CVE ID and Trustify URL before attempting the
download — giving operators context that the bare 403 from
the download guard cannot provide.

The middleware reads ``trustify.vulnerable`` and
``trustify.cves`` labels set by the scanner, builds a
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

logger = logging.getLogger(__name__)

_ANCHOR_RE = re.compile(r"(<a\s+[^>]*href=\"([^\"#]+)(?:#[^\"]*)?\")([^>]*>)")


def _build_yanked_reason(
    labels: dict[str, str],
    base_url: str,
    max_cves: int = 3,
) -> str | None:
    if labels.get("trustify.vulnerable") != "true":
        return None
    all_cves = labels.get("trustify.cves", "").split()
    if not all_cves:
        return None
    total = len(all_cves)
    shown = all_cves[: max(max_cves, 1)]
    _P = "Vulnerable package flagged by Trustify"
    urls = [build_trustify_url(base_url, c) for c in shown]
    count = f" ({len(shown)} of {total} CVEs)" if total > len(shown) else ""
    if len(urls) == 1:
        return f"{_P}{count}: {urls[0]}"
    lines = "\n".join(f"- {u}" for u in urls)
    return f"{_P}{count}:\n{lines}"


def _label_lookup(
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
        reason = _build_yanked_reason(labels, base_url, max_cves)
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

    yanked = _label_lookup(filenames)
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

    yanked = _label_lookup(filenames)
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
