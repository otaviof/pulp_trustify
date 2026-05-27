from __future__ import annotations

import posixpath
import re

from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    parse_sdist_filename,
    parse_wheel_filename,
)

from pulp_trustify.purl import register, register_content


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", str(name)).lower()


@register("pypi")
def parse_pypi_url(path: str) -> str | None:
    filename = posixpath.basename(path)

    if filename.endswith(".whl"):
        try:
            name, version, _, _ = parse_wheel_filename(filename)
            return f"pkg:pypi/{_normalize(name)}@{version}"
        except InvalidWheelFilename:
            return None

    if filename.endswith(".tar.gz") or filename.endswith(".zip"):
        try:
            name, version = parse_sdist_filename(filename)
            return f"pkg:pypi/{_normalize(name)}@{version}"
        except InvalidSdistFilename:
            return None

    return None


@register_content("pypi")
def parse_pypi_content(content: object) -> str | None:
    name = getattr(content, "name", None)
    version = getattr(content, "version", None)
    if not name or not version:
        return None
    return f"pkg:pypi/{_normalize(name)}@{version}"
