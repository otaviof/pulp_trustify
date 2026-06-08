from __future__ import annotations

import re
from dataclasses import dataclass

import semver
from packaging.version import InvalidVersion, Version


@dataclass(frozen=True)
class VersionRange:
    """Half-open version interval [introduced, fixed).

    Both bounds are optional:
      - introduced=None, fixed="2.6.3" means all versions
        before 2.6.3 are affected.
      - introduced="1.22", fixed="2.6.3" means versions
        >=1.22 and <2.6.3 are affected.
      - introduced="1.22", fixed=None means all versions
        >=1.22 are affected (no fix available).
    """

    introduced: str | None = None
    fixed: str | None = None


# "Starting in version 1.22 and prior to version 2.6.3"
_RANGE_PATTERN = re.compile(
    r"[Ss]tarting\s+in\s+version\s+"
    r"(\d+(?:\.\d+)*)"
    r"\s+and\s+(?:prior\s+to|before)\s+version\s+"
    r"(\d+(?:\.\d+)*)"
)

# "From 1.23 to before 2.7.0" (GitHub advisory style)
_FROM_PATTERN = re.compile(
    r"[Ff]rom\s+(\d+(?:\.\d+)*)"
    r"\s+to\s+(?:before\s+)?(\d+(?:\.\d+)*)"
)

# "versions 1.0 through 2.0"
_THROUGH_PATTERN = re.compile(
    r"versions?\s+(\d+(?:\.\d+)*)"
    r"\s+(?:through|to)\s+"
    r"(\d+(?:\.\d+)*)"
)

# "prior to version 2.6.3" / "before version 3.0.0"
_BEFORE_PATTERN = re.compile(
    r"(?:prior\s+to|before)\s+version\s+"
    r"(\d+(?:\.\d+)*)"
)


def extract_version_ranges(description: str) -> list[VersionRange]:
    """Parse version ranges from advisory description text.

    Recognizes patterns like:
      - "prior to version X.Y.Z"
      - "before version X.Y.Z"
      - "starting in version X.Y.Z and prior to version A.B.C"
      - "from X.Y.Z to before A.B.C"
      - "versions X.Y.Z through A.B.C"

    Returns an empty list if no version ranges are found.
    """
    ranges: list[VersionRange] = []
    remaining_text = description

    for pattern, both_bounds in [
        (_RANGE_PATTERN, True),
        (_FROM_PATTERN, True),
        (_THROUGH_PATTERN, True),
    ]:
        matches = list(pattern.finditer(remaining_text))
        for match in matches:
            if both_bounds:
                ranges.append(VersionRange(match.group(1), match.group(2)))
            remaining_text = (
                remaining_text[: match.start()]
                + " " * (match.end() - match.start())
                + remaining_text[match.end() :]
            )

    for match in _BEFORE_PATTERN.finditer(remaining_text):
        ranges.append(VersionRange(None, match.group(1)))

    return ranges


def is_version_affected(
    version_str: str,
    ranges: list[VersionRange],
) -> bool:
    """Check if a version falls within any of the given ranges.

    Tries PEP 440 comparison first, falls back to semver
    if PEP 440 parsing fails.
    """
    try:
        version = Version(version_str)
    except InvalidVersion:
        try:
            semver_version = semver.Version.parse(version_str)
        except ValueError:
            return False

        for r in ranges:
            lower_ok = True
            upper_ok = True
            if r.introduced is not None:
                try:
                    introduced = semver.Version.parse(r.introduced)
                    lower_ok = semver_version >= introduced
                except ValueError:
                    continue
            if r.fixed is not None:
                try:
                    fixed = semver.Version.parse(r.fixed)
                    upper_ok = semver_version < fixed
                except ValueError:
                    continue
            if lower_ok and upper_ok:
                return True
        return False

    for r in ranges:
        lower_ok = True
        upper_ok = True
        if r.introduced is not None:
            try:
                lower_ok = version >= Version(r.introduced)
            except InvalidVersion:
                continue
        if r.fixed is not None:
            try:
                upper_ok = version < Version(r.fixed)
            except InvalidVersion:
                continue
        if lower_ok and upper_ok:
            return True
    return False


def purl_package_name(purl: str) -> str | None:
    """Extract the unversioned package name from a PURL.

    'pkg:pypi/urllib3@2.6.2' -> 'urllib3'
    'pkg:pypi/my-package@1.0' -> 'my-package'
    """
    if not purl.startswith("pkg:"):
        return None
    without_scheme = purl[4:]
    name_part = without_scheme.split("@")[0]
    return name_part.rsplit("/", 1)[-1]


def purl_full_name(purl: str) -> str | None:
    """Extract full package name from PURL, preserving scope.

    'pkg:pypi/urllib3@2.6.2' -> 'urllib3'
    'pkg:npm/%40angular/core@17.0.0' -> '@angular/core'
    'pkg:npm/lodash@4.17.21' -> 'lodash'
    """
    if not purl.startswith("pkg:"):
        return None
    purl = purl.split("?", 1)[0]
    purl = purl.split("#", 1)[0]
    without_scheme = purl[4:]
    slash_idx = without_scheme.find("/")
    if slash_idx < 0:
        return None
    name_ver = without_scheme[slash_idx + 1 :]
    decoded = name_ver.replace("%40", "@")
    if "@" not in decoded:
        return decoded
    return decoded.rsplit("@", 1)[0]


def purl_version(purl: str) -> str | None:
    """Extract the version from a PURL.

    'pkg:pypi/urllib3@2.6.2' -> '2.6.2'
    """
    if "@" not in purl:
        return None
    version = purl.split("@", 1)[1]
    version = version.split("?", 1)[0]
    version = version.split("#", 1)[0]
    return version
