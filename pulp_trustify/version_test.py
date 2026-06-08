from __future__ import annotations

import pytest

from pulp_trustify.version import (
    VersionRange,
    extract_version_ranges,
    is_version_affected,
    purl_full_name,
    purl_package_name,
    purl_version,
)


@pytest.mark.parametrize(
    ("description", "expected"),
    [
        (
            "Starting in version 1.22 and prior to version 2.6.3",
            [VersionRange("1.22", "2.6.3")],
        ),
        (
            "prior to version 2.6.3",
            [VersionRange(None, "2.6.3")],
        ),
        (
            "before version 3.0.0",
            [VersionRange(None, "3.0.0")],
        ),
        (
            "versions 1.0 through 2.0",
            [VersionRange("1.0", "2.0")],
        ),
        (
            "No version info here",
            [],
        ),
        (
            "Starting in version 1.22 and prior to version 2.6.3. "
            "Also prior to version 1.21.7 in the 1.x series",
            [VersionRange("1.22", "2.6.3"), VersionRange(None, "1.21.7")],
        ),
        (
            "From 1.23 to before 2.7.0, cross-origin redirects",
            [VersionRange("1.23", "2.7.0")],
        ),
        (
            "From 2.6.0 to before 2.7.0, urllib3 could decompress",
            [VersionRange("2.6.0", "2.7.0")],
        ),
    ],
)
def test_extract_version_ranges(description, expected):
    assert extract_version_ranges(description) == expected


@pytest.mark.parametrize(
    ("version_str", "ranges", "expected"),
    [
        ("2.6.2", [VersionRange("1.22", "2.6.3")], True),
        ("2.6.3", [VersionRange("1.22", "2.6.3")], False),
        ("1.21", [VersionRange("1.22", "2.6.3")], False),
        ("1.22", [VersionRange("1.22", "2.6.3")], True),
        ("2.6.2", [VersionRange(None, "2.6.3")], True),
        ("2.6.3", [VersionRange(None, "2.6.3")], False),
        ("2.7.0", [VersionRange("1.22", None)], True),
        ("not.a.version", [VersionRange("1.0", "2.0")], False),
        ("1.5.0", [], False),
        # Semver versions (not valid PEP 440, should use semver fallback)
        ("1.0.0-alpha.1", [VersionRange("0.9.0", "2.0.0")], True),
        ("1.0.0-rc.1", [VersionRange("1.0.0-alpha.1", "1.0.0")], True),
        ("1.0.0+build.123", [VersionRange("0.9.0", "2.0.0")], True),
        ("0.8.0", [VersionRange("0.9.0", "2.0.0")], False),
    ],
)
def test_is_version_affected(version_str, ranges, expected):
    assert is_version_affected(version_str, ranges) == expected


@pytest.mark.parametrize(
    ("purl", "expected_name", "expected_version"),
    [
        ("pkg:pypi/urllib3@2.6.2", "urllib3", "2.6.2"),
        ("pkg:pypi/my-package@1.0", "my-package", "1.0"),
        ("pkg:maven/org.example/foo@1.0", "foo", "1.0"),
        ("pkg:pypi/foo@1.0?vcs_url=git", "foo", "1.0"),
        ("pkg:pypi/foo@1.0#sub/path", "foo", "1.0"),
        ("not-a-purl", None, None),
    ],
)
def test_purl_parsing(purl, expected_name, expected_version):
    assert purl_package_name(purl) == expected_name
    assert purl_version(purl) == expected_version


@pytest.mark.parametrize(
    "purl,expected",
    [
        ("pkg:pypi/urllib3@2.6.2", "urllib3"),
        ("pkg:npm/lodash@4.17.21", "lodash"),
        ("pkg:npm/%40angular/core@17.0.0", "@angular/core"),
        ("pkg:npm/%40types/node@20.10.0", "@types/node"),
        ("pkg:pypi/foo@1.0?vcs_url=git", "foo"),
        ("pkg:pypi/foo@1.0#sub/path", "foo"),
        ("not-a-purl", None),
    ],
)
def test_purl_full_name(purl: str, expected: str | None):
    assert purl_full_name(purl) == expected
