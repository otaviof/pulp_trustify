from __future__ import annotations

import pytest

from pulp_trustify.purl import url_to_purl
from pulp_trustify.purl.npm import parse_npm_content, parse_npm_url


@pytest.mark.parametrize(
    "url,expected",
    [
        # Unscoped packages
        ("lodash/-/lodash-4.17.21.tgz", "pkg:npm/lodash@4.17.21"),
        # Scoped packages
        (
            "@angular/core/-/core-17.0.0.tgz",
            "pkg:npm/%40angular/core@17.0.0",
        ),
        # Full path unscoped
        (
            "/pulp/content/npm-registry/lodash/-/lodash-4.17.21.tgz",
            "pkg:npm/lodash@4.17.21",
        ),
        # Full path scoped
        (
            "/pulp/content/npm-registry/@angular/core/-/core-17.0.0.tgz",
            "pkg:npm/%40angular/core@17.0.0",
        ),
        # Pre-release version
        (
            "express/-/express-5.0.0-alpha.1.tgz",
            "pkg:npm/express@5.0.0-alpha.1",
        ),
        # Scoped pre-release
        ("@types/node/-/node-20.10.0.tgz", "pkg:npm/%40types/node@20.10.0"),
        # NOT an NPM tarball (no /-/)
        ("lodash-4.17.21.tgz", None),
        # NOT a .tgz file
        ("lodash/-/lodash-4.17.21.whl", None),
    ],
)
def test_url_to_purl_npm(url: str, expected: str | None):
    """Test NPM URL parser via url_to_purl() registry."""
    assert url_to_purl(url) == expected


@pytest.mark.parametrize(
    "url,expected",
    [
        ("lodash/-/lodash-4.17.21.tgz", "pkg:npm/lodash@4.17.21"),
        (
            "@angular/core/-/core-17.0.0.tgz",
            "pkg:npm/%40angular/core@17.0.0",
        ),
        ("express/-/express-5.0.0-alpha.1.tgz", "pkg:npm/express@5.0.0-alpha.1"),
        ("@types/node/-/node-20.10.0.tgz", "pkg:npm/%40types/node@20.10.0"),
        ("lodash-4.17.21.tgz", None),
        ("lodash/-/lodash-4.17.21.whl", None),
    ],
)
def test_parse_npm_url_direct(url: str, expected: str | None):
    """Test parse_npm_url() directly."""
    assert parse_npm_url(url) == expected


def _make_npm_content(name: str, version: str):
    """Create mock npm Package with correct module path."""

    class MockPackage:
        pass

    MockPackage.__module__ = "pulp_npm.app.models"
    obj = MockPackage()
    obj.name = name
    obj.version = version
    return obj


@pytest.mark.parametrize(
    "name,version,expected",
    [
        ("lodash", "4.17.21", "pkg:npm/lodash@4.17.21"),
        ("@angular/core", "17.0.0", "pkg:npm/%40angular/core@17.0.0"),
        ("@types/node", "20.10.0", "pkg:npm/%40types/node@20.10.0"),
    ],
)
def test_content_to_purl_npm(name: str, version: str, expected: str | None):
    """Test NPM content parser."""
    content = _make_npm_content(name, version)
    assert parse_npm_content(content) == expected


def test_content_to_purl_npm_none_name():
    """Return None when name is missing."""

    class MockPackage:
        pass

    MockPackage.__module__ = "pulp_npm.app.models"
    obj = MockPackage()
    obj.version = "1.0.0"
    assert parse_npm_content(obj) is None


def test_content_to_purl_npm_none_version():
    """Return None when version is missing."""

    class MockPackage:
        pass

    MockPackage.__module__ = "pulp_npm.app.models"
    obj = MockPackage()
    obj.name = "lodash"
    assert parse_npm_content(obj) is None


def test_content_to_purl_npm_empty_name():
    """Return None when name is empty."""
    content = _make_npm_content("", "1.0.0")
    assert parse_npm_content(content) is None


def test_content_to_purl_npm_empty_version():
    """Return None when version is empty."""
    content = _make_npm_content("lodash", "")
    assert parse_npm_content(content) is None


def test_content_to_purl_npm_wrong_module():
    """Return None when content is not from pulp_npm module."""

    class MockPackage:
        pass

    MockPackage.__module__ = "pulp_python.app.models"
    obj = MockPackage()
    obj.name = "lodash"
    obj.version = "4.17.21"
    assert parse_npm_content(obj) is None
