from __future__ import annotations

import pytest

import pulp_trustify.purl.pypi  # noqa: F401
from pulp_trustify.purl import url_to_purl


@pytest.mark.parametrize(
    "url,expected",
    [
        (
            "requests-2.28.0-py3-none-any.whl",
            "pkg:pypi/requests@2.28.0",
        ),
        ("requests-2.28.0.tar.gz", "pkg:pypi/requests@2.28.0"),
        ("urllib3-1.26.5.zip", "pkg:pypi/urllib3@1.26.5"),
        ("Jinja2-3.1.2.tar.gz", "pkg:pypi/jinja2@3.1.2"),
        ("my_package-1.0.tar.gz", "pkg:pypi/my-package@1.0"),
        ("zope.interface-5.4.0.tar.gz", "pkg:pypi/zope-interface@5.4.0"),
        (
            "/packages/source/r/requests/requests-2.28.0.tar.gz",
            "pkg:pypi/requests@2.28.0",
        ),
        ("/simple/requests/", None),
        ("/foo/bar.txt", None),
        ("unknown-file.pdf", None),
    ],
)
def test_url_to_purl_pypi(url: str, expected: str | None):
    """Test PyPI PURL extraction from various URL formats."""
    assert url_to_purl(url) == expected


def test_wheel_with_build_tag():
    """Verify wheels with build tags parse correctly."""
    url = "numpy-1.24.0-1-cp311-cp311-linux_x86_64.whl"
    expected = "pkg:pypi/numpy@1.24.0"
    assert url_to_purl(url) == expected


def test_sdist_with_complex_version():
    """Verify sdists with complex versions parse correctly."""
    url = "package-1.0.0rc1.tar.gz"
    expected = "pkg:pypi/package@1.0.0rc1"
    assert url_to_purl(url) == expected


def test_mixed_separators_normalize():
    """Verify names with mixed separators normalize to hyphens."""
    url = "my_long.package_name-2.0.0.tar.gz"
    expected = "pkg:pypi/my-long-package-name@2.0.0"
    assert url_to_purl(url) == expected
