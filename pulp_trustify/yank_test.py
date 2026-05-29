from __future__ import annotations

import json
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from pulp_trustify.yank import (
    YankMiddleware,
    _build_yanked_reason,
    _href_to_filename,
    _inject_yanked_html,
    _inject_yanked_json,
)

TRUSTIFY_URL = "https://trustify.example.com"
CVE_1 = "CVE-2026-21441"
CVE_2 = "CVE-2026-44432"


def _make_settings(**overrides):
    defaults = {
        "TRUSTIFY_YANK_VULNERABLE": True,
        "TRUSTIFY_URL": TRUSTIFY_URL,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


@pytest.fixture
def html_sample() -> bytes:
    return b"""<!DOCTYPE html>
<html>
  <head><title>Links for urllib3</title></head>
  <body>
    <h1>Links for urllib3</h1>
    <a href="urllib3-2.6.2-py3-none-any.whl#sha256=abc123">link</a>
    <a href="six-1.17.0-py2.py3-none-any.whl#sha256=def456">link</a>
  </body>
</html>"""


@pytest.fixture
def json_sample() -> bytes:
    return json.dumps(
        {
            "meta": {"api-version": "1.0"},
            "name": "urllib3",
            "files": [
                {
                    "filename": "urllib3-2.6.2-py3-none-any.whl",
                    "url": "urllib3-2.6.2-py3-none-any.whl#sha256=abc123",
                },
                {
                    "filename": "six-1.17.0-py2.py3-none-any.whl",
                    "url": "six-1.17.0-py2.py3-none-any.whl#sha256=def456",
                },
            ],
        }
    ).encode("utf-8")


@dataclass
class MockRequest:
    path: str


@dataclass
class MockResponse:
    status_code: int
    content: bytes
    headers: dict[str, str]

    def get(self, key: str, default: str = "") -> str:
        return self.headers.get(key, default)


URL_1 = f"{TRUSTIFY_URL}/vulnerabilities/{CVE_1}"
URL_2 = f"{TRUSTIFY_URL}/vulnerabilities/{CVE_2}"


_P = "Vulnerable package flagged by Trustify"


@pytest.mark.parametrize(
    "labels,expected",
    [
        (
            {
                "trustify.vulnerable": "true",
                "trustify.cves": f"{CVE_1} {CVE_2}",
            },
            f"{_P}:\n- {URL_1}\n- {URL_2}",
        ),
        (
            {
                "trustify.vulnerable": "true",
                "trustify.cves": CVE_1,
            },
            f"{_P}: {URL_1}",
        ),
        (
            {
                "trustify.vulnerable": "true",
                "trustify.cves": "",
            },
            None,
        ),
        ({"trustify.vulnerable": "true"}, None),
        (
            {
                "trustify.vulnerable": "false",
                "trustify.cves": CVE_1,
            },
            None,
        ),
        ({}, None),
        ({"trustify.cves": CVE_1}, None),
    ],
)
def test_build_yanked_reason(labels: dict[str, str], expected: str | None):
    result = _build_yanked_reason(labels, TRUSTIFY_URL)
    assert result == expected


def test_build_yanked_reason_with_trailing_slash():
    labels = {
        "trustify.vulnerable": "true",
        "trustify.cves": CVE_1,
    }
    result = _build_yanked_reason(labels, f"{TRUSTIFY_URL}/")
    assert result == f"{_P}: {URL_1}"


def test_build_yanked_reason_max_cves_limits_output():
    labels = {
        "trustify.vulnerable": "true",
        "trustify.cves": (f"{CVE_1} {CVE_2} CVE-2026-99999"),
    }
    result = _build_yanked_reason(labels, TRUSTIFY_URL, max_cves=2)
    assert result == (f"{_P} (2 of 3 CVEs):\n- {URL_1}\n- {URL_2}")


def test_build_yanked_reason_max_cves_single():
    labels = {
        "trustify.vulnerable": "true",
        "trustify.cves": f"{CVE_1} {CVE_2}",
    }
    result = _build_yanked_reason(labels, TRUSTIFY_URL, max_cves=1)
    assert result == f"{_P} (1 of 2 CVEs): {URL_1}"


@pytest.mark.parametrize(
    "href,expected",
    [
        ("urllib3-2.6.2.whl", "urllib3-2.6.2.whl"),
        (
            "https://host/pulp/content/repo/urllib3-2.6.2.whl",
            "urllib3-2.6.2.whl",
        ),
        (
            "/pulp/content/repo/six-1.17.0.whl",
            "six-1.17.0.whl",
        ),
        ("file.whl?redirect=https://x", "file.whl"),
    ],
)
def test_href_to_filename(href: str, expected: str):
    assert _href_to_filename(href) == expected


@patch("pulp_trustify.yank._label_lookup")
def test_inject_yanked_html_full_urls(
    mock_lookup: Mock,
):
    """pulp_python emits full URLs in href attributes."""
    html = (
        b"<html><body>"
        b'<a href="https://host/pulp/content/repo/'
        b"urllib3-2.6.2-py3-none-any.whl#sha256=abc"
        b'" data-requires-python="&gt;=3.7"'
        b">urllib3-2.6.2-py3-none-any.whl</a>"
        b"</body></html>"
    )
    reason = URL_1
    mock_lookup.return_value = {
        "urllib3-2.6.2-py3-none-any.whl": reason,
    }

    result = _inject_yanked_html(html, "/simple/urllib3/")

    decoded = result.decode("utf-8")
    assert f'data-yanked="{reason}"' in decoded


@patch("pulp_trustify.yank._label_lookup")
def test_inject_yanked_html_adds_data_yanked(
    mock_lookup: Mock, html_sample: bytes
):
    reason = URL_1
    mock_lookup.return_value = {
        "urllib3-2.6.2-py3-none-any.whl": reason,
    }

    result = _inject_yanked_html(html_sample, "/simple/urllib3/")

    html = result.decode("utf-8")
    assert f'data-yanked="{reason}"' in html
    assert 'href="urllib3-2.6.2-py3-none-any.whl#sha256=abc123"' in html
    lines = html.splitlines()
    urllib3_line = [ln for ln in lines if "urllib3-2.6.2" in ln][0]
    six_line = [ln for ln in lines if "six-1.17.0" in ln][0]
    assert "data-yanked" in urllib3_line
    assert "data-yanked" not in six_line


@patch("pulp_trustify.yank._label_lookup")
def test_inject_yanked_html_escapes_quotes_in_reason(
    mock_lookup: Mock, html_sample: bytes
):
    mock_lookup.return_value = {
        "urllib3-2.6.2-py3-none-any.whl": 'CVE-123 "test"',
    }

    result = _inject_yanked_html(html_sample, "/simple/urllib3/")

    html = result.decode("utf-8")
    assert 'data-yanked="CVE-123 &quot;test&quot;"' in html


@patch("pulp_trustify.yank._label_lookup")
def test_inject_yanked_html_no_anchors(mock_lookup: Mock):
    html = b"<html><body>No anchors here</body></html>"
    result = _inject_yanked_html(html, "/simple/urllib3/")
    assert result == html
    mock_lookup.assert_not_called()


@patch("pulp_trustify.yank._label_lookup")
def test_inject_yanked_html_no_vulnerable_files(
    mock_lookup: Mock, html_sample: bytes
):
    mock_lookup.return_value = {}

    result = _inject_yanked_html(html_sample, "/simple/urllib3/")

    assert result == html_sample


@patch("pulp_trustify.yank._label_lookup")
def test_inject_yanked_html_mixed_vulnerable_and_clean(
    mock_lookup: Mock, html_sample: bytes
):
    reason = URL_1
    mock_lookup.return_value = {
        "urllib3-2.6.2-py3-none-any.whl": reason,
    }

    result = _inject_yanked_html(html_sample, "/simple/urllib3/")

    html = result.decode("utf-8")
    lines = html.splitlines()
    urllib3_line = [ln for ln in lines if "urllib3-2.6.2" in ln][0]
    six_line = [ln for ln in lines if "six-1.17.0" in ln][0]
    assert "data-yanked" in urllib3_line
    assert "data-yanked" not in six_line


@patch("pulp_trustify.yank._label_lookup")
def test_inject_yanked_html_skips_already_yanked(mock_lookup: Mock):
    html = b'<a href="file.whl" data-yanked="already yanked">link</a>'
    mock_lookup.return_value = {"file.whl": "new reason"}

    result = _inject_yanked_html(html, "/simple/urllib3/")

    assert result == html


@patch("pulp_trustify.yank._label_lookup")
def test_inject_yanked_json_adds_yanked_field(
    mock_lookup: Mock, json_sample: bytes
):
    reason = URL_1
    mock_lookup.return_value = {
        "urllib3-2.6.2-py3-none-any.whl": reason,
    }

    result = _inject_yanked_json(json_sample, "/simple/urllib3/")

    data = json.loads(result)
    assert data["files"][0]["yanked"] == reason
    assert "yanked" not in data["files"][1]


@patch("pulp_trustify.yank._label_lookup")
def test_inject_yanked_json_empty_files_array(mock_lookup: Mock):
    content = json.dumps({"meta": {"api-version": "1.0"}, "files": []})
    content_bytes = content.encode("utf-8")

    result = _inject_yanked_json(content_bytes, "/simple/urllib3/")

    assert result == content_bytes
    mock_lookup.assert_not_called()


@patch("pulp_trustify.yank._label_lookup")
def test_inject_yanked_json_no_files_key(mock_lookup: Mock):
    content = json.dumps({"meta": {"api-version": "1.0"}})
    content_bytes = content.encode("utf-8")

    result = _inject_yanked_json(content_bytes, "/simple/urllib3/")

    assert result == content_bytes
    mock_lookup.assert_not_called()


@patch("pulp_trustify.yank._label_lookup")
def test_inject_yanked_json_no_vulnerable_files(
    mock_lookup: Mock, json_sample: bytes
):
    mock_lookup.return_value = {}

    result = _inject_yanked_json(json_sample, "/simple/urllib3/")

    assert result == json_sample


@patch("pulp_trustify.yank._label_lookup")
def test_inject_yanked_json_mixed_vulnerable_and_clean(
    mock_lookup: Mock, json_sample: bytes
):
    reason = URL_1
    mock_lookup.return_value = {
        "urllib3-2.6.2-py3-none-any.whl": reason,
    }

    result = _inject_yanked_json(json_sample, "/simple/urllib3/")

    data = json.loads(result)
    assert len(data["files"]) == 2
    assert data["files"][0]["yanked"] == reason
    assert "yanked" not in data["files"][1]


@patch("pulp_trustify.yank._label_lookup")
def test_inject_yanked_json_files_without_filename(mock_lookup: Mock):
    content = json.dumps(
        {
            "meta": {"api-version": "1.0"},
            "files": [{"url": "some-url"}],
        }
    ).encode("utf-8")

    result = _inject_yanked_json(content, "/simple/urllib3/")

    assert result == content
    mock_lookup.assert_not_called()


def _make_middleware(get_response):
    mw = YankMiddleware.__new__(YankMiddleware)
    mw.get_response = get_response
    mw._available = True
    return mw


def test_middleware_injects_html():
    with (
        patch("pulp_trustify.yank._inject_yanked_html") as mock_inject,
        patch("pulp_trustify.yank.settings", _make_settings()),
    ):
        mock_inject.return_value = b"modified html"

        request = MockRequest(path="/simple/urllib3/")
        response = MockResponse(
            status_code=200,
            content=b"original html",
            headers={"Content-Type": "text/html"},
        )

        middleware = _make_middleware(lambda r: response)
        result = middleware(request)

        mock_inject.assert_called_once_with(b"original html", "/simple/urllib3/")
        assert result.content == b"modified html"


def test_middleware_injects_json():
    with (
        patch("pulp_trustify.yank._inject_yanked_json") as mock_inject,
        patch("pulp_trustify.yank.settings", _make_settings()),
    ):
        mock_inject.return_value = b"modified json"

        request = MockRequest(path="/simple/urllib3/")
        response = MockResponse(
            status_code=200,
            content=b"original json",
            headers={
                "Content-Type": "application/vnd.pypi.simple.v1+json",
            },
        )

        middleware = _make_middleware(lambda r: response)
        result = middleware(request)

        mock_inject.assert_called_once_with(b"original json", "/simple/urllib3/")
        assert result.content == b"modified json"


def test_middleware_skips_when_feature_disabled():
    with patch(
        "pulp_trustify.yank.settings",
        _make_settings(TRUSTIFY_YANK_VULNERABLE=False),
    ):
        request = MockRequest(path="/simple/urllib3/")
        response = MockResponse(
            status_code=200,
            content=b"original",
            headers={"Content-Type": "text/html"},
        )

        middleware = _make_middleware(lambda r: response)
        result = middleware(request)

        assert result.content == b"original"


def test_middleware_skips_non_simple_paths():
    with patch("pulp_trustify.yank.settings", _make_settings()):
        request = MockRequest(path="/api/v3/packages/")
        response = MockResponse(
            status_code=200,
            content=b"original",
            headers={"Content-Type": "text/html"},
        )

        middleware = _make_middleware(lambda r: response)
        result = middleware(request)

        assert result.content == b"original"


def test_middleware_skips_non_200_status():
    with patch("pulp_trustify.yank.settings", _make_settings()):
        request = MockRequest(path="/simple/urllib3/")
        response = MockResponse(
            status_code=404,
            content=b"not found",
            headers={"Content-Type": "text/html"},
        )

        middleware = _make_middleware(lambda r: response)
        result = middleware(request)

        assert result.content == b"not found"


def test_middleware_skips_unsupported_content_type():
    with patch("pulp_trustify.yank.settings", _make_settings()):
        request = MockRequest(path="/simple/urllib3/")
        response = MockResponse(
            status_code=200,
            content=b"original",
            headers={"Content-Type": "application/octet-stream"},
        )

        middleware = _make_middleware(lambda r: response)
        result = middleware(request)

        assert result.content == b"original"


def test_middleware_skips_when_pulp_python_unavailable():
    request = MockRequest(path="/simple/urllib3/")
    response = MockResponse(
        status_code=200,
        content=b"original",
        headers={"Content-Type": "text/html"},
    )

    mw = YankMiddleware.__new__(YankMiddleware)
    mw.get_response = lambda r: response
    mw._available = False
    result = mw(request)

    assert result.content == b"original"


def test_middleware_logs_exception_and_returns_original():
    with (
        patch("pulp_trustify.yank.logger") as mock_logger,
        patch("pulp_trustify.yank._inject_yanked_html") as mock_inject,
        patch("pulp_trustify.yank.settings", _make_settings()),
    ):
        mock_inject.side_effect = ValueError("test error")

        request = MockRequest(path="/simple/urllib3/")
        response = MockResponse(
            status_code=200,
            content=b"original html",
            headers={"Content-Type": "text/html"},
        )

        middleware = _make_middleware(lambda r: response)
        result = middleware(request)

        assert result.content == b"original html"
        mock_logger.exception.assert_called_once_with(
            "Failed to inject yanked attributes"
        )
