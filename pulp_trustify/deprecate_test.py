from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch


def _make_settings(**overrides):
    """Create mock settings with defaults."""
    defaults = {
        "TRUSTIFY_DEPRECATE_VULNERABLE": True,
        "TRUSTIFY_URL": "https://trustify.example.com",
        "TRUSTIFY_SEVERITY_THRESHOLD": "critical",
        "TRUSTIFY_YANK_MAX_CVES": 3,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def test_inject_deprecated_single_vulnerable_version():
    """Packument with single vulnerable version gets deprecated field."""
    from pulp_trustify.deprecate import _inject_deprecated

    packument = {
        "name": "lodash",
        "versions": {
            "4.17.21": {
                "name": "lodash",
                "version": "4.17.21",
                "dist": {"tarball": "..."},
            },
        },
    }
    body = json.dumps(packument).encode("utf-8")

    with (
        patch("pulp_trustify.deprecate.lookup_vulnerable") as mock_lookup,
        patch("django.conf.settings", _make_settings()),
    ):
        mock_lookup.return_value = {
            "4.17.21": "Vulnerable package flagged by Trustify",
        }

        result = _inject_deprecated(body, "lodash")

    assert result is not None
    data = json.loads(result)
    assert "deprecated" in data["versions"]["4.17.21"]
    assert "Trustify" in data["versions"]["4.17.21"]["deprecated"]


def test_inject_deprecated_multiple_versions_partial_vulnerable():
    """Only vulnerable versions get deprecated field."""
    from pulp_trustify.deprecate import _inject_deprecated

    packument = {
        "name": "lodash",
        "versions": {
            "4.17.20": {"name": "lodash", "version": "4.17.20"},
            "4.17.21": {"name": "lodash", "version": "4.17.21"},
            "4.17.22": {"name": "lodash", "version": "4.17.22"},
        },
    }
    body = json.dumps(packument).encode("utf-8")

    with (
        patch("pulp_trustify.deprecate.lookup_vulnerable") as mock_lookup,
        patch("django.conf.settings", _make_settings()),
    ):
        mock_lookup.return_value = {
            "4.17.21": "Vulnerable",
        }

        result = _inject_deprecated(body, "lodash")

    assert result is not None
    data = json.loads(result)
    assert "deprecated" not in data["versions"]["4.17.20"]
    assert "deprecated" in data["versions"]["4.17.21"]
    assert "deprecated" not in data["versions"]["4.17.22"]


def test_inject_deprecated_no_vulnerable_versions():
    """Returns None when no versions are vulnerable."""
    from pulp_trustify.deprecate import _inject_deprecated

    packument = {
        "name": "lodash",
        "versions": {
            "4.17.21": {"name": "lodash", "version": "4.17.21"},
        },
    }
    body = json.dumps(packument).encode("utf-8")

    with (
        patch("pulp_trustify.deprecate.lookup_vulnerable") as mock_lookup,
        patch("django.conf.settings", _make_settings()),
    ):
        mock_lookup.return_value = {}

        result = _inject_deprecated(body, "lodash")

    assert result is None


def test_inject_deprecated_non_packument_no_versions_key():
    """Returns None when JSON lacks versions key."""
    from pulp_trustify.deprecate import _inject_deprecated

    body = json.dumps({"name": "lodash"}).encode("utf-8")

    result = _inject_deprecated(body, "lodash")

    assert result is None


def test_inject_deprecated_invalid_json():
    """Returns None when body is not valid JSON."""
    from pulp_trustify.deprecate import _inject_deprecated

    body = b"not json"

    result = _inject_deprecated(body, "lodash")

    assert result is None


def test_inject_deprecated_empty_versions():
    """Returns None when versions dict is empty."""
    from pulp_trustify.deprecate import _inject_deprecated

    packument = {
        "name": "lodash",
        "versions": {},
    }
    body = json.dumps(packument).encode("utf-8")

    result = _inject_deprecated(body, "lodash")

    assert result is None


def test_wrap_npm_content_handler_feature_disabled():
    """No-op when TRUSTIFY_DEPRECATE_VULNERABLE is False."""
    from pulp_trustify.deprecate import wrap_npm_content_handler

    with (
        patch(
            "django.conf.settings",
            _make_settings(TRUSTIFY_DEPRECATE_VULNERABLE=False),
        ),
        patch("pulp_trustify.deprecate.logger") as mock_logger,
    ):
        wrap_npm_content_handler()

        mock_logger.debug.assert_called_once_with("NPM deprecation disabled")


def test_wrap_npm_content_handler_pulp_npm_not_installed():
    """No-op when pulp_npm is not installed."""
    from pulp_trustify.deprecate import wrap_npm_content_handler

    with (
        patch("django.conf.settings", _make_settings()),
        patch("pulp_trustify.deprecate.logger") as mock_logger,
        patch.dict(
            "sys.modules",
            {"pulp_npm.app.models": None},
        ),
    ):
        wrap_npm_content_handler()

        assert any(
            "not installed" in str(call)
            for call in mock_logger.debug.call_args_list
        )


def test_wrap_npm_content_handler_wrapper_installed():
    """Wrapper replaces NpmDistribution.content_handler."""
    from pulp_trustify.deprecate import wrap_npm_content_handler

    mock_distribution = MagicMock()
    original_handler = Mock()
    mock_distribution.content_handler = original_handler

    mock_npm_models = MagicMock()
    mock_npm_models.NpmDistribution = mock_distribution

    with (
        patch("django.conf.settings", _make_settings()),
        patch.dict(
            "sys.modules",
            {"pulp_npm.app.models": mock_npm_models},
        ),
    ):
        wrap_npm_content_handler()

        assert mock_distribution.content_handler != original_handler, (
            "Handler should be wrapped"
        )


def test_wrapped_handler_non_json_response():
    """Wrapper passes through non-JSON responses unchanged."""
    from pulp_trustify.deprecate import wrap_npm_content_handler

    mock_response = Mock()
    mock_response.body = b"not json"
    mock_response.content_type = "text/html"

    original_handler = Mock(return_value=mock_response)

    mock_distribution = MagicMock()
    mock_distribution.content_handler = original_handler

    mock_npm_models = MagicMock()
    mock_npm_models.NpmDistribution = mock_distribution

    with (
        patch("django.conf.settings", _make_settings()),
        patch.dict(
            "sys.modules",
            {"pulp_npm.app.models": mock_npm_models},
        ),
    ):
        wrap_npm_content_handler()

        wrapped_handler = mock_distribution.content_handler
        instance = Mock()
        result = wrapped_handler(instance, "lodash")

        assert result == mock_response


def test_wrapped_handler_injects_deprecated():
    """Wrapper injects deprecated fields for vulnerable versions."""
    from pulp_trustify.deprecate import wrap_npm_content_handler

    packument = {
        "name": "lodash",
        "versions": {
            "4.17.21": {"name": "lodash", "version": "4.17.21"},
        },
    }

    mock_response = Mock()
    mock_response.body = json.dumps(packument).encode("utf-8")
    mock_response.content_type = "application/json"
    mock_response.status = 200

    original_handler = Mock(return_value=mock_response)

    mock_distribution = MagicMock()
    mock_distribution.content_handler = original_handler

    mock_npm_models = MagicMock()
    mock_npm_models.NpmDistribution = mock_distribution

    with (
        patch("django.conf.settings", _make_settings()),
        patch.dict(
            "sys.modules",
            {"pulp_npm.app.models": mock_npm_models},
        ),
        patch("pulp_trustify.deprecate.lookup_vulnerable") as mock_lookup,
    ):
        mock_lookup.return_value = {
            "4.17.21": "Vulnerable",
        }

        wrap_npm_content_handler()

        wrapped_handler = mock_distribution.content_handler
        instance = Mock()
        result = wrapped_handler(instance, "lodash")

        assert result.status == 200
        data = json.loads(result.body)
        assert "deprecated" in data["versions"]["4.17.21"]


def test_wrapped_handler_exception_returns_original():
    """Wrapper returns original response on exception."""
    from pulp_trustify.deprecate import wrap_npm_content_handler

    mock_response = Mock()
    mock_response.body = b"{}"
    mock_response.content_type = "application/json"

    original_handler = Mock(return_value=mock_response)

    mock_distribution = MagicMock()
    mock_distribution.content_handler = original_handler

    mock_npm_models = MagicMock()
    mock_npm_models.NpmDistribution = mock_distribution

    with (
        patch("django.conf.settings", _make_settings()),
        patch.dict(
            "sys.modules",
            {"pulp_npm.app.models": mock_npm_models},
        ),
        patch("pulp_trustify.deprecate._inject_deprecated") as mock_inject,
        patch("pulp_trustify.deprecate.logger") as mock_logger,
    ):
        mock_inject.side_effect = ValueError("test error")

        wrap_npm_content_handler()

        wrapped_handler = mock_distribution.content_handler
        instance = Mock()
        result = wrapped_handler(instance, "lodash")

        assert result == mock_response
        mock_logger.exception.assert_called_once()


def test_wrapped_handler_text_plain_content_type():
    """Wrapper processes text/plain responses (pulp_npm behavior)."""
    from pulp_trustify.deprecate import wrap_npm_content_handler

    packument = {
        "name": "lodash",
        "versions": {
            "4.17.21": {"name": "lodash", "version": "4.17.21"},
        },
    }

    mock_response = Mock()
    mock_response.body = json.dumps(packument).encode("utf-8")
    mock_response.content_type = "text/plain"
    mock_response.status = 200

    original_handler = Mock(return_value=mock_response)

    mock_distribution = MagicMock()
    mock_distribution.content_handler = original_handler

    mock_npm_models = MagicMock()
    mock_npm_models.NpmDistribution = mock_distribution

    with (
        patch("django.conf.settings", _make_settings()),
        patch.dict(
            "sys.modules",
            {"pulp_npm.app.models": mock_npm_models},
        ),
        patch("pulp_trustify.deprecate.lookup_vulnerable") as mock_lookup,
    ):
        mock_lookup.return_value = {
            "4.17.21": "Vulnerable",
        }

        wrap_npm_content_handler()

        wrapped_handler = mock_distribution.content_handler
        instance = Mock()
        result = wrapped_handler(instance, "lodash")

        assert result.status == 200
        data = json.loads(result.body)
        assert "deprecated" in data["versions"]["4.17.21"]


def test_wrapped_handler_string_payload_body():
    """Wrapper extracts ._value from StringPayload objects."""
    from pulp_trustify.deprecate import wrap_npm_content_handler

    packument = {
        "name": "lodash",
        "versions": {
            "4.17.21": {"name": "lodash", "version": "4.17.21"},
        },
    }

    mock_payload = Mock()
    mock_payload._value = json.dumps(packument).encode("utf-8")

    mock_response = Mock()
    mock_response.body = mock_payload
    mock_response.content_type = "application/json"
    mock_response.status = 200

    original_handler = Mock(return_value=mock_response)

    mock_distribution = MagicMock()
    mock_distribution.content_handler = original_handler

    mock_npm_models = MagicMock()
    mock_npm_models.NpmDistribution = mock_distribution

    with (
        patch("django.conf.settings", _make_settings()),
        patch.dict(
            "sys.modules",
            {"pulp_npm.app.models": mock_npm_models},
        ),
        patch("pulp_trustify.deprecate.lookup_vulnerable") as mock_lookup,
    ):
        mock_lookup.return_value = {
            "4.17.21": "Vulnerable",
        }

        wrap_npm_content_handler()

        wrapped_handler = mock_distribution.content_handler
        instance = Mock()
        result = wrapped_handler(instance, "lodash")

        assert result.status == 200
        data = json.loads(result.body)
        assert "deprecated" in data["versions"]["4.17.21"]
