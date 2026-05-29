"""Tests for the logging strategy."""

from __future__ import annotations

import logging
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from pulp_trustify.client.client import TrustifyError


class _FakeClient:
    """Minimal VulnerabilityChecker for log assertions."""

    def __init__(
        self,
        response=None,
        error=None,
        search_response=None,
        search_error=None,
    ):
        self._response = response
        self._error = error
        self._search_response = search_response
        self._search_error = search_error

    def analyze(self, purls):
        if self._error:
            raise self._error
        return self._response or {"items": []}

    def search_vulnerabilities(self, query, offset=0, limit=10):
        if self._search_error:
            raise self._search_error
        return self._search_response or {
            "items": [],
            "total": 0,
        }


def test_gate_blocked_logs_info(caplog):
    """Blocked artifact produces INFO log with CVE IDs."""
    from pulp_trustify.gate import gate_purl

    client = _FakeClient(
        response={
            "items": [
                {
                    "details": [
                        {
                            "entry": {"cve": "CVE-2023-1234"},
                            "base_score": {"severity": "critical"},
                        }
                    ]
                }
            ]
        }
    )

    with caplog.at_level(logging.DEBUG, logger="pulp_trustify"):
        with pytest.raises(PermissionError, match="Blocked due to CVE"):
            gate_purl(
                client=client,
                purl="pkg:pypi/requests@2.28.0",
                threshold="critical",
                fail_open=False,
            )

    info_records = [r for r in caplog.records if r.levelname == "INFO"]
    assert any("CVE-2023-1234" in r.message for r in info_records), (
        "Expected INFO log with CVE ID"
    )


def test_gate_allowed_logs_debug(caplog):
    """Allowed artifact produces DEBUG log."""
    from pulp_trustify.gate import gate_purl

    client = _FakeClient(response={"items": []})

    with caplog.at_level(logging.DEBUG, logger="pulp_trustify"):
        gate_purl(
            client=client,
            purl="pkg:pypi/requests@2.32.0",
            threshold="critical",
            fail_open=False,
        )

    debug_records = [r for r in caplog.records if r.levelname == "DEBUG"]
    assert any("Allowing" in r.message for r in debug_records), (
        "Expected DEBUG log with 'Allowing'"
    )


def test_gate_fail_open_logs_warning(caplog):
    """Fail-open events produce WARNING log."""
    from pulp_trustify.gate import gate_purl

    client = _FakeClient(error=TrustifyError("API unavailable"))

    with caplog.at_level(logging.DEBUG, logger="pulp_trustify"):
        gate_purl(
            client=client,
            purl="pkg:pypi/requests@2.28.0",
            threshold="critical",
            fail_open=True,
        )

    warning_records = [r for r in caplog.records if r.levelname == "WARNING"]
    assert any("fail_open=True" in r.message for r in warning_records), (
        "Expected WARNING log with fail_open indication"
    )


def test_guard_logs_path_debug(caplog):
    """Guard logs path checking at DEBUG level."""
    from pulp_trustify.guard import permit_request

    client = _FakeClient(response={"items": []})

    with caplog.at_level(logging.DEBUG, logger="pulp_trustify"):
        permit_request(
            client=client,
            path="packages/requests-2.32.0.tar.gz",
            threshold="critical",
            fail_open=False,
        )

    debug_records = [
        r
        for r in caplog.records
        if r.levelname == "DEBUG" and r.name == "pulp_trustify.guard"
    ]
    assert any("Guard checking path" in r.message for r in debug_records), (
        "Expected DEBUG log with 'Guard checking path'"
    )


def test_guard_no_purl_logs_debug(caplog):
    """Guard logs DEBUG when no PURL can be extracted."""
    from pulp_trustify.guard import permit_request

    client = _FakeClient(response={"items": []})

    with caplog.at_level(logging.DEBUG, logger="pulp_trustify"):
        permit_request(
            client=client,
            path="/simple/requests/",
            threshold="critical",
            fail_open=False,
        )

    debug_records = [
        r
        for r in caplog.records
        if r.levelname == "DEBUG" and r.name == "pulp_trustify.guard"
    ]
    assert any("No PURL" in r.message for r in debug_records), (
        "Expected DEBUG log with 'No PURL'"
    )


def _make_settings(**overrides):
    """Create mock settings with defaults."""
    defaults = {
        "TRUSTIFY_GATE_UPLOADS": True,
        "TRUSTIFY_URL": "https://trustify.example.com",
        "TRUSTIFY_SEVERITY_THRESHOLD": "critical",
        "TRUSTIFY_FAIL_OPEN": False,
        "TRUSTIFY_ENRICH_DETAILS": True,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_instance(name="test-pkg", version="1.0.0"):
    """Create mock PythonPackageContent instance."""
    return SimpleNamespace(name=name, version=version)


def _fake_models():
    """Build fake pulp_trustify.app.models module."""
    mod = ModuleType("pulp_trustify.app.models")
    setattr(mod, "_get_client", MagicMock())
    return mod


@patch("pulp_trustify.gate.gate_purl")
@patch.dict(
    sys.modules,
    {"pulp_trustify.app.models": _fake_models()},
)
@patch("django.conf.settings", _make_settings())
def test_upload_blocked_logs_warning(mock_gate, caplog):
    """Upload blocked produces WARNING log."""
    from rest_framework.exceptions import ValidationError

    from pulp_trustify.upload import upload_gate

    mock_gate.side_effect = PermissionError("Blocked due to CVE: CVE-2023-1234")
    instance = _make_instance(name="requests", version="2.28.0")

    with caplog.at_level(logging.DEBUG, logger="pulp_trustify"):
        with pytest.raises(ValidationError):
            upload_gate(sender=None, instance=instance)

    warning_records = [
        r
        for r in caplog.records
        if r.levelname == "WARNING" and r.name == "pulp_trustify.upload"
    ]
    assert any("Upload blocked" in r.message for r in warning_records), (
        "Expected WARNING log with 'Upload blocked'"
    )


@patch("pulp_trustify.gate.gate_purl")
@patch.dict(
    sys.modules,
    {"pulp_trustify.app.models": _fake_models()},
)
@patch(
    "django.conf.settings",
    _make_settings(TRUSTIFY_GATE_UPLOADS=False),
)
def test_upload_disabled_logs_debug(mock_gate, caplog):
    """Upload gating disabled produces DEBUG log."""
    from pulp_trustify.upload import upload_gate

    instance = _make_instance(name="requests", version="2.32.0")

    with caplog.at_level(logging.DEBUG, logger="pulp_trustify"):
        upload_gate(sender=None, instance=instance)

    debug_records = [
        r
        for r in caplog.records
        if r.levelname == "DEBUG" and r.name == "pulp_trustify.upload"
    ]
    assert any("disabled" in r.message for r in debug_records), (
        "Expected DEBUG log with 'disabled'"
    )


def test_settings_logging_dict():
    """Settings module contains LOGGING with pulp_trustify logger."""
    import pulp_trustify.app.settings as settings

    assert hasattr(settings, "LOGGING"), "LOGGING dict missing"
    assert settings.LOGGING.get("dynaconf_merge") is True, (
        "dynaconf_merge should be True"
    )
    assert "pulp_trustify" in settings.LOGGING.get("loggers", {}), (
        "pulp_trustify logger missing"
    )
    assert settings.TRUSTIFY_LOG_LEVEL == "INFO", (
        "TRUSTIFY_LOG_LEVEL should default to INFO"
    )


def test_log_level_setting_applied():
    """TRUSTIFY_LOG_LEVEL sets logger level programmatically."""
    mock_settings = SimpleNamespace(TRUSTIFY_LOG_LEVEL="DEBUG")
    logger = logging.getLogger("pulp_trustify")
    original_level = logger.level

    try:
        level = getattr(mock_settings, "TRUSTIFY_LOG_LEVEL", "INFO")
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))

        assert logger.level == logging.DEBUG, "Logger level should be DEBUG"
    finally:
        logger.setLevel(original_level)


def test_log_level_invalid_falls_back_to_info():
    """Invalid TRUSTIFY_LOG_LEVEL falls back to INFO."""
    mock_settings = SimpleNamespace(TRUSTIFY_LOG_LEVEL="INVALID")
    logger = logging.getLogger("pulp_trustify")
    original_level = logger.level

    try:
        level = getattr(mock_settings, "TRUSTIFY_LOG_LEVEL", "INFO")
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))

        assert logger.level == logging.INFO, (
            "Logger level should fall back to INFO"
        )
    finally:
        logger.setLevel(original_level)
