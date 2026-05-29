from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


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
def test_blocks_vulnerable_upload(mock_gate):
    """Raise ValidationError on PermissionError from gate."""
    from rest_framework.exceptions import ValidationError

    from pulp_trustify.upload import upload_gate

    mock_gate.side_effect = PermissionError("Blocked due to CVE-2023-1234")
    instance = _make_instance(name="requests", version="2.28.0")

    with pytest.raises(
        ValidationError,
        match="Blocked due to CVE-2023-1234",
    ):
        upload_gate(sender=None, instance=instance)


@patch("pulp_trustify.gate.gate_purl")
@patch.dict(
    sys.modules,
    {"pulp_trustify.app.models": _fake_models()},
)
@patch("django.conf.settings", _make_settings())
def test_allows_clean_upload(mock_gate):
    """Allow upload when gate_purl does not raise."""
    from pulp_trustify.upload import upload_gate

    instance = _make_instance(name="requests", version="2.32.0")

    upload_gate(sender=None, instance=instance)

    mock_gate.assert_called_once()


@patch("pulp_trustify.gate.gate_purl")
@patch.dict(
    sys.modules,
    {"pulp_trustify.app.models": _fake_models()},
)
@patch(
    "django.conf.settings",
    _make_settings(TRUSTIFY_GATE_UPLOADS=False),
)
def test_noop_when_gating_disabled(mock_gate):
    """Skip gating when TRUSTIFY_GATE_UPLOADS is False."""
    from pulp_trustify.upload import upload_gate

    instance = _make_instance(name="requests", version="2.32.0")

    upload_gate(sender=None, instance=instance)

    mock_gate.assert_not_called()


@patch("pulp_trustify.gate.gate_purl")
@patch.dict(
    sys.modules,
    {"pulp_trustify.app.models": _fake_models()},
)
@patch(
    "django.conf.settings",
    _make_settings(TRUSTIFY_URL=""),
)
def test_noop_when_url_empty(mock_gate):
    """Skip gating when TRUSTIFY_URL is empty."""
    from pulp_trustify.upload import upload_gate

    instance = _make_instance(name="requests", version="2.32.0")

    upload_gate(sender=None, instance=instance)

    mock_gate.assert_not_called()


@patch("pulp_trustify.gate.gate_purl")
@patch.dict(
    sys.modules,
    {"pulp_trustify.app.models": _fake_models()},
)
@patch("django.conf.settings", _make_settings())
def test_noop_when_name_empty(mock_gate):
    """Skip gating when instance name is empty."""
    from pulp_trustify.upload import upload_gate

    instance = _make_instance(name="", version="1.0.0")

    upload_gate(sender=None, instance=instance)

    mock_gate.assert_not_called()


@patch("pulp_trustify.gate.gate_purl")
@patch.dict(
    sys.modules,
    {"pulp_trustify.app.models": _fake_models()},
)
@patch("django.conf.settings", _make_settings())
def test_noop_when_version_empty(mock_gate):
    """Skip gating when instance version is empty."""
    from pulp_trustify.upload import upload_gate

    instance = _make_instance(name="test-pkg", version="")

    upload_gate(sender=None, instance=instance)

    mock_gate.assert_not_called()


@patch("pulp_trustify.gate.gate_purl")
@patch.dict(
    sys.modules,
    {"pulp_trustify.app.models": _fake_models()},
)
@patch("django.conf.settings", _make_settings())
def test_purl_normalization(mock_gate):
    """Normalize package name per PEP 503."""
    from pulp_trustify.upload import upload_gate

    instance = _make_instance(name="My_Package", version="1.0")

    upload_gate(sender=None, instance=instance)

    mock_gate.assert_called_once()
    call_args = mock_gate.call_args
    assert call_args.kwargs["purl"] == "pkg:pypi/my-package@1.0"
