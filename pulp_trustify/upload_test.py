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
        "TRUSTIFY_GATE_LABEL_CONTENT": True,
        "TRUSTIFY_GATE_ADVISORY": True,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_instance(name="test-pkg", version="1.0.0"):
    """Create mock PythonPackageContent instance."""
    inst = SimpleNamespace(name=name, version=version)
    inst.pulp_labels = {}
    return inst


def _fake_models():
    """Build fake pulp_trustify.app.models module."""
    mod = ModuleType("pulp_trustify.app.models")
    setattr(mod, "_get_client", MagicMock())
    gate_advisory = MagicMock()
    gate_advisory.objects = MagicMock()
    setattr(mod, "GateAdvisory", gate_advisory)
    return mod


@patch("pulp_trustify.gate.check_purl_with_mode")
@patch.dict(
    sys.modules,
    {"pulp_trustify.app.models": _fake_models()},
)
@patch("django.conf.settings", _make_settings())
def test_blocks_vulnerable_upload(mock_check):
    """Raise ValidationError when check returns CVEs."""
    from rest_framework.exceptions import ValidationError

    from pulp_trustify.gate import GateResult
    from pulp_trustify.upload import upload_gate

    mock_check.return_value = GateResult(cve_ids=["CVE-2023-1234"])
    instance = _make_instance(name="requests", version="2.28.0")

    with pytest.raises(
        ValidationError,
        match="CVE-2023-1234",
    ):
        upload_gate(sender=None, instance=instance)


@patch("pulp_trustify.gate.check_purl_with_mode")
@patch.dict(
    sys.modules,
    {"pulp_trustify.app.models": _fake_models()},
)
@patch("django.conf.settings", _make_settings())
def test_allows_clean_upload(mock_check):
    """Allow upload when check returns clean result."""
    from pulp_trustify.gate import GateResult
    from pulp_trustify.upload import upload_gate

    mock_check.return_value = GateResult()
    instance = _make_instance(name="requests", version="2.32.0")

    upload_gate(sender=None, instance=instance)

    mock_check.assert_called_once()


@patch("pulp_trustify.gate.check_purl_with_mode")
@patch.dict(
    sys.modules,
    {"pulp_trustify.app.models": _fake_models()},
)
@patch(
    "django.conf.settings",
    _make_settings(TRUSTIFY_GATE_UPLOADS=False),
)
def test_noop_when_gating_disabled(mock_check):
    """Skip gating when TRUSTIFY_GATE_UPLOADS is False."""
    from pulp_trustify.upload import upload_gate

    instance = _make_instance(name="requests", version="2.32.0")

    upload_gate(sender=None, instance=instance)

    mock_check.assert_not_called()


@patch("pulp_trustify.gate.check_purl_with_mode")
@patch.dict(
    sys.modules,
    {"pulp_trustify.app.models": _fake_models()},
)
@patch(
    "django.conf.settings",
    _make_settings(TRUSTIFY_URL=""),
)
def test_noop_when_url_empty(mock_check):
    """Skip gating when TRUSTIFY_URL is empty."""
    from pulp_trustify.upload import upload_gate

    instance = _make_instance(name="requests", version="2.32.0")

    upload_gate(sender=None, instance=instance)

    mock_check.assert_not_called()


@patch("pulp_trustify.gate.check_purl_with_mode")
@patch.dict(
    sys.modules,
    {"pulp_trustify.app.models": _fake_models()},
)
@patch("django.conf.settings", _make_settings())
def test_noop_when_name_empty(mock_check):
    """Skip gating when instance name is empty."""
    from pulp_trustify.upload import upload_gate

    instance = _make_instance(name="", version="1.0.0")

    upload_gate(sender=None, instance=instance)

    mock_check.assert_not_called()


@patch("pulp_trustify.gate.check_purl_with_mode")
@patch.dict(
    sys.modules,
    {"pulp_trustify.app.models": _fake_models()},
)
@patch("django.conf.settings", _make_settings())
def test_noop_when_version_empty(mock_check):
    """Skip gating when instance version is empty."""
    from pulp_trustify.upload import upload_gate

    instance = _make_instance(name="test-pkg", version="")

    upload_gate(sender=None, instance=instance)

    mock_check.assert_not_called()


@patch("pulp_trustify.gate.check_purl_with_mode")
@patch.dict(
    sys.modules,
    {"pulp_trustify.app.models": _fake_models()},
)
@patch("django.conf.settings", _make_settings())
def test_purl_normalization(mock_check):
    """Normalize package name per PEP 503."""
    from pulp_trustify.gate import GateResult
    from pulp_trustify.upload import upload_gate

    mock_check.return_value = GateResult()
    instance = _make_instance(name="My_Package", version="1.0")

    upload_gate(sender=None, instance=instance)

    mock_check.assert_called_once()
    call_args = mock_check.call_args
    assert call_args.kwargs["purl"] == "pkg:pypi/my-package@1.0"


def _make_npm_instance(name="lodash", version="4.17.21"):
    """Create mock NPM Package instance."""

    class MockPackage:
        pass

    MockPackage.__module__ = "pulp_npm.app.models"
    obj = MockPackage()
    obj.name = name
    obj.version = version
    obj.pulp_labels = {}
    return obj


@patch("pulp_trustify.gate.check_purl_with_mode")
@patch.dict(
    sys.modules,
    {"pulp_trustify.app.models": _fake_models()},
)
@patch("django.conf.settings", _make_settings())
def test_npm_upload_gating(mock_check):
    """NPM content gets pkg:npm PURL and is checked."""
    from pulp_trustify.gate import GateResult
    from pulp_trustify.upload import upload_gate

    mock_check.return_value = GateResult()
    instance = _make_npm_instance(name="lodash", version="4.17.21")

    upload_gate(sender=None, instance=instance)

    mock_check.assert_called_once()
    call_args = mock_check.call_args
    assert call_args.kwargs["purl"] == "pkg:npm/lodash@4.17.21"


@patch("pulp_trustify.gate.check_purl_with_mode")
@patch.dict(
    sys.modules,
    {"pulp_trustify.app.models": _fake_models()},
)
@patch("django.conf.settings", _make_settings())
def test_npm_upload_scoped_package(mock_check):
    """Scoped NPM package gets correct PURL with %40."""
    from pulp_trustify.gate import GateResult
    from pulp_trustify.upload import upload_gate

    mock_check.return_value = GateResult()
    instance = _make_npm_instance(name="@angular/core", version="17.0.0")

    upload_gate(sender=None, instance=instance)

    mock_check.assert_called_once()
    call_args = mock_check.call_args
    assert call_args.kwargs["purl"] == "pkg:npm/%40angular/core@17.0.0"


@patch("pulp_trustify.gate.check_purl_with_mode")
@patch.dict(
    sys.modules,
    {"pulp_trustify.app.models": _fake_models()},
)
@patch("django.conf.settings", _make_settings())
def test_npm_upload_blocks_vulnerable(mock_check):
    """NPM upload raises ValidationError when check returns CVEs."""
    from rest_framework.exceptions import ValidationError

    from pulp_trustify.gate import GateResult
    from pulp_trustify.upload import upload_gate

    mock_check.return_value = GateResult(cve_ids=["CVE-2024-1234"])
    instance = _make_npm_instance(name="lodash", version="4.17.21")

    with pytest.raises(
        ValidationError,
        match="CVE-2024-1234",
    ):
        upload_gate(sender=None, instance=instance)


@patch("pulp_trustify.gate.check_purl_with_mode")
@patch.dict(sys.modules, {"pulp_trustify.app.models": _fake_models()})
@patch("django.conf.settings", _make_settings())
def test_labels_clean_upload(mock_check):
    """Clean upload gets trustify labels with clean=true."""
    from pulp_trustify.gate import GateResult
    from pulp_trustify.upload import upload_gate

    mock_check.return_value = GateResult(detection_mode="analyze")
    instance = _make_instance(name="requests", version="2.32.0")

    upload_gate(sender=None, instance=instance)

    assert instance.pulp_labels["trustify.scanned"] == "true"
    assert instance.pulp_labels["trustify.clean"] == "true"
    assert instance.pulp_labels["trustify.detected_by"] == "analyze"
    assert "trustify.scanned_at" in instance.pulp_labels


@patch("pulp_trustify.gate.check_purl_with_mode")
@patch.dict(sys.modules, {"pulp_trustify.app.models": _fake_models()})
@patch("django.conf.settings", _make_settings())
def test_labels_blocked_upload(mock_check):
    """Blocked upload gets labels with clean=false and CVEs."""
    from rest_framework.exceptions import ValidationError

    from pulp_trustify.gate import GateResult
    from pulp_trustify.upload import upload_gate

    mock_check.return_value = GateResult(
        cve_ids=["CVE-2023-1234", "CVE-2023-5678"],
        all_findings=[
            {
                "entry": {"cve": "CVE-2023-1234"},
                "base_score": {"severity": "critical"},
            },
            {
                "entry": {"cve": "CVE-2023-5678"},
                "base_score": {"severity": "high"},
            },
        ],
        detection_mode="analyze",
    )
    instance = _make_instance(name="requests", version="2.28.0")

    with pytest.raises(ValidationError):
        upload_gate(sender=None, instance=instance)

    assert instance.pulp_labels["trustify.scanned"] == "true"
    assert instance.pulp_labels["trustify.clean"] == "false"
    assert "CVE-2023-1234" in instance.pulp_labels["trustify.cves"]
    assert "CVE-2023-5678" in instance.pulp_labels["trustify.cves"]
    assert instance.pulp_labels["trustify.detected_by"] == "analyze"


@patch("pulp_trustify.gate.check_purl_with_mode")
@patch.dict(sys.modules, {"pulp_trustify.app.models": _fake_models()})
@patch("django.conf.settings", _make_settings())
def test_labels_below_threshold(mock_check):
    """Below-threshold upload gets clean=false with CVEs but allowed."""
    from pulp_trustify.gate import GateResult
    from pulp_trustify.upload import upload_gate

    mock_check.return_value = GateResult(
        cve_ids=[],
        all_findings=[
            {
                "entry": {"cve": "CVE-2023-9999"},
                "base_score": {"severity": "medium"},
            }
        ],
        detection_mode="analyze",
    )
    instance = _make_instance(name="requests", version="2.28.0")

    upload_gate(sender=None, instance=instance)

    assert instance.pulp_labels["trustify.scanned"] == "true"
    assert instance.pulp_labels["trustify.clean"] == "false"
    assert "CVE-2023-9999" in instance.pulp_labels["trustify.cves"]


@patch("pulp_trustify.gate.check_purl_with_mode")
@patch.dict(sys.modules, {"pulp_trustify.app.models": _fake_models()})
@patch(
    "django.conf.settings",
    _make_settings(TRUSTIFY_GATE_LABEL_CONTENT=False),
)
def test_labels_disabled(mock_check):
    """No labels when TRUSTIFY_GATE_LABEL_CONTENT=False."""
    from pulp_trustify.gate import GateResult
    from pulp_trustify.upload import upload_gate

    mock_check.return_value = GateResult(detection_mode="analyze")
    instance = _make_instance(name="requests", version="2.32.0")

    upload_gate(sender=None, instance=instance)

    assert not instance.pulp_labels


@patch("pulp_trustify.gate.check_purl_with_mode")
@patch.dict(sys.modules, {"pulp_trustify.app.models": _fake_models()})
@patch("django.conf.settings", _make_settings())
def test_advisory_created_on_allow(mock_check):
    """Allowed upload creates GateAdvisory."""
    from pulp_trustify.gate import GateResult
    from pulp_trustify.scanner import VulnerabilityDetail
    from pulp_trustify.upload import upload_gate

    mock_check.return_value = GateResult(
        cve_ids=[],
        all_findings=[
            {
                "entry": {"cve": "CVE-2023-9999"},
                "base_score": {"severity": "medium"},
            }
        ],
        details=[
            VulnerabilityDetail(
                cve_id="CVE-2023-9999",
                severity="medium",
                trustify_url="https://trustify.example.com/CVE-2023-9999",
                description="",
            )
        ],
        detection_mode="analyze",
    )
    instance = _make_instance(name="requests", version="2.28.0")

    upload_gate(sender=None, instance=instance)

    from pulp_trustify.app.models import GateAdvisory

    GateAdvisory.objects.create.assert_called_once()
    call_kwargs = GateAdvisory.objects.create.call_args.kwargs
    assert call_kwargs["purl"] == "pkg:pypi/requests@2.28.0"
    assert call_kwargs["detection_mode"] == "analyze"
    assert call_kwargs["action"] == "allowed"
    assert "CVE-2023-9999" in call_kwargs["cve_ids"]


@patch("pulp_trustify.gate.check_purl_with_mode")
@patch.dict(sys.modules, {"pulp_trustify.app.models": _fake_models()})
@patch(
    "django.conf.settings",
    _make_settings(TRUSTIFY_GATE_ADVISORY=False),
)
def test_advisory_disabled(mock_check):
    """No GateAdvisory when TRUSTIFY_GATE_ADVISORY=False."""
    from pulp_trustify.gate import GateResult
    from pulp_trustify.upload import upload_gate

    mock_check.return_value = GateResult(detection_mode="analyze")
    instance = _make_instance(name="requests", version="2.32.0")

    upload_gate(sender=None, instance=instance)

    from pulp_trustify.app.models import GateAdvisory

    GateAdvisory.objects.create.assert_not_called()


@patch("pulp_trustify.gate.check_purl_with_mode")
@patch.dict(sys.modules, {"pulp_trustify.app.models": _fake_models()})
@patch("django.conf.settings", _make_settings())
def test_advisory_not_created_on_block(mock_check):
    """Blocked upload does NOT create GateAdvisory."""
    from rest_framework.exceptions import ValidationError

    from pulp_trustify.gate import GateResult
    from pulp_trustify.upload import upload_gate

    mock_check.return_value = GateResult(cve_ids=["CVE-2023-1234"])
    instance = _make_instance(name="requests", version="2.28.0")

    with pytest.raises(ValidationError):
        upload_gate(sender=None, instance=instance)

    from pulp_trustify.app.models import GateAdvisory

    GateAdvisory.objects.create.assert_not_called()
