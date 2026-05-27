from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, patch


def _make_settings(**overrides):
    defaults = {
        "TRUSTIFY_SEVERITY_THRESHOLD": "critical",
        "TRUSTIFY_FAIL_OPEN": False,
        "TRUSTIFY_BATCH_SIZE": 100,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _fake_pulpcore():
    mod = ModuleType("pulpcore")
    plugin = ModuleType("pulpcore.plugin")
    models = ModuleType("pulpcore.plugin.models")
    setattr(models, "Repository", MagicMock())
    setattr(plugin, "models", models)
    setattr(mod, "plugin", plugin)
    return {
        "pulpcore": mod,
        "pulpcore.plugin": plugin,
        "pulpcore.plugin.models": models,
    }


def _fake_pulp_python():
    mod = ModuleType("pulp_python")
    app = ModuleType("pulp_python.app")
    models = ModuleType("pulp_python.app.models")
    setattr(models, "PythonRepository", MagicMock())
    setattr(app, "models", models)
    setattr(mod, "app", app)
    return {
        "pulp_python": mod,
        "pulp_python.app": app,
        "pulp_python.app.models": models,
    }


def _fake_app_models():
    mod = ModuleType("pulp_trustify.app.models")
    setattr(mod, "_get_client", MagicMock())
    return {"pulp_trustify.app.models": mod}


def _make_content(pk, name, version):
    ns = SimpleNamespace(pk=pk, name=name, version=version)
    ns.cast = lambda: ns
    return ns


@patch("pulp_trustify.app.tasks.scanner.scan_content")
@patch("pulp_trustify.app.tasks.scanner.content_to_purl")
@patch.dict(
    sys.modules,
    {
        **_fake_pulpcore(),
        **_fake_pulp_python(),
        **_fake_app_models(),
    },
)
@patch("django.conf.settings", _make_settings())
def test_removes_vulnerable_content(
    mock_content_to_purl,
    mock_scan_content,
):
    """Create new version removing vulnerable content."""
    from pulp_trustify.scanner import ScanResult

    c1 = _make_content("pk1", "vuln-pkg", "1.0")
    c2 = _make_content("pk2", "safe-pkg", "2.0")
    c3 = _make_content("pk3", "vuln-other", "3.0")

    mock_content_to_purl.side_effect = lambda c: f"pkg:pypi/{c.name}@{c.version}"

    mock_scan_content.return_value = [
        ScanResult(
            content_pk="pk1",
            purl="pkg:pypi/vuln-pkg@1.0",
            cve_ids=["CVE-2023-001"],
            blocked=True,
        ),
        ScanResult(
            content_pk="pk2",
            purl="pkg:pypi/safe-pkg@2.0",
        ),
        ScanResult(
            content_pk="pk3",
            purl="pkg:pypi/vuln-other@3.0",
            cve_ids=["CVE-2023-002"],
            blocked=True,
        ),
    ]

    mock_repo = MagicMock()
    mock_repo.pk = "repo-pk"
    mock_version = MagicMock()
    mock_version.content.all.return_value = [c1, c2, c3]
    mock_repo.latest_version.return_value = mock_version

    new_version_ctx = MagicMock()
    mock_repo.new_version.return_value.__enter__ = lambda _: new_version_ctx
    mock_repo.new_version.return_value.__exit__ = lambda *_: None

    from pulp_trustify.app.tasks.scanner import scan_repository

    with patch(
        "pulp_trustify.app.tasks.scanner._get_repository",
        return_value=mock_repo,
    ):
        scan_repository(repository_pk="repo-pk")

    mock_repo.new_version.assert_called_once()
    new_version_ctx.remove_content.assert_called_once()
    mock_version.content.filter.assert_called_once()
    filter_kwargs = mock_version.content.filter.call_args.kwargs
    assert set(filter_kwargs["pk__in"]) == {"pk1", "pk3"}


@patch("pulp_trustify.app.tasks.scanner.scan_content")
@patch("pulp_trustify.app.tasks.scanner.content_to_purl")
@patch.dict(
    sys.modules,
    {
        **_fake_pulpcore(),
        **_fake_pulp_python(),
        **_fake_app_models(),
    },
)
@patch("django.conf.settings", _make_settings())
def test_noop_when_all_clean(
    mock_content_to_purl,
    mock_scan_content,
):
    """No new version when no vulnerabilities found."""
    from pulp_trustify.scanner import ScanResult

    c1 = _make_content("pk1", "safe", "1.0")
    mock_content_to_purl.return_value = "pkg:pypi/safe@1.0"
    mock_scan_content.return_value = [
        ScanResult(content_pk="pk1", purl="pkg:pypi/safe@1.0"),
    ]

    mock_repo = MagicMock()
    mock_repo.pk = "repo-pk"
    mock_version = MagicMock()
    mock_version.content.all.return_value = [c1]
    mock_repo.latest_version.return_value = mock_version

    from pulp_trustify.app.tasks.scanner import scan_repository

    with patch(
        "pulp_trustify.app.tasks.scanner._get_repository",
        return_value=mock_repo,
    ):
        scan_repository(repository_pk="repo-pk")

    mock_repo.new_version.assert_not_called()


@patch.dict(
    sys.modules,
    {
        **_fake_pulpcore(),
        **_fake_pulp_python(),
        **_fake_app_models(),
    },
)
@patch("django.conf.settings", _make_settings())
def test_noop_when_no_latest_version():
    """Early return when repository has no versions."""
    mock_repo = MagicMock()
    mock_repo.pk = "repo-pk"
    mock_repo.latest_version.return_value = None

    from pulp_trustify.app.tasks.scanner import scan_repository

    with (
        patch(
            "pulp_trustify.app.tasks.scanner._get_repository",
            return_value=mock_repo,
        ),
        patch("pulp_trustify.app.tasks.scanner.scan_content") as mock_scan,
    ):
        scan_repository(repository_pk="repo-pk")

    mock_scan.assert_not_called()


@patch("pulp_trustify.app.tasks.scanner.content_to_purl")
@patch.dict(
    sys.modules,
    {
        **_fake_pulpcore(),
        **_fake_pulp_python(),
        **_fake_app_models(),
    },
)
@patch("django.conf.settings", _make_settings())
def test_noop_when_no_purls(mock_content_to_purl):
    """Early return when no content produces PURLs."""
    c1 = _make_content("pk1", None, None)
    mock_content_to_purl.return_value = None

    mock_repo = MagicMock()
    mock_repo.pk = "repo-pk"
    mock_version = MagicMock()
    mock_version.content.all.return_value = [c1]
    mock_repo.latest_version.return_value = mock_version

    from pulp_trustify.app.tasks.scanner import scan_repository

    with (
        patch(
            "pulp_trustify.app.tasks.scanner._get_repository",
            return_value=mock_repo,
        ),
        patch("pulp_trustify.app.tasks.scanner.scan_content") as mock_scan,
    ):
        scan_repository(repository_pk="repo-pk")

    mock_scan.assert_not_called()


@patch.dict(
    sys.modules,
    {
        **_fake_pulpcore(),
        **_fake_pulp_python(),
        **_fake_app_models(),
    },
)
@patch(
    "django.conf.settings",
    _make_settings(TRUSTIFY_SCAN_ENABLED=False),
)
def test_noop_when_scanning_disabled():
    """Early return when TRUSTIFY_SCAN_ENABLED is False."""
    from pulp_trustify.app.tasks.scanner import scan_repository

    with patch(
        "pulp_trustify.app.tasks.scanner._get_repository",
    ) as mock_get_repo:
        scan_repository(repository_pk="repo-pk")

    mock_get_repo.assert_not_called()


@patch("pulp_trustify.app.tasks.scanner.scan_content")
@patch("pulp_trustify.app.tasks.scanner.content_to_purl")
@patch.dict(
    sys.modules,
    {
        **_fake_pulpcore(),
        **_fake_pulp_python(),
        **_fake_app_models(),
    },
)
@patch(
    "django.conf.settings",
    _make_settings(TRUSTIFY_BATCH_SIZE=50),
)
def test_batch_size_from_settings(
    mock_content_to_purl,
    mock_scan_content,
):
    """Pass TRUSTIFY_BATCH_SIZE to scan_content."""
    from pulp_trustify.scanner import ScanResult

    c1 = _make_content("pk1", "pkg", "1.0")
    mock_content_to_purl.return_value = "pkg:pypi/pkg@1.0"
    mock_scan_content.return_value = [
        ScanResult(content_pk="pk1", purl="pkg:pypi/pkg@1.0"),
    ]

    mock_repo = MagicMock()
    mock_repo.pk = "repo-pk"
    mock_version = MagicMock()
    mock_version.content.all.return_value = [c1]
    mock_repo.latest_version.return_value = mock_version

    from pulp_trustify.app.tasks.scanner import scan_repository

    with patch(
        "pulp_trustify.app.tasks.scanner._get_repository",
        return_value=mock_repo,
    ):
        scan_repository(repository_pk="repo-pk")

    call_kwargs = mock_scan_content.call_args.kwargs
    assert call_kwargs["batch_size"] == 50
