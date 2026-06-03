from __future__ import annotations

import contextvars
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, patch


def _make_settings(**overrides):
    defaults = {
        "TRUSTIFY_SCAN_ON_CONTENT_CHANGE": False,
        "TRUSTIFY_SCAN_ENABLED": True,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _fake_pulpcore():
    mod = ModuleType("pulpcore")
    plugin = ModuleType("pulpcore.plugin")
    models = ModuleType("pulpcore.plugin.models")
    tasking = ModuleType("pulpcore.plugin.tasking")
    setattr(models, "Repository", MagicMock())
    setattr(tasking, "dispatch", MagicMock())
    setattr(plugin, "models", models)
    setattr(plugin, "tasking", tasking)
    setattr(mod, "plugin", plugin)
    return {
        "pulpcore": mod,
        "pulpcore.plugin": plugin,
        "pulpcore.plugin.models": models,
        "pulpcore.plugin.tasking": tasking,
    }


def _fake_pulpcore_contexts(task=None):
    mod = ModuleType("pulpcore.app.contexts")
    ctx_var = contextvars.ContextVar("_current_task", default=None)
    if task is not None:
        ctx_var.set(task)
    setattr(mod, "_current_task", ctx_var)
    return {"pulpcore.app.contexts": mod}


@patch.dict(sys.modules, {**_fake_pulpcore(), **_fake_pulpcore_contexts()})
@patch("django.conf.settings", _make_settings())
def test_skips_incomplete_version():
    from pulp_trustify.app.signals import on_repository_version_created

    mock_instance = MagicMock()
    mock_instance.complete = False

    on_repository_version_created(sender=None, instance=mock_instance)


@patch.dict(sys.modules, {**_fake_pulpcore(), **_fake_pulpcore_contexts()})
@patch(
    "django.conf.settings",
    _make_settings(TRUSTIFY_SCAN_ON_CONTENT_CHANGE=False),
)
def test_skips_when_feature_disabled():
    from pulpcore.plugin.tasking import dispatch

    from pulp_trustify.app.signals import on_repository_version_created

    mock_instance = MagicMock()
    mock_instance.complete = True

    on_repository_version_created(sender=None, instance=mock_instance)

    dispatch.assert_not_called()


@patch.dict(sys.modules, {**_fake_pulpcore(), **_fake_pulpcore_contexts()})
@patch(
    "django.conf.settings",
    _make_settings(
        TRUSTIFY_SCAN_ON_CONTENT_CHANGE=True,
        TRUSTIFY_SCAN_ENABLED=False,
    ),
)
def test_skips_when_scanning_disabled():
    from pulpcore.plugin.tasking import dispatch

    from pulp_trustify.app.signals import on_repository_version_created

    mock_instance = MagicMock()
    mock_instance.complete = True

    on_repository_version_created(sender=None, instance=mock_instance)

    dispatch.assert_not_called()


@patch.dict(sys.modules, {**_fake_pulpcore(), **_fake_pulpcore_contexts()})
@patch(
    "django.conf.settings",
    _make_settings(TRUSTIFY_SCAN_ON_CONTENT_CHANGE=True),
)
def test_dispatches_scan_on_content_change():
    from pulpcore.plugin.tasking import dispatch

    from pulp_trustify.app.signals import on_repository_version_created

    mock_repo = MagicMock()
    mock_repo.pk = "repo-pk"
    mock_repo.name = "my-repo"

    mock_instance = MagicMock()
    mock_instance.complete = True
    mock_instance.repository = mock_repo

    on_repository_version_created(sender=None, instance=mock_instance)

    dispatch.assert_called_once()
    call_kwargs = dispatch.call_args.kwargs
    assert call_kwargs["exclusive_resources"] == [mock_repo]
    assert call_kwargs["kwargs"]["repository_pk"] == "repo-pk"


@patch.dict(sys.modules, {**_fake_pulpcore(), **_fake_pulpcore_contexts()})
@patch(
    "django.conf.settings",
    _make_settings(TRUSTIFY_SCAN_ON_CONTENT_CHANGE=True),
)
def test_self_trigger_prevention():
    from pulpcore.app.contexts import _current_task  # noqa: TID251
    from pulpcore.plugin.tasking import dispatch

    from pulp_trustify.app.signals import on_repository_version_created

    mock_task = MagicMock()
    mock_task.name = "scan_repository"
    _current_task.set(mock_task)

    mock_repo = MagicMock()
    mock_repo.pk = "repo-pk"

    mock_instance = MagicMock()
    mock_instance.complete = True
    mock_instance.repository = mock_repo

    on_repository_version_created(sender=None, instance=mock_instance)

    dispatch.assert_not_called()


@patch.dict(sys.modules, {**_fake_pulpcore(), **_fake_pulpcore_contexts()})
@patch(
    "django.conf.settings",
    _make_settings(TRUSTIFY_SCAN_ON_CONTENT_CHANGE=True),
)
def test_self_trigger_allows_other_tasks():
    from pulpcore.app.contexts import _current_task  # noqa: TID251
    from pulpcore.plugin.tasking import dispatch

    from pulp_trustify.app.signals import on_repository_version_created

    mock_task = MagicMock()
    mock_task.name = "sync_repository"
    _current_task.set(mock_task)

    mock_repo = MagicMock()
    mock_repo.pk = "repo-pk"
    mock_repo.name = "my-repo"

    mock_instance = MagicMock()
    mock_instance.complete = True
    mock_instance.repository = mock_repo

    on_repository_version_created(sender=None, instance=mock_instance)

    dispatch.assert_called_once()
    call_kwargs = dispatch.call_args.kwargs
    assert call_kwargs["exclusive_resources"] == [mock_repo]
    assert call_kwargs["kwargs"]["repository_pk"] == "repo-pk"
