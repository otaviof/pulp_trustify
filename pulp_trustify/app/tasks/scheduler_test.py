from __future__ import annotations

import sys
from datetime import timedelta
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest


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


def test_parse_duration_hours():
    from pulp_trustify.app.tasks.scheduler import _parse_duration

    assert _parse_duration("6h") == timedelta(hours=6)


def test_parse_duration_days():
    from pulp_trustify.app.tasks.scheduler import _parse_duration

    assert _parse_duration("1d") == timedelta(days=1)


def test_parse_duration_minutes():
    from pulp_trustify.app.tasks.scheduler import _parse_duration

    assert _parse_duration("30m") == timedelta(minutes=30)


def test_parse_duration_combined():
    from pulp_trustify.app.tasks.scheduler import _parse_duration

    assert _parse_duration("1d12h") == timedelta(days=1, hours=12)


def test_parse_duration_full():
    from pulp_trustify.app.tasks.scheduler import _parse_duration

    assert _parse_duration("1d6h30m") == timedelta(days=1, hours=6, minutes=30)


def test_parse_duration_strips_whitespace():
    from pulp_trustify.app.tasks.scheduler import _parse_duration

    assert _parse_duration(" 6h ") == timedelta(hours=6)


def test_parse_duration_invalid_raises():
    from pulp_trustify.app.tasks.scheduler import _parse_duration

    with pytest.raises(ValueError, match="Invalid duration"):
        _parse_duration("invalid")


def test_parse_duration_empty_raises():
    from pulp_trustify.app.tasks.scheduler import _parse_duration

    with pytest.raises(ValueError, match="Invalid duration"):
        _parse_duration("")


@patch.dict(sys.modules, _fake_pulpcore())
def test_scan_all_dispatches_for_each_repo():
    from pulpcore.plugin.models import Repository
    from pulpcore.plugin.tasking import dispatch

    mock_repo1 = MagicMock()
    mock_repo1.pk = "pk1"
    mock_repo2 = MagicMock()
    mock_repo2.pk = "pk2"
    mock_repo3 = MagicMock()
    mock_repo3.pk = "pk3"

    Repository.objects.all.return_value = [
        mock_repo1,
        mock_repo2,
        mock_repo3,
    ]

    from pulp_trustify.app.tasks.scheduler import scan_all_repositories

    scan_all_repositories()

    assert dispatch.call_count == 3

    calls = dispatch.call_args_list
    assert calls[0].kwargs["exclusive_resources"] == [mock_repo1]
    assert calls[0].kwargs["kwargs"]["repository_pk"] == "pk1"
    assert calls[1].kwargs["exclusive_resources"] == [mock_repo2]
    assert calls[1].kwargs["kwargs"]["repository_pk"] == "pk2"
    assert calls[2].kwargs["exclusive_resources"] == [mock_repo3]
    assert calls[2].kwargs["kwargs"]["repository_pk"] == "pk3"


@patch.dict(sys.modules, _fake_pulpcore())
def test_scan_all_no_repos():
    from pulpcore.plugin.models import Repository
    from pulpcore.plugin.tasking import dispatch

    Repository.objects.all.return_value = []

    from pulp_trustify.app.tasks.scheduler import scan_all_repositories

    scan_all_repositories()

    dispatch.assert_not_called()
