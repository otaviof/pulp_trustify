from __future__ import annotations

from importlib.metadata import version

import pytest


@pytest.mark.e2e
@pytest.mark.status
def test_plugin_appears_in_status(
    pulp_api,
):
    resp = pulp_api.get(
        f"{pulp_api.api_url}/status/",
    )
    resp.raise_for_status()
    status = resp.json()

    versions = status.get("versions", [])
    plugin = next(
        (v for v in versions if v.get("component") == "trustify"),
        None,
    )

    assert plugin is not None, "trustify not found in status"
    expected_version = version("pulp_trustify")
    assert plugin.get("version") == expected_version
