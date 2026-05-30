from __future__ import annotations

import pytest
import requests


@pytest.mark.e2e
@pytest.mark.guard
def test_guard_blocks_vulnerable_content(
    pulp_api,
    python_repository,
    uploaded_vulnerable,
):
    _, base_path = python_repository

    download_url = (
        f"{pulp_api.origin}/pulp/content/"
        f"{base_path}/simple/urllib3/"
        "urllib3-2.6.2-py3-none-any.whl"
    )

    resp = requests.get(
        download_url,
        auth=pulp_api.session.auth,
        allow_redirects=False,
    )

    assert resp.status_code == 403, (
        f"Expected 403 for vulnerable content, got {resp.status_code}"
    )
