from __future__ import annotations

import pytest


@pytest.mark.e2e
@pytest.mark.gate
def test_gate_rejects_vulnerable_upload(
    pulp_api,
    python_repository,
):
    repo_href, _ = python_repository
    wheel = "tests/e2e/fixtures/urllib3-2.6.2-py3-none-any.whl"

    url = f"{pulp_api.api_url}/content/python/packages/"
    with open(wheel, "rb") as f:
        resp = pulp_api.post(
            url,
            data={
                "repository": repo_href,
                "relative_path": wheel.rsplit("/", 1)[-1],
            },
            files={"file": f},
        )

    assert resp.status_code == 400, (
        f"Expected 400 for vulnerable upload, got {resp.status_code}"
    )

    error_msg = str(resp.json())
    assert "CVE" in error_msg, "Error should contain CVE IDs"
