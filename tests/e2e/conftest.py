from __future__ import annotations

import pytest


@pytest.fixture()
def python_repository(pulp_api, wait_for_task):
    repo_url = f"{pulp_api.api_url}/repositories/python/python/"
    repo_resp = pulp_api.post(
        repo_url,
        json={"name": "test-repo"},
    )
    repo_resp.raise_for_status()
    repo_href = repo_resp.json()["pulp_href"]

    distro_url = f"{pulp_api.api_url}/distributions/python/pypi/"
    distro_resp = pulp_api.post(
        distro_url,
        json={
            "name": "test-distro",
            "base_path": "test",
            "repository": repo_href,
        },
    )
    distro_resp.raise_for_status()
    task_href = distro_resp.json()["task"]
    wait_for_task(task_href)

    distro_list = pulp_api.get(
        distro_url,
        params={"name": "test-distro"},
    )
    distros = distro_list.json().get("results", [])
    base_path = distros[0]["base_path"] if distros else "test"

    yield repo_href, base_path

    pulp_api.delete(pulp_api.href(repo_href))
    for item in distros:
        pulp_api.delete(
            pulp_api.href(item["pulp_href"]),
        )


@pytest.fixture()
def uploaded_vulnerable(
    python_repository,
    pulp_api,
    upload_package,
    wait_for_task,
):
    repo_href, _ = python_repository
    wheel = "tests/e2e/fixtures/urllib3-2.6.2-py3-none-any.whl"
    task_href = upload_package(repo_href, wheel)
    data = wait_for_task(task_href)
    content_href = data.get(
        "created_resources",
        [None],
    )[0]
    return content_href
