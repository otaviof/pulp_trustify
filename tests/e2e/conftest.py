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

    guard_url = f"{pulp_api.api_url}/contentguards/trustify/guard/"
    guard_resp = pulp_api.post(guard_url, json={"name": "test-guard"})
    guard_resp.raise_for_status()
    guard_href = guard_resp.json()["pulp_href"]

    distro_url = f"{pulp_api.api_url}/distributions/python/pypi/"
    distro_resp = pulp_api.post(
        distro_url,
        json={
            "name": "test-distro",
            "base_path": "test",
            "repository": repo_href,
            "content_guard": guard_href,
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

    for item in distros:
        pulp_api.delete(
            pulp_api.href(item["pulp_href"]),
        )
    pulp_api.delete(pulp_api.href(guard_href))
    pulp_api.delete(pulp_api.href(repo_href))


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
    content_href = next(
        (r for r in data.get("created_resources", []) if "/content/" in r),
        None,
    )
    assert content_href is not None, (
        f"No content href in created_resources: {data.get('created_resources')}"
    )
    return content_href
