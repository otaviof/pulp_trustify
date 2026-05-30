from __future__ import annotations

import pytest


@pytest.mark.e2e
@pytest.mark.scan
def test_scan_dispatches_task(
    pulp_api,
    wait_for_task,
):
    scan_url = f"{pulp_api.api_url}/trustify/scan/"
    resp = pulp_api.post(scan_url)
    resp.raise_for_status()
    data = resp.json()
    assert "task" in data
    wait_for_task(data["task"], timeout=120)


@pytest.mark.e2e
@pytest.mark.scan
def test_scan_creates_advisory_records(
    pulp_api,
    uploaded_vulnerable,
    wait_for_task,
):
    scan_url = f"{pulp_api.api_url}/trustify/scan/"
    resp = pulp_api.post(scan_url)
    resp.raise_for_status()
    task_href = resp.json()["task"]
    wait_for_task(task_href, timeout=120)

    adv_url = f"{pulp_api.api_url}/trustify/advisories/"
    adv_resp = pulp_api.get(adv_url)
    adv_resp.raise_for_status()
    advisories = adv_resp.json().get("results", [])
    assert len(advisories) > 0, "No advisories created after scan"


@pytest.mark.e2e
@pytest.mark.scan
def test_scan_adds_labels_to_content(
    pulp_api,
    uploaded_vulnerable,
    wait_for_task,
):
    content_href = uploaded_vulnerable

    scan_url = f"{pulp_api.api_url}/trustify/scan/"
    resp = pulp_api.post(scan_url)
    resp.raise_for_status()
    task_href = resp.json()["task"]
    wait_for_task(task_href, timeout=120)

    content_resp = pulp_api.get(
        pulp_api.href(content_href),
    )
    content_resp.raise_for_status()
    labels = content_resp.json().get(
        "pulp_labels",
        {},
    )

    trustify_labels = {
        k: v for k, v in labels.items() if k.startswith("trustify.")
    }
    assert len(trustify_labels) > 0, "No trustify.* labels on content"
