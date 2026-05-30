from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
import requests

from pulp_trustify.client.client import TrustifyClient


@dataclass
class PulpAPI:
    """Thin wrapper around requests.Session
    carrying Pulp connection coordinates."""

    session: requests.Session
    origin: str
    api_path: str

    @property
    def api_url(self) -> str:
        return f"{self.origin}{self.api_path}"

    def get(self, url: str, **kw):
        return self.session.get(url, **kw)

    def post(self, url: str, **kw):
        return self.session.post(url, **kw)

    def delete(self, url: str, **kw):
        return self.session.delete(url, **kw)

    def href(self, pulp_href: str) -> str:
        """Resolve an absolute pulp_href to a
        full URL."""
        return f"{self.origin}{pulp_href}"


@pytest.fixture()
def trustify_client() -> TrustifyClient:
    url = os.environ.get("TRUSTIFY_URL", "http://localhost:9010")
    return TrustifyClient(url=url, issuer_url="")


@pytest.fixture(scope="session")
def pulp_api() -> PulpAPI:
    origin = os.environ.get("PULP_URL", "http://localhost:8080")
    api_root = os.environ.get("PULP_API_ROOT", "/pulp/")
    username = os.environ.get("PULP_USERNAME", "admin")
    password = os.environ.get("PULP_PASSWORD", "password")
    verify_str = os.environ.get("PULP_VERIFY_SSL", "false")
    verify = verify_str.lower() not in ("false", "0")

    session = requests.Session()
    session.auth = (username, password)
    session.verify = verify

    clean_origin = origin.rstrip("/")
    api_path = f"/{api_root.strip('/')}/api/v3"

    return PulpAPI(
        session=session,
        origin=clean_origin,
        api_path=api_path,
    )


@pytest.fixture(scope="session")
def wait_for_task(pulp_api):
    def _wait(
        task_href: str,
        timeout: int = 60,
    ) -> dict:
        start = time.time()
        while time.time() - start < timeout:
            resp = pulp_api.get(pulp_api.href(task_href))
            resp.raise_for_status()
            data = resp.json()
            state = data.get("state")
            if state == "completed":
                return data
            if state == "failed":
                desc = data.get(
                    "error",
                    {},
                ).get("description", "Unknown")
                raise RuntimeError(f"Task failed: {desc}")
            time.sleep(1)
        raise TimeoutError(f"Task {task_href} timed out after {timeout}s")

    return _wait


@pytest.fixture(scope="session")
def upload_package(pulp_api):
    def _upload(
        repo_href: str,
        file_path: str,
    ) -> str:
        url = f"{pulp_api.api_url}/content/python/packages/"
        filename = Path(file_path).name
        with open(file_path, "rb") as f:
            resp = pulp_api.post(
                url,
                data={
                    "repository": repo_href,
                    "relative_path": filename,
                },
                files={"file": f},
            )
            resp.raise_for_status()
            return resp.json()["task"]

    return _upload
