from __future__ import annotations

import ssl
import threading
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context


class _CAAdapter(HTTPAdapter):
    """HTTPS adapter using a custom CA bundle with relaxed
    X.509 strictness for internal CAs whose Basic Constraints
    extension is not marked critical."""

    def __init__(self, ca_bundle: str, **kwargs) -> None:
        self._ca_bundle = ca_bundle
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.load_verify_locations(self._ca_bundle)
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)


class TrustifyError(Exception):
    """Raised when the Trustify API is unreachable
    or returns an error."""


class TrustifyClient:
    def __init__(
        self,
        url: str,
        api_version: str = "v2",
        client_id: str = "cli",
        client_secret: str = "",
        issuer_url: str = "",
        ca_bundle: str = "",
    ) -> None:
        self._url = url
        self._api_version = api_version
        self._client_id = client_id
        self._client_secret = client_secret
        self._issuer_url = issuer_url
        self._session = requests.Session()
        if ca_bundle:
            adapter = _CAAdapter(ca_bundle)
            self._session.mount("https://", adapter)
        self._token: str | None = None
        self._token_expiry: float = 0.0
        self._token_lock = threading.Lock()

    def _fetch_token(self) -> tuple[str, float]:
        token_url = f"{self._issuer_url}/protocol/openid-connect/token"
        try:
            response = self._session.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
                timeout=10,
            )
            response.raise_for_status()
            data = response.json()
            expires_in = data.get("expires_in", 300)
            expiry = time.monotonic() + expires_in - 30
            return data["access_token"], expiry
        except requests.RequestException as exc:
            raise TrustifyError(f"Failed to fetch OIDC token: {exc}") from exc

    def _get_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Content-Type": "application/json",
        }
        if not self._issuer_url:
            return headers

        needs_refresh = False
        with self._token_lock:
            needs_refresh = time.monotonic() >= self._token_expiry

        if needs_refresh:
            token, expiry = self._fetch_token()
            with self._token_lock:
                self._token = token
                self._token_expiry = expiry

        with self._token_lock:
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def analyze(self, purls: list[str]) -> dict:
        endpoint = f"{self._url}/api/{self._api_version}/vulnerability/analyze"
        try:
            response = self._session.post(
                endpoint,
                json={"purls": purls},
                headers=self._get_headers(),
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as exc:
            raise TrustifyError(f"Trustify API request failed: {exc}") from exc
