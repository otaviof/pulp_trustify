from __future__ import annotations

import logging
import ssl
import threading
import time
from typing import Any, Protocol, runtime_checkable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

logger = logging.getLogger(__name__)


@runtime_checkable
class VulnerabilityChecker(Protocol):
    """Structural interface for vulnerability checking."""

    def analyze(self, purls: list[str]) -> dict[str, Any]: ...

    def search_vulnerabilities(
        self,
        query: str,
        offset: int = ...,
        limit: int = ...,
    ) -> dict[str, Any]: ...


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


def build_trustify_url(base_url: str, cve_id: str) -> str:
    return f"{base_url.rstrip('/')}/vulnerabilities/{cve_id}"


class TrustifyError(Exception):
    """Raised when the Trustify API is unreachable
    or returns an error."""


def _extract_severity(detail: dict) -> str | None:
    """Extract the highest severity from a Trustify detail."""
    for affected in detail.get("status", {}).get("affected", []):
        for score in affected.get("scores", []):
            sev = score.get("severity")
            if sev:
                return sev
    return None


def _normalize_analyze(raw: dict) -> dict[str, Any]:
    """Normalize Trustify analyze response.

    Trustify returns ``{purl: {details: [...]}}``.
    The gate layer expects ``{items: [{details: [...]}]}``.
    """
    if "items" in raw:
        return raw
    items: list[dict[str, Any]] = []
    for purl_key, purl_data in raw.items():
        if not isinstance(purl_data, dict):
            continue
        details: list[dict[str, Any]] = []
        for d in purl_data.get("details", []):
            details.append(
                {
                    "entry": {
                        "cve": d.get("identifier", "unknown"),
                    },
                    "base_score": {
                        "severity": _extract_severity(d),
                    },
                }
            )
        items.append({"purl": purl_key, "details": details})
    return {"items": items}


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
        logger.debug("Fetching OIDC token from '%s'", token_url)
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
            logger.debug("OIDC token refreshed, expires in %ds", expires_in)
            return data["access_token"], expiry
        except requests.RequestException as exc:
            logger.warning("OIDC token fetch failed: %s", exc)
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

    def analyze(self, purls: list[str]) -> dict[str, Any]:
        endpoint = f"{self._url}/api/{self._api_version}/vulnerability/analyze"
        logger.debug("POST '%s' with %d PURLs", endpoint, len(purls))
        try:
            response = self._session.post(
                endpoint,
                json={"purls": purls},
                headers=self._get_headers(),
                timeout=30,
            )
            response.raise_for_status()
            raw = response.json()
            result = _normalize_analyze(raw)
            items_count = len(result.get("items", []))
            logger.debug("Analyze response: %d items", items_count)
            return result
        except requests.RequestException as exc:
            logger.warning("Trustify API request failed: %s", exc)
            raise TrustifyError(f"Trustify API request failed: {exc}") from exc

    def search_vulnerabilities(
        self,
        query: str,
        offset: int = 0,
        limit: int = 10,
    ) -> dict[str, Any]:
        endpoint = f"{self._url}/api/{self._api_version}/vulnerability"
        logger.debug("GET '%s' q='%s'", endpoint, query)
        try:
            response = self._session.get(
                endpoint,
                params={
                    "q": query,
                    "offset": offset,
                    "limit": limit,
                },
                headers=self._get_headers(),
                timeout=30,
            )
            response.raise_for_status()
            result = response.json()
            items_count = len(result.get("items", []))
            logger.debug("Search response: %d items", items_count)
            return result
        except requests.RequestException as exc:
            logger.warning("Vulnerability search failed: %s", exc)
            raise TrustifyError(f"Vulnerability search failed: {exc}") from exc

    def get_vulnerability(self, identifier: str) -> dict[str, Any]:
        endpoint = (
            f"{self._url}/api/{self._api_version}/vulnerability/{identifier}"
        )
        try:
            response = self._session.get(
                endpoint,
                headers=self._get_headers(),
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as exc:
            logger.warning("Vulnerability detail fetch failed: %s", exc)
            raise TrustifyError(
                f"Vulnerability detail fetch failed: {exc}"
            ) from exc
