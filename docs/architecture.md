# Architecture

`pulp_trustify` is a `pulpcore` plugin — a Django app discovered at runtime via the `pulpcore.plugin` entry point. It provides four protection layers that share a common detection core.

## Protection Layers

```mermaid
flowchart TD
    subgraph "Protection Layers"
        A["Download Guard<br/>(real-time blocking)"]
        B["Upload Gate<br/>(upload-time blocking)"]
        C["Scanner<br/>(periodic sweep)"]
        D2["Yank Warnings<br/>(PEP 592 Simple API)"]
    end

    A --> I["Shared Detection Core<br/>gate.py → check_purl()"]
    B --> I
    C --> I
    D2 -.reads.-> J["Scanner Labels<br/>(pulp_labels)"]
    C -.writes.-> J
```

| Layer | Timing | Action | Scope |
|:------|:-------|:-------|:------|
| [Download Guard](guard.md) | Per-request | Blocks download (403) | Single artifact |
| [Upload Gate](upload-gate.md) | Per-upload | Rejects upload (400) | Single package |
| [Scanner](scanner.md) | On-demand/periodic | Label, quarantine, remove, advisory | Entire repository |
| [Yank Warnings](yank.md) | Per-index-request | Injects PEP 592 `data-yanked` | Simple API response |

## PURL Extraction

The plugin uses a pluggable parser registry to convert URL paths or content objects into [Package URLs](https://github.com/package-url/purl-spec).

- **`@register('pypi')`** — `parse_pypi_url(path)`: extracts PURL from download paths (wheels, sdists). Used by the download guard via `url_to_purl()`.
- **`@register_content('pypi')`** — `parse_pypi_content(content)`: extracts PURL from content model fields (name, version). Used by the upload gate and scanner via `content_to_purl()`.

Currently supports PyPI packages only. Additional ecosystems can be added by decorating new parser functions.

## Authentication

`TrustifyClient` authenticates via OIDC `client_credentials` grant against a Keycloak realm. Tokens are cached with a 30-second expiry buffer and refreshed lazily under a `threading.Lock`. Custom CA bundles are supported via `TRUSTIFY_CA_BUNDLE`.

See [Settings Reference](settings.md#connection) for `TRUSTIFY_ISSUER_URL`, `TRUSTIFY_CLIENT_ID`, and `TRUSTIFY_CLIENT_SECRET`. See [Trustify Concepts](https://docs.guac.sh/trustify/concepts/) for the upstream authentication model.

## Detection Pipeline

All protection layers share the same detection logic — see [Detection Pipeline](detection.md) for the full analysis, including the dual-mode detection flow (analyze + search fallback), severity filtering, fail-open behavior, and Trustify importer requirements.
