# Settings Reference

All settings are read via [Dynaconf](https://www.dynaconf.com/). Set them as `PULP_TRUSTIFY_*` environment variables on the Pulp pods, or in the Pulp settings file (`/etc/pulp/settings.py`).

## Connection

| Setting | Default | Description |
|:--------|:--------|:------------|
| `TRUSTIFY_URL` | `""` | [Trustify](https://docs.guac.sh/trustify/getting-started) API base URL (e.g., `https://trustify.example.com`) |
| `TRUSTIFY_API_VERSION` | `"v2"` | Trustify API version path segment. Trustify v0.4.x uses `v2`; v0.5.x and later use `v3`. See [release notes](https://guac.sh/blog/2025-10-28-trustify-v0.4.1/). |
| `TRUSTIFY_CLIENT_ID` | `"cli"` | OIDC client ID for Trustify authentication |
| `TRUSTIFY_CLIENT_SECRET` | `""` | OIDC client secret. Leave empty when Trustify does not require authentication. |
| `TRUSTIFY_ISSUER_URL` | `""` | Keycloak realm URL for OIDC token exchange (e.g., `https://sso.example.com/realms/trustify`). This points to the Keycloak realm provisioned by Trustify's infrastructure chart. When empty, no `Authorization` header is sent. |
| `TRUSTIFY_CA_BUNDLE` | `""` | Filesystem path to a PEM CA bundle for Trustify's TLS certificate. Useful for internal CAs. |

## Detection

| Setting | Default | Description |
|:--------|:--------|:------------|
| `TRUSTIFY_SEVERITY_THRESHOLD` | `"critical"` | Minimum CVE severity that triggers blocking (`low`, `medium`, `high`, `critical`). See [Severity Filtering](detection.md#severity-filtering). |
| `TRUSTIFY_FAIL_OPEN` | `False` | When `True`, allow operations if the Trustify API is unreachable. When `False`, treat API errors as a hard block. See [Fail-Open Behavior](detection.md#fail-open-behavior). |

The detection mode (analyze vs. search fallback) is auto-selected based on Trustify's data. No configuration change is needed.

## Upload Gate

| Setting | Default | Description |
|:--------|:--------|:------------|
| `TRUSTIFY_GATE_UPLOADS` | `True` | Block vulnerable packages at upload time via Django's `pre_save` signal. Set to `False` to disable. See [Upload Gate](upload-gate.md). |

## Scanner

| Setting | Default | Description |
|:--------|:--------|:------------|
| `TRUSTIFY_SCAN_ENABLED` | `True` | Enable the `POST /api/v3/trustify/scan/` endpoint |
| `TRUSTIFY_SCAN_REMOVE_CONTENT` | `True` | Create new repository version excluding vulnerable content |
| `TRUSTIFY_SCAN_QUARANTINE_REPO` | `""` | Quarantine repo name prefix (e.g., `"quarantine"` creates `"quarantine-python"`). Empty disables quarantine. See [Scanner Actions](scanner.md#scanner-actions). |
| `TRUSTIFY_SCAN_LABEL_CONTENT` | `True` | Tag vulnerable content with `trustify.*` labels in `pulp_labels` |
| `TRUSTIFY_SCAN_ADVISORY` | `True` | Record a `ScanAdvisory` per finding |
| `TRUSTIFY_SCAN_SCHEDULE` | `""` | Periodic scan interval (e.g., `"6h"`, `"1d"`, `"30m"`). Empty disables periodic scanning. See [Automation](scanner.md#automation). |
| `TRUSTIFY_SCAN_ON_CONTENT_CHANGE` | `False` | Dispatch scan when a new repository version is created (sync, upload, or any content change). See [Automation](scanner.md#automation). |
| `TRUSTIFY_BATCH_SIZE` | `100` | Number of PURLs per batch `/analyze` call (scanner only) |

## Yank Warnings

| Setting | Default | Description |
|:--------|:--------|:------------|
| `TRUSTIFY_YANK_VULNERABLE` | `True` | Inject PEP 592 `data-yanked` into Simple API responses. Requires `TRUSTIFY_URL` for live queries; falls back to scanner labels without it. See [Yank Warnings](yank.md). |
| `TRUSTIFY_YANK_MAX_CVES` | `3` | Maximum number of CVE URLs in the yanked reason string |

## NPM Protection

| Setting | Default | Description |
|:--------|:--------|:------------|
| `TRUSTIFY_DEPRECATE_VULNERABLE` | `True` | Inject `deprecated` fields in NPM packument responses for vulnerable versions. Requires `pulp_npm`. See [NPM Deprecation](deprecate.md). |
| `TRUSTIFY_NPM_BLOCK_DOWNLOADS` | `False` | Remove vulnerable version entries from NPM packument responses. npm cannot resolve or install filtered versions. Default `False` — deprecation warnings with Trustify URLs are shown instead. **Do not attach a `TrustifyGuard` to NPM distributions** — npm suppresses deprecation warnings when the tarball download is blocked, hiding the Trustify URLs. The guard is designed for PyPI distributions where yank warnings display before the download. See [Version Filtering](deprecate.md#version-filtering). |

## Recommended Configuration

Two operational profiles balance strictness vs. availability:

### Strict (default)

Gate enabled + guard attached + periodic scanning. Syncs fail on vulnerable content, guard covers retroactive CVEs.

```bash
PULP_TRUSTIFY_GATE_UPLOADS=True
PULP_TRUSTIFY_SCAN_SCHEDULE=6h
PULP_TRUSTIFY_SCAN_ON_CONTENT_CHANGE=False
```

Attach a `TrustifyGuard` to distributions. Syncs fail entirely if any package is vulnerable — no vulnerable content enters. The guard blocks downloads of content that becomes vulnerable after sync (CVEs disclosed between scheduled scans).

### Permissive

Gate disabled + event-driven scanner + guard attached. Syncs always succeed, scanner remediates post-sync, guard covers the interim.

```bash
PULP_TRUSTIFY_GATE_UPLOADS=False
PULP_TRUSTIFY_SCAN_ON_CONTENT_CHANGE=True
PULP_TRUSTIFY_SCAN_SCHEDULE=""
```

Attach a `TrustifyGuard` to distributions. Syncs always succeed — vulnerable content enters the repository and is selectively removed post-sync. The guard blocks downloads during the async remediation window.

## Observability

| Setting | Default | Description |
|:--------|:--------|:------------|
| `TRUSTIFY_LOG_LEVEL` | `"INFO"` | Log verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) |
| `TRUSTIFY_ENRICH_DETAILS` | `True` | Include Trustify vulnerability URLs in error messages, logs, and advisory records. URLs are constructed locally from `TRUSTIFY_URL` — no extra API calls. |

### Where Logs Appear

| Pod | Modules |
|:----|:--------|
| Content App (`pulp-content`) | `guard.py`, `gate.py` |
| API App (`pulp-api`) | `upload.py`, `yank.py` |
| Worker (`pulp-worker`) | `app/tasks/scanner.py`, `scanner.py` |

`client.py` logs appear in all pod types.

### Debugging

```bash
kubectl set env deployment/pulp-content -n pulp PULP_TRUSTIFY_LOG_LEVEL=DEBUG
kubectl logs -n pulp deployment/pulp-content | grep pulp_trustify
```

Expected output at `DEBUG` level when a download is blocked:

```
pulp_trustify.guard: Guard checking path: .../urllib3-2.6.2-py3-none-any.whl
pulp_trustify.guard: Resolved PURL: 'pkg:pypi/urllib3@2.6.2'
pulp_trustify.client.client: POST .../analyze with 1 PURLs
pulp_trustify.gate: PURL 'pkg:pypi/urllib3@2.6.2' has 1 CVEs at or above 'critical'
pulp_trustify.gate: Blocking 'pkg:pypi/urllib3@2.6.2': CVE-2026-21441
```

Expected scanner progression in worker logs:

```
pulp_trustify...scanner: Scan task started for repository '<uuid>'
pulp_trustify...scanner: Scanning content for vulnerabilities
pulp_trustify.scanner: Processing batch 1/1 (3 PURLs)
pulp_trustify...scanner: PURL 'pkg:pypi/urllib3@2.6.2' has 1 CVEs at or above 'critical':
  CVE-2026-21441 (critical)
    https://trustify.example.com/vulnerabilities/CVE-2026-21441
pulp_trustify...scanner: Removing vulnerable content: removing 1 vulnerable items
```
