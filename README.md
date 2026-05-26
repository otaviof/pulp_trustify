# `pulp_trustify`

Pulp plugin integrating [Trustify](https://trustify.dev/) CVE intelligence for vulnerability-gated artifact serving. When attached to a Pulp distribution as a `ContentGuard`, the plugin queries Trustify's vulnerability analysis API at download time and blocks artifacts that have CVEs at or above a configurable severity threshold.

## How It Works

1. A client requests a package download (e.g., `pip install`)
2. Pulp's Content App invokes `TrustifyGuard.permit(request)`
3. The guard extracts a [Package URL](https://github.com/package-url/purl-spec)
   from the request path (currently supports PyPI wheels and sdists)
4. The guard queries Trustify in one of two modes (see Detection Modes
   below)
5. Vulnerabilities matching the severity threshold produce a
   `403 Forbidden`

### Detection Modes

The guard operates in two modes, trying **analyze** first and falling
back to **search** when needed:

#### Analyze Mode (Preferred)

- Calls `POST /api/v2/vulnerability/analyze` with the package PURL
- Requires Trustify's OSV or CSAF importers to be enabled
- Server-side version matching with scheme-aware comparison
- For PyPI, requires the [PyPA Advisory Database](https://github.com/pypa/advisory-database)
  OSV importer

When OSV data is available, this is the most reliable detection method.

#### Search Fallback Mode

- Automatically triggered when `analyze` returns empty results
- Searches Trustify's vulnerability endpoint by package name
- Parses version ranges from CVE description text using regex
- Compares versions client-side using `packaging.version`

This mode enables vulnerability detection when only the CVE importer
is active (no OSV data). It is best-effort: version range parsing is
heuristic, and some CVE phrasings may not be recognized.

**The guard always tries analyze first.** The fallback is transparent:
no configuration change is needed. When you enable the OSV importer,
the guard automatically switches to analyze mode.

### Trustify Importer Requirements

The plugin's behavior depends on which importers are enabled on your
Trustify instance:

| Importer | Detection Mode | Notes |
|:---------|:--------------|:------|
| **OSV** (advisory-database) | Analyze mode | Preferred. Server-side version matching. For PyPI, use the PyPA Advisory Database: `https://github.com/pypa/advisory-database` |
| **CVE** (cvelistV5) | Search fallback mode | Default in many deployments. Client-side version parsing from CVE description text. Best-effort heuristic. |
| **CSAF** (vendor advisories) | Analyze mode | Vendor-specific (e.g., Red Hat). Not applicable for PyPI. |
| **None** | Blocks or allows all | If no importers are active: `fail_open=True` allows all downloads, `fail_open=False` blocks all. |

To get full coverage for PyPI packages, enable the PyPI OSV importer
in Trustify:

```json
{
  "osv": {
    "source": "https://github.com/pypa/advisory-database",
    "path": "vulns",
    "disabled": false,
    "period": "6h"
  }
}
```

The guard works immediately with only the CVE importer active
(fallback mode), but analyze mode is more reliable once OSV data is
ingested.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Tasks

All project tasks are managed via [Poe the Poet](https://poethepoet.naez.com/):

| Task | Command | Description |
|:-----|:--------|:------------|
| Lint | `poe lint` | Run ruff linter checks |
| Fix | `poe fix` | Auto-fix lint violations |
| Format check | `poe fmt-check` | Verify code formatting |
| Format | `poe fmt` | Apply code formatting |
| Test | `poe test` | Run unit tests |
| **All checks** | `poe check` | Lint + format + test |
| Image build | `poe image-build` | Build the plugin container image |
| Image push | `poe image-push` | Push to the dev registry |

### Test Layout

Unit tests live side-by-side with source files using `*_test.py` naming (e.g., `guard.py` and `guard_test.py`). Integration tests are marked with `@pytest.mark.integration` and require network access plus a `.env` file with Trustify credentials.

```bash
# Run integration tests
pytest -m integration
```

## Deployment

The plugin ships as a container image extending `pulp/pulp-minimal`. All Pulp components (API, Content App, Worker) use this same image — the Pulp Operator manages entrypoints.

### 1. Build and Push the Image

```bash
poe image-build
poe image-push
```

The image reference is configured in `pyproject.toml` under `[tool.poe.env]` (`IMAGE_REPOSITORY`, `IMAGE_NAMESPACE`, `IMAGE_TAG`).

### 2. Configure the Pulp Operator

The plugin needs three things on the cluster: the custom image, a CA bundle for internal TLS, and Trustify connection settings via `PULP_`-prefixed env vars (read by Dynaconf at runtime).

#### Create the CA ConfigMap

```bash
kubectl create configmap trustify-ca-bundle -n pulp \
  --from-file=ca-bundle.crt=tmp/lan-ca.crt
```

#### Patch the Pulp CR

```bash
kubectl patch pulp pulp -n pulp --type merge -p '{
  "spec": {
    "image": "registry.rachael.home.lan/pulp-trustify",
    "image_version": "latest",
    "mount_trusted_ca": true,
    "mount_trusted_ca_configmap_key": "trustify-ca-bundle:ca-bundle.crt",
    "content": {
      "env_vars": [
        {"name": "PULP_TRUSTIFY_URL", "value": "https://trustify.rachael.home.lan"},
        {"name": "PULP_TRUSTIFY_ISSUER_URL", "value": "https://sso.rachael.home.lan/realms/trustify"},
        {"name": "PULP_TRUSTIFY_CLIENT_ID", "value": "cli"},
        {"name": "PULP_TRUSTIFY_CLIENT_SECRET", "value": "<secret>"},
        {"name": "PULP_TRUSTIFY_SEVERITY_THRESHOLD", "value": "critical"},
        {"name": "PULP_TRUSTIFY_FAIL_OPEN", "value": "false"},
        {"name": "PULP_TRUSTIFY_CA_BUNDLE", "value": "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"}
      ]
    },
    "api": {
      "env_vars": [
        {"name": "PULP_TRUSTIFY_URL", "value": "https://trustify.rachael.home.lan"},
        {"name": "PULP_TRUSTIFY_ISSUER_URL", "value": "https://sso.rachael.home.lan/realms/trustify"},
        {"name": "PULP_TRUSTIFY_CLIENT_ID", "value": "cli"},
        {"name": "PULP_TRUSTIFY_CLIENT_SECRET", "value": "<secret>"},
        {"name": "PULP_TRUSTIFY_SEVERITY_THRESHOLD", "value": "critical"},
        {"name": "PULP_TRUSTIFY_FAIL_OPEN", "value": "false"},
        {"name": "PULP_TRUSTIFY_CA_BUNDLE", "value": "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"}
      ]
    }
  }
}'
```

The Operator restarts all pods automatically after patching.

### 3. Settings Reference

| Setting | Default | Description |
|:--------|:--------|:------------|
| `TRUSTIFY_URL` | `""` | Trustify API base URL |
| `TRUSTIFY_API_VERSION` | `"v2"` | Trustify API version |
| `TRUSTIFY_CLIENT_ID` | `"cli"` | OIDC client ID |
| `TRUSTIFY_CLIENT_SECRET` | `""` | OIDC client secret |
| `TRUSTIFY_ISSUER_URL` | `""` | OIDC issuer URL (Keycloak realm) |
| `TRUSTIFY_CA_BUNDLE` | `""` | Path to CA certificate bundle |
| `TRUSTIFY_SEVERITY_THRESHOLD` | `"critical"` | Minimum severity to block (`low`, `medium`, `high`, `critical`) |
| `TRUSTIFY_FAIL_OPEN` | `False` | If `True`, allow downloads when Trustify API calls fail (applies to both analyze and search fallback modes) |

All settings are read via Dynaconf. Set them as `PULP_TRUSTIFY_*` env
vars on the Pulp pods.

**Note:** The guard automatically chooses the detection mode based on
Trustify's data. No configuration change is needed to switch between
analyze and search fallback modes.

### 4. Create and Attach the Guard

```bash
# Create a TrustifyGuard instance
curl -X POST https://pulp.example.com/api/v3/contentguards/trustify/guard/ \
  -u admin:<password> \
  -H "Content-Type: application/json" \
  -d '{"name": "trustify-guard"}'

# Attach the guard to a distribution
curl -X PATCH https://pulp.example.com/api/v3/distributions/python/pypi/<uuid>/ \
  -u admin:<password> \
  -H "Content-Type: application/json" \
  -d '{"content_guard": "/api/v3/contentguards/trustify/guard/<guard-uuid>/"}'
```

### 5. Verify

```bash
# Plugin appears in Pulp status
curl -s https://pulp.example.com/api/v3/status/ | \
  python3 -c "import sys,json; [print(v['component'], v['version']) \
  for v in json.load(sys.stdin)['versions'] \
  if v['component']=='trustify']"

# Download a vulnerable package (should return 403)
# Works in both analyze mode (with OSV) and search fallback mode
# (CVE-only)
curl -o /dev/null -w "%{http_code}" \
  https://pulp.example.com/pulp/content/<dist>/urllib3-2.6.2-py3-none-any.whl

# Download a fixed package (should return 200)
curl -o /dev/null -w "%{http_code}" \
  https://pulp.example.com/pulp/content/<dist>/urllib3-2.7.0-py3-none-any.whl
```

#### Verify Detection Mode

Check which mode the guard is using by examining Trustify's data:

```bash
# Check if OSV data is available (analyze mode indicator)
curl -X POST https://trustify.example.com/api/v2/vulnerability/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"purls": ["pkg:pypi/urllib3@2.6.2"]}'

# If analyze returns CVE details -> analyze mode active
# If analyze returns {} -> search fallback mode active
```
