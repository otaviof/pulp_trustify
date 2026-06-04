# Detection Pipeline

How `pulp_trustify` queries [Trustify](https://github.com/guacsec/trustify) to determine whether a package is vulnerable. All four protection layers share this logic via `gate.py`. Single-PURL checks use `check_purl()`; batch checks (scanner, yank) use `check_purls()`.

See [Trustify Vulnerability Correlation Overview](https://docs.guac.sh/trustify/vulnerability-correlation-overview/) for how Trustify correlates advisories to packages upstream.

## Dual-Mode Detection

The plugin tries the **analyze** endpoint first and falls back to **search** when analyze returns empty results:

```mermaid
flowchart LR
    A["check_purl(purl)"] --> B["analyze(purl)"]
    B -- "results" --> C["filter by severity"]
    B -- "empty" --> D["fallback_search(purl)"]
    D --> C
    C -- "CVEs found" --> E["Return CVE IDs"]
    C -- "clean" --> F["Return []"]
```

No configuration change is needed to switch between modes — the fallback is transparent.

### Analyze Mode (Preferred)

- Calls `POST /api/{version}/vulnerability/analyze` with the package PURL
- Server-side version matching with scheme-aware comparison
- Requires Trustify's OSV or CSAF importers to have ingested advisory data
- For PyPI, requires the [PyPA Advisory Database](https://github.com/pypa/advisory-database) OSV importer

### Search Fallback Mode

Automatically triggered when analyze returns empty results. Searches Trustify by package name, then performs client-side version matching.

The `fallback_search()` function:

1. Extracts package name and version from the PURL
2. Queries `GET /api/{version}/vulnerability?q={name}`
3. Parses version ranges from CVE description text using four regex patterns
4. Compares versions client-side using PEP 440 (`packaging.version.Version`)
5. Filters results by severity threshold

**Version range patterns** recognized by `version.py`:

| Pattern | Example Text |
|:--------|:-------------|
| `_RANGE_PATTERN` | "Starting in version 1.22 and prior to version 2.6.3" |
| `_FROM_PATTERN` | "From 1.23 to before 2.7.0" |
| `_THROUGH_PATTERN` | "versions 1.0 through 2.0" |
| `_BEFORE_PATTERN` | "prior to version 2.6.3" |

This mode is best-effort: version range parsing is heuristic, and some CVE phrasings may not be recognized.

## Severity Filtering

`policy.py` defines the severity scale used by all protection layers:

| Level | Numeric Value |
|:------|:-------------|
| `low` | 0 |
| `medium` | 1 |
| `high` | 2 |
| `critical` | 3 |

`filter_vulnerabilities(details, threshold)` keeps entries whose severity is at or above the threshold. The threshold is configured via `TRUSTIFY_SEVERITY_THRESHOLD` (default: `"critical"`). See [Settings Reference](settings.md).

## Verify Detection Mode

Operators can determine which detection mode is active by checking the plugin logs. At `DEBUG` level, the logs show which path was taken:

```
# Analyze mode active (OSV data available):
pulp_trustify.gate: Analyze returned 2 items for 'pkg:pypi/urllib3@2.6.2'

# Search fallback mode active (no OSV data):
pulp_trustify.gate: Analyze empty for 'pkg:pypi/urllib3@2.6.2', falling back to search
```

To enable the preferred analyze mode, ensure at least the PyPI OSV importer is configured in Trustify. See [Trustify Importer Requirements](#trustify-importer-requirements) below.

## Timeouts and Retries

All Trustify API calls use a **30-second timeout** with **no automatic retries**. OIDC token fetch uses a 10-second timeout. A single transient network failure will block or allow the operation depending on `fail_open`.

## Fail-Open Behavior

When Trustify is unreachable:

- `TRUSTIFY_FAIL_OPEN=True` — log a warning, allow the operation
- `TRUSTIFY_FAIL_OPEN=False` (default) — raise `PermissionError`, block the operation

This applies to both analyze and search fallback modes. Because there are no retries, a transient Trustify outage with `fail_open=False` will block all downloads and uploads until Trustify recovers.

## Trustify Importer Requirements

The plugin's detection accuracy depends on which importers are enabled on your Trustify instance:

| Importer | Detection Mode | Notes |
|:---------|:--------------|:------|
| **OSV** (advisory-database) | Analyze mode | Preferred. Server-side version matching. For PyPI, use the PyPA Advisory Database. |
| **CVE** (cvelistV5) | Search fallback | Default in many deployments. Client-side version parsing from description text. Best-effort. |
| **CSAF** (vendor advisories) | Analyze mode | Vendor-specific (e.g., Red Hat). Not applicable for PyPI. |
| **None** | Blocks or allows all | `fail_open=True` allows all, `fail_open=False` blocks all. |

See [Trustify Getting Started](https://docs.guac.sh/trustify/getting-started) for importer setup.
