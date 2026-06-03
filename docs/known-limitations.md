# Known Limitations

Single source of truth for all caveats and constraints across `pulp_trustify`. Feature documents link here instead of inlining limitation bullets.

## General

- **PyPI packages only.** The PURL registry currently supports wheels (`.whl`) and sdists (`.tar.gz`, `.zip`). Additional ecosystems can be added via `@register` / `@register_content` decorators — see [PURL Extraction](architecture.md#purl-extraction).
- **Requires a Trustify instance with at least one importer active.** Without ingested advisory data, the analyze endpoint returns empty and the search fallback has nothing to query. See [Trustify Importer Requirements](detection.md#trustify-importer-requirements).
- **`fail_open` behavior.** When Trustify is unreachable and `TRUSTIFY_FAIL_OPEN=True`, all operations are allowed. When `False` (default), API errors produce a hard block. See [Detection Pipeline](detection.md#fail-open-behavior).
- **Search fallback is heuristic.** Version range parsing relies on regex patterns matching CVE description text. Some phrasings may not be recognized, leading to false negatives. See [Search Fallback Mode](detection.md#search-fallback-mode).

For Trustify's own limitations on vulnerability correlation, see the [Trustify Vulnerability Correlation Overview](https://docs.guac.sh/trustify/vulnerability-correlation-overview/).

## Download Guard

- **Explicit attachment required.** The guard only applies to distributions where a `TrustifyGuard` instance has been explicitly attached. Distributions without a guard serve all content without checks.
- **Per-request latency.** Each download triggers a Trustify API call (30s timeout). Under high concurrency, this adds latency to every download.
- **Content app URL only.** The guard runs in the Pulp Content App. It does not intercept requests through other paths.

## Upload Gate

- **Does not apply to synced content.** Django's `pre_save` signal is not fired by `bulk_create()`. Packages synced from upstream remotes via `pulp_python` sync tasks use `bulk_create()` internally, so they bypass the upload gate entirely. The download guard still catches these at serve time — vulnerable synced content will be blocked on download, not on ingestion.
- **30s timeout per Trustify query.** Each upload incurs a Trustify API call, adding latency to the upload response.
- **Requires `pulp_python`.** The gate connects to `PythonPackageContent`'s `pre_save` signal. If `pulp_python` is not installed, the gate is gracefully disabled (logged at startup).
- **Controlled by `TRUSTIFY_GATE_UPLOADS`.** Set to `False` to disable the upload gate while keeping the download guard active. See [Settings Reference](settings.md#upload-gate).

## Scanner

- **Full repository scan.** The scanner always scans the entire latest repository version. There is no incremental scanning — every scan re-checks all content.
- **Exclusive repository lock.** `scan_repository` acquires an exclusive lock on the repository, blocking concurrent syncs and scans for the duration.
- **Immutable version history.** Content removal creates a new repository version. Previous versions (containing vulnerable content) remain in Pulp's version history. There is no "undo" — content must be re-added explicitly.
- **Orphaned quarantine repos.** Quarantine repositories created before the typed-quarantine feature (which creates `prefix-type_suffix` repos like `quarantine-python`) are orphaned and must be cleaned up manually.
- **Window of exposure.** Between a repository version being finalized and the scan task executing, newly synced vulnerable content is available for download. Attach a `TrustifyGuard` to the distribution for zero-window protection. See [Automation](scanner.md#automation).
- **Event-driven full re-scan.** Event-driven scans re-scan the entire repository, not just newly added content. This is by design (catches retroactive CVEs) but adds load proportional to repository size.
- **`_current_task` is a private API.** The self-trigger prevention for event-driven scanning uses `pulpcore.app.contexts._current_task`, a private ContextVar. No public accessor exists in pulpcore 3.112.

## Yank Warnings

- **Repo-only distributions.** Yank warnings only apply to distributions that serve content directly from a repository (not publication-based distributions).
- **API app URL required.** The `YankMiddleware` runs in Django's request/response cycle (API App). Pip must use the API app URL (`/pypi/<dist>/simple/`), not the content app URL (`/pulp/content/<dist>/simple/`).
- **Scanner labels required.** Yank warnings read `trustify.vulnerable` and `trustify.cves` labels from `pulp_labels`. These labels are set by the scanner's label action. Packages that have not been scanned (or were scanned with `TRUSTIFY_SCAN_LABEL_CONTENT=False`) will not show yank warnings.
