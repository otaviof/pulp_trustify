# Known Limitations

Single source of truth for all caveats and constraints across `pulp_trustify`. Feature documents link here instead of inlining limitation bullets.

## General

- **PyPI and NPM packages only.** The PURL registry currently supports Python wheels (`.whl`), sdists (`.tar.gz`, `.zip`), and NPM tarballs (`.tgz`). Additional ecosystems can be added via `@register` / `@register_content` decorators — see [PURL Extraction](architecture.md#purl-extraction).
- **Requires a Trustify instance with at least one importer active.** Without ingested advisory data, the analyze endpoint returns empty and the search fallback has nothing to query. See [Trustify Importer Requirements](detection.md#trustify-importer-requirements).
- **`fail_open` behavior.** When Trustify is unreachable and `TRUSTIFY_FAIL_OPEN=True`, all operations are allowed. When `False` (default), API errors produce a hard block. See [Detection Pipeline](detection.md#fail-open-behavior).
- **Search fallback is heuristic.** Version range parsing relies on regex patterns matching CVE description text. Some phrasings may not be recognized, leading to false negatives. See [Search Fallback Mode](detection.md#search-fallback-mode).

For Trustify's own limitations on vulnerability correlation, see the [Trustify Vulnerability Correlation Overview](https://docs.guac.sh/trustify/vulnerability-correlation-overview/).

## Download Guard

- **Explicit attachment required.** The guard only applies to distributions where a `TrustifyGuard` instance has been explicitly attached. Distributions without a guard serve all content without checks.
- **Per-request latency.** Each download triggers a Trustify API call (30s timeout). Under high concurrency, this adds latency to every download.
- **Content app URL only.** The guard runs in the Pulp Content App. It does not intercept requests through other paths.

## Upload Gate

- **Covers synced content (pulpcore 3.112).** Pulpcore's `ContentSaver` stage calls `.save()` individually on each Content object during sync, which fires `pre_save`. Synced packages are checked by the upload gate at ingestion time, not only at download time. **Caveat:** The Content model's manager provides a `bulk_get_or_create()` method that bypasses signals. Future pulpcore versions or custom sync stages could use this method, re-introducing a gap. If you suspect the gate is not firing during sync, enable `DEBUG` logging and verify that `"Upload gate checking"` appears in the API/worker logs during sync operations.
- **Fails entire sync if any package is vulnerable.** The gate raises `ValidationError` on the first vulnerable package, which aborts the entire sync. No clean packages from the same sync are persisted. Enable event-driven scanning (`TRUSTIFY_SCAN_ON_CONTENT_CHANGE=True`) for selective remediation as an alternative — syncs always succeed, vulnerable content is removed post-sync. See [Scanner — Event-Driven Scanning](scanner.md#event-driven-scanning).
- **30s timeout per Trustify query.** Each upload incurs a Trustify API call, adding latency to the upload response.
- **Requires `pulp_python`.** The gate connects to `PythonPackageContent`'s `pre_save` signal. If `pulp_python` is not installed, the gate is gracefully disabled (logged at startup).
- **Controlled by `TRUSTIFY_GATE_UPLOADS`.** Set to `False` to disable the upload gate while keeping the download guard active. See [Settings Reference](settings.md#upload-gate).

## Scanner

- **Full repository scan.** The scanner always scans the entire latest repository version. There is no incremental scanning — every scan re-checks all content.
- **Exclusive repository lock.** `scan_repository` acquires an exclusive lock on the repository, blocking concurrent syncs and scans for the duration.
- **Immutable version history.** Content removal creates a new repository version. Previous versions (containing vulnerable content) remain in Pulp's version history. There is no "undo" — content must be re-added explicitly.
- **Orphaned quarantine repos.** Quarantine repositories created before the typed-quarantine feature (which creates `prefix-type_suffix` repos like `quarantine-python`) are orphaned and must be cleaned up manually.
- **Window of exposure for retroactive CVEs.** Content that was clean at sync time becomes vulnerable when new CVEs are disclosed. Between CVE publication and the next scan, vulnerable content is available for download. Attach a `TrustifyGuard` to the distribution for real-time download blocking independent of scan timing. See [Automation](scanner.md#automation).
- **Event-driven scanning does not reliably catch retroactive CVEs.** Event-driven scans only fire when a repository version is created (sync, upload, or manual content change). They do NOT fire when new CVEs are disclosed. Content that was clean at sync time becomes vulnerable only when an unrelated change happens to trigger a version creation. Use periodic scanning for retroactive CVE detection (fires on schedule regardless of content changes).
- **Event-driven full re-scan.** Event-driven scans re-scan the entire repository, not just newly added content. This is by design (re-checks all content against current advisory data) but adds load proportional to repository size.
- **`_current_task` is a private API.** The self-trigger prevention for event-driven scanning uses `pulpcore.app.contexts._current_task`, a private ContextVar. No public accessor exists in pulpcore 3.112.

## Yank Warnings

- **Repo-only distributions.** Yank warnings only apply to distributions that serve content directly from a repository (not publication-based distributions).
- **API app URL required.** The `YankMiddleware` runs in Django's request/response cycle (API App). Pip must use the API app URL (`/pypi/<dist>/simple/`), not the content app URL (`/pulp/content/<dist>/simple/`).
- **Live query with label fallback.** Yank warnings query Trustify live at index request time. If Trustify is unreachable, falls back to scanner labels. If neither is available, yank attributes are silently omitted.
- **Per-index-request latency.** Each Simple API index request triggers a Trustify `/analyze` call with all package versions. For packages with many versions, this adds latency proportional to the number of versions.

## NPM Deprecation

- **Content App dependency.** NPM deprecation runs in the Pulp Content App (aiohttp), not as Django middleware. This means it only affects requests through the content app URL (`/pulp/content/<dist>/<pkg>`), unlike yank warnings which require the API app URL.
- **Monkey-patch fragility.** The wrapper patches `NpmDistribution.content_handler`. If `pulp_npm` changes the `content_handler` signature or internals, the wrapper may break. The wrapper catches all exceptions and fails gracefully (returns unmodified response).
- **Scoped package encoding.** Scoped packages (e.g., `@scope/pkg`) are encoded as `%40scope/pkg` in PURLs. The wrapper handles this encoding when constructing PURLs for live queries, but edge cases in client encoding may not match Trustify's PURL normalization.
- **Live query with label fallback.** Like yank warnings, NPM deprecation queries Trustify live for each packument request. If Trustify is unreachable, falls back to scanner labels. If neither is available, deprecated fields are silently omitted.
- **Per-packument-request latency.** Each packument request (e.g., `npm view <pkg>`) triggers a Trustify `/analyze` call with all package versions in the packument. For packages with many versions, this adds latency proportional to the number of versions.

## NPM Audit

- **Scoped package fallback.** `fallback_search()` uses `purl_package_name()` which strips scope from scoped packages (`@angular/core` → `core`). The audit endpoint skips `fallback_search` for scoped PURLs (`%40` in PURL) and relies solely on the Trustify analyze API. Scoped packages not indexed by Trustify's analyze may not report vulnerabilities.
- **Exact version matching only.** `vulnerable_versions` uses `"=X.Y.Z"` (exact match). npm matches this against lockfile entries. Richer range data (e.g., `>=1.0.0 <2.0.0`) would require parsing advisory descriptions, which is expensive at audit scale.
- **Synchronous execution.** Unlike the scanner (async task), the audit endpoint runs synchronously. Large audit payloads with many packages may time out on slow Trustify connections.
