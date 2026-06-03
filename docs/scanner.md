# Scanner

A Pulp dispatched task that proactively walks repository content, detects vulnerabilities, and applies configurable remediation actions.

The scanner covers the **past** — it detects packages already in the repository that have had CVEs disclosed since they were uploaded.

### Key Differences from Guard/Gate

| | Scanner | Guard / Gate |
|:--|:--------|:-------------|
| **Scope** | Entire repository | Single request |
| **Timing** | On-demand / periodic | Real-time |
| **Action** | Label, quarantine, remove, advisory | Block access (403 / 400) |
| **Performance** | Batch API calls | Per-request API calls |

## When to Use

- Detect packages that have had CVEs disclosed since they were uploaded
- Remove or quarantine newly vulnerable content from existing repositories
- Periodic repository hygiene via `TRUSTIFY_SCAN_SCHEDULE`
- Automatic scanning after sync or upload via `TRUSTIFY_SCAN_ON_CONTENT_CHANGE`

## Automation

The scanner supports two built-in automation modes that complement manual triggering.

### Periodic Scanning

Set `TRUSTIFY_SCAN_SCHEDULE` to a duration string (e.g., `"6h"`, `"1d"`, `"30m"`) to enable periodic scanning. The plugin registers a Pulpcore `TaskSchedule` that dispatches `scan_all_repositories` on the configured interval. Each dispatch iterates all repositories and dispatches individual `scan_repository` tasks.

```bash
# Enable 6-hour periodic scans
PULP_TRUSTIFY_SCAN_SCHEDULE=6h
```

Setting the value to empty (`""`) disables the schedule and removes any existing `TaskSchedule`.

### Event-Driven Scanning

Set `TRUSTIFY_SCAN_ON_CONTENT_CHANGE=True` to trigger a scan automatically when a new repository version is created. This fires after sync, upload, or any operation that creates a repository version.

```bash
PULP_TRUSTIFY_SCAN_ON_CONTENT_CHANGE=True
```

Event-driven scanning provides defense-in-depth. The upload gate checks each package at sync time via `pre_save`, but it can only detect CVEs known at that moment. The event-driven scanner re-examines all content in the new repository version, catching packages whose CVEs were disclosed between upload and the latest advisory import. This also guards against the possibility that a future pulpcore version or custom sync stage bypasses `.save()` for Content objects (see [Known Limitations](known-limitations.md#upload-gate)).

> **Operational difference:** Event-driven scanning provides selective remediation (remove, label, or quarantine individual packages) vs. the gate's all-or-nothing sync failure. It queries the same Trustify data as the gate, so it doesn't catch additional CVEs — it provides a different remediation mode.

**Self-trigger prevention:** The scanner creates new repository versions when removing content. The signal handler checks the current task name via `_current_task` ContextVar and skips versions created by `scan_repository` to prevent infinite loops.

**Debounce:** The `scan_repository` task acquires an exclusive lock on the repository. If a scan is already queued or running, the new dispatch waits in line.

### Choosing an Approach

| Trigger | Purpose | Catches | Setting |
|:--------|:--------|:--------|:--------|
| Periodic | Re-scan for newly disclosed CVEs | CVEs published after last scan | `TRUSTIFY_SCAN_SCHEDULE` |
| Event-driven | Defense-in-depth after content changes | Known CVEs at time of content change | `TRUSTIFY_SCAN_ON_CONTENT_CHANGE` |

Periodic and event-driven can be enabled together, they serve different purposes.

> The download guard provides real-time blocking at download time independent of scanning. Periodic scanning is the correct tool for retroactive CVEs (fires on schedule regardless of content changes).

## How It Works

1. Scan is triggered manually via REST API, automatically via schedule, or by content change signal
2. Task enumerates all content in the repository's latest version
3. Builds PURLs from content metadata (name/version fields)
4. Queries Trustify in batches (`TRUSTIFY_BATCH_SIZE`, default: 100)
5. Uses analyze mode first, falls back to search for packages without OSV data
6. Applies configurable actions: label, quarantine, remove, record advisory
7. If no vulnerabilities found, completes without creating a version

For the shared detection logic, see [Detection Pipeline](detection.md).

### Early Exits

The scanner exits early at these points:

| Condition | Log Message |
|:----------|:-----------|
| `TRUSTIFY_SCAN_ENABLED=False` | `"Scanning disabled via TRUSTIFY_SCAN_ENABLED"` |
| Repository has no versions | `"Repository '<pk>' has no content, skipping scan"` |
| No content with extractable PURLs | `"No scannable content in repository '<pk>'"` |
| No vulnerabilities found | `"No vulnerable content found in repository '<pk>'"` |

## Scanner Actions

Actions execute in order: label (non-destructive) → quarantine → remove → advisory (records which actions were taken). Any combination can be enabled independently.

| Action | Setting | Default | Description |
|:-------|:--------|:--------|:------------|
| Label | `TRUSTIFY_SCAN_LABEL_CONTENT` | `True` | Tag content with CVE metadata via `pulp_labels` |
| Quarantine | `TRUSTIFY_SCAN_QUARANTINE_REPO` | `""` | Copy vulnerable content to a typed quarantine repo |
| Remove | `TRUSTIFY_SCAN_REMOVE_CONTENT` | `True` | Remove vulnerable content from source repo |
| Advisory | `TRUSTIFY_SCAN_ADVISORY` | `True` | Record `ScanAdvisory` per finding |

See [Settings Reference](settings.md#scanner) for all scanner settings.

### Label

Tags each vulnerable content unit with metadata queryable via Pulp's `pulp_label_select` filter.

Labels applied: `trustify.vulnerable`, `trustify.cves`, `trustify.severity`, `trustify.detected_by`, `trustify.scanned`, `trustify.source_repo`.

```bash
# List all vulnerable content across all repos
pulp python content list --pulp-label-select "trustify.vulnerable=true"

# Filter by specific CVE
pulp python content list --pulp-label-select "trustify.cves~CVE-2026-21441"

# Filter by detection mode
pulp python content list --pulp-label-select "trustify.detected_by=analyze"

# Find all content quarantined from a specific repo
pulp python content list --pulp-label-select "trustify.source_repo=local-pypi"
```

The `trustify.source_repo` label records which repository the vulnerability was discovered in — useful when inspecting quarantined content.

### Quarantine

Copies vulnerable content to typed repositories before removal. Set `TRUSTIFY_SCAN_QUARANTINE_REPO` to a name prefix (e.g., `"quarantine"`). The scanner creates one quarantine repository per plugin type, matching the source repository type. For example, prefix `"quarantine"` creates `"quarantine-python"` for Python repos.

```bash
# List quarantined Python content
pulp python repository content list \
  --repository quarantine-python

# Move a package back to the original repository
pulp python repository content add \
  --repository local-pypi \
  --href /api/v3/content/python/packages/<uuid>/
```

**Upgrade note:** Existing base quarantine repositories from versions prior to typed quarantine are orphaned and can be cleaned up manually.

### Remove

Creates a new immutable repository version excluding vulnerable content. The previous version (with vulnerable content) remains in Pulp's version history.

```bash
# View repository versions after a scan
pulp python repository version list --repository local-pypi
```

### Advisory

Records a `ScanAdvisory` per finding with CVE IDs, severity, detection mode, actions taken, and enriched vulnerability details.

```bash
# List all scan advisories (no CLI subcommand — use curl)
curl https://pulp.example.com/api/v3/trustify/advisories/ \
  -u admin:<password>
```

Each advisory includes a `details` field with per-CVE enrichment:

```json
{
  "purl": "pkg:pypi/urllib3@2.6.2",
  "cve_ids": ["CVE-2026-21441"],
  "details": [
    {
      "cve_id": "CVE-2026-21441",
      "severity": "critical",
      "trustify_url": "https://trustify.example.com/vulnerabilities/CVE-2026-21441",
      "description": ""
    }
  ],
  "severity": "critical",
  "detection_mode": "analyze",
  "action": "labeled,removed"
}
```

## Triggering and Monitoring

### Trigger a Scan

There is no `pulp` CLI subcommand for scanning, use `curl` instead:

```bash
# No CLI subcommand for /trustify/scan/ — use curl
curl -X POST https://pulp.example.com/api/v3/trustify/scan/ \
  -u admin:<password> \
  -H "Content-Type: application/json" \
  -d '{
    "repository": "/api/v3/repositories/python/python/<uuid>/"
  }'
```

Response: `202 Accepted` with a task href.

### Monitor Scan Progress

```bash
pulp task show --href /api/v3/tasks/<task-uuid>/
```

Progress reports:

| Phase | Message |
|:------|:--------|
| Scanning | `"Scanning content for vulnerabilities"` |
| Removing | `"Removing vulnerable content: removing N vulnerable items"` |

### Inspect Results

```bash
# View repository versions
pulp python repository version list --repository local-pypi

# List content with labels
pulp python content list

# Query scan advisories (no CLI subcommand — use curl)
curl -u admin:<password> \
  https://pulp.example.com/api/v3/trustify/advisories/
```

See [Known Limitations — Scanner](known-limitations.md#scanner) for caveats.
