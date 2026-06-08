# Upload Gate

A Django `pre_save` signal handler that blocks uploads of vulnerable packages before they are persisted. Supports both Python packages (`PythonPackageContent`) and NPM packages (`Package`). The gate builds a PURL from the content metadata and checks it against Trustify.

The upload gate covers the **future**, it prevents new vulnerable packages from entering the repository.

> The gate blocks the entire sync when any package is vulnerable. This is strict by design — syncs fail entirely if any single package is vulnerable. Enable event-driven scanning (`TRUSTIFY_SCAN_ON_CONTENT_CHANGE=True`) as an alternative for selective post-sync remediation when sync availability is a priority.

## How It Works

```mermaid
flowchart TD
    A["pre_save fires on<br/>content model"] --> B["content_to_purl(instance)<br/>extract PURL via registry"]
    B --> C["check_purl(purl)<br/>analyze + search fallback"]
    C -- "clean" --> D["Return (save proceeds)<br/>201 Created"]
    C -- "CVEs found" --> E["raise ValidationError<br/>400 Bad Request"]
```

For the detection logic internals, see [Detection Pipeline](detection.md).

## Signal Wiring

The upload gate connects at Django startup via `AppConfig.ready()`:

```mermaid
flowchart TD
    A["Django startup"] --> B["AppConfig.ready()"]
    B --> C["connect_signal()<br/>(PyPI)"]
    B --> D["connect_npm_signal()<br/>(NPM)"]
    C --> E{"import PythonPackageContent<br/>from pulp_python?"}
    D --> F{"import Package<br/>from pulp_npm?"}
    E -- ImportError --> G["PyPI gate NOT connected"]
    E -- Success --> H["pre_save.connect(upload_gate)"]
    F -- ImportError --> I["NPM gate NOT connected"]
    F -- Success --> J["pre_save.connect(upload_gate)"]
```

## Verify

Upload a vulnerable package (expect 400 with CVE IDs):

```bash
pulp python content create \
  --relative-path urllib3-2.6.2-py3-none-any.whl \
  --file urllib3-2.6.2-py3-none-any.whl \
  --repository local-pypi
```

Expected error:

```
Error: Task failed: Blocked due to CVE: CVE-2026-21441
Details:
  https://trustify.example.com/vulnerabilities/CVE-2026-21441
```

Enrichment is controlled by `TRUSTIFY_ENRICH_DETAILS` (default: `True`). See [Settings Reference](settings.md).

See [Known Limitations — Upload Gate](known-limitations.md#upload-gate) for caveats.
