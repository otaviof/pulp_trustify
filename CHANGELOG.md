# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- towncrier -->

## [0.4.0] - 2026-06-08

### Added

- Migration `0004_gateadvisory.py`
- Upload-time content labeling (`trustify.scanned`, `trustify.scanned_at`, `trustify.detected_by`, `trustify.cves`, `trustify.clean`)
- `GateAdvisorySerializer` and read-only `GateAdvisoryViewSet` at `/pulp/api/v3/trustify/gate-advisories/`
- `GateAdvisory` model recording upload gate check results with PURL, CVE IDs, severity, detection mode, and action
- `GateResult` frozen dataclass in `gate.py` for structured detection results
- `TRUSTIFY_GATE_ADVISORY` setting (default: `True`)
- `TRUSTIFY_GATE_LABEL_CONTENT` setting (default: `True`)
- `check_purl_with_mode()` function providing detection mode tracking (analyze vs. search)

### Changed

- Upload gate now labels all content (clean, below-threshold, and blocked) before deciding whether to allow or reject
- Upload gate refactored from exception-based flow (`gate_purl` raising `PermissionError`) to result-based flow (`check_purl_with_mode` returning `GateResult`)
- `_build_block_message()` extracted as standalone function for upload rejection messages

### Removed

- `_CVE_RE` regex and `_extract_cve_ids()` from `upload.py` (replaced by structured `GateResult.cve_ids`)

## [0.3.0] - 2026-06-06

### Added

- NPM audit endpoint (`/-/npm/v1/security/advisories/bulk`) implementing the full npm audit protocol
- `NpmBulkAdvisoryView` DRF view with `GzipJSONParser` for compressed payloads
- `pulp_trustify/audit.py` module with PURL conversion, batch analysis, and fallback search
- `docs/npm-audit.md` documentation
- 23 unit tests for audit module

## [0.2.0] - 2026-06-06

### Added

- `TRUSTIFY_NPM_BLOCK_DOWNLOADS` setting for opt-in version filtering in NPM deprecation
- Enhanced guard 403 messages with single-line Trustify vulnerability URLs

### Changed

- NPM deprecation defaults to advisory-only mode (warnings without blocking downloads)
- Removed `getattr` fallbacks from settings access; `settings.py` is now the single source of truth for all defaults

### Fixed

- Documented that ContentGuards should only be used on PyPI distributions (NPM suppresses deprecation warnings when tarball downloads are blocked)

## [0.1.0] - 2026-06-06

### Added

- NPM registry support across all protection layers (guard, gate, scanner, deprecation)
- NPM PURL parser (`pulp_trustify/purl/npm.py`) with scoped package handling (`@scope/pkg`)
- NPM deprecation wrapper (`pulp_trustify/deprecate.py`) injecting `deprecated` field into packument JSON
- Shared label and reason-building helpers (`pulp_trustify/labels.py`) extracted from yank/gate modules
- Semver fallback in `version.py` for exotic NPM version strings
- `semver>=3.0.0` dependency
- OSV advisory fixture for is-svg (CVE-2021-28092)
- NPM tarball fixtures for E2E testing (is-svg@4.2.1, is-number@7.0.0)
- `npm` pytest marker
- `docs/deprecate.md` documentation
- 43 new tests (NPM PURL parsing, labels, deprecation wrapper)

### Changed

- Upload gate refactored to use PURL registry dispatch for ecosystem-agnostic detection
- Yank module simplified; shared logic extracted to `labels.py`

## [0.0.1.dev] - 2026-05-25

Initial development release. All core protection layers implemented and validated against live Trustify 0.4.12.

### Added

- Project scaffold: Django app discovered via `pulpcore.plugin` entry point, co-located test layout, ruff linting, pytest, poe task runner
- Trustify HTTP client with OIDC `client_credentials` flow, custom SSL adapter, token caching with 30-second expiry buffer
- PURL builder registry with pluggable parsers (PyPI)
- Severity threshold comparison and vulnerability filtering
- **Download Guard** (`TrustifyGuard` ContentGuard): real-time per-request blocking with dual-mode detection (analyze + search fallback)
- **Upload Gate** (`pre_save` signal): upload-time CVE gating for `PythonPackageContent`
- **Repository Scanner** (`scan_repository` task): batch vulnerability detection across entire repositories with configurable post-detection actions (label, quarantine, remove)
- **Yank Warnings**: PEP 592 `data-yanked` attribute injection in Simple API responses with configurable CVE URLs
- Scanner automation: periodic scanning via `TaskSchedule` and event-driven scanning on repository version changes with self-trigger prevention
- Typed quarantine repositories per plugin type
- Source repository provenance labels on scanner findings
- Enriched vulnerability details with Trustify URLs (`VulnerabilityDetail`)
- `ScanAdvisory` model for persistent scanner findings
- Comprehensive structured logging across all modules
- Python deployment script with poe automation (`deploy/deploy.py`)
- Dynaconf settings: `TRUSTIFY_URL`, `TRUSTIFY_SEVERITY_THRESHOLD`, `TRUSTIFY_FAIL_OPEN`, `TRUSTIFY_GATE_UPLOADS`, `TRUSTIFY_SCAN_ENABLED`, `TRUSTIFY_SCAN_REMOVE_CONTENT`, `TRUSTIFY_SCAN_QUARANTINE_REPO`, `TRUSTIFY_YANK_VULNERABLE`, `TRUSTIFY_ENRICH_DETAILS`, `TRUSTIFY_SCAN_SCHEDULE`, `TRUSTIFY_SCAN_ON_CONTENT_CHANGE`, and connection settings
- E2E test infrastructure: Docker/Podman Compose workflow, two-phase pipeline (status/scan/guard then gate), CI workflows
- Apache v2 license
- Documentation: architecture, detection pipeline, guard, upload gate, scanner, yank, settings reference, known limitations, contributing guide

### Fixed

- Upload gate uses DRF `ValidationError` instead of bare `PermissionError` to avoid pulpcore warning
- Pyright type errors resolved across plugin and test modules
- Yank module suppresses `ImportError` for optional `pulp_python` dependency
- E2E test fixtures, response normalization, and infrastructure improvements
- Pulp health check uses service name to support all container runtimes
