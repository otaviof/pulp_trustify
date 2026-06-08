# NPM Deprecation Warnings

Monkey-patch wrapper for `pulp_npm.app.models.NpmDistribution.content_handler` that injects `deprecated` fields into NPM packument JSON responses for versions marked vulnerable by the scanner or detected via live Trustify queries. NPM clients (`npm`, `yarn`, `pnpm`) display inline warnings before installation.

NPM deprecation is advisory — for enforcement, use the [Download Guard](guard.md).

## How It Works

When a client queries the NPM registry for package metadata (e.g., `npm view <pkg>`), the wrapper intercepts the packument response from `NpmDistribution.content_handler` and injects `deprecated` fields for vulnerable versions by querying Trustify live, with scanner labels as fallback.

```mermaid
sequenceDiagram
    participant C as npm Client
    participant A as Content App (aiohttp)
    participant N as NpmDistribution.content_handler
    participant W as Wrapper (_wrapped_content_handler)
    participant T as Trustify API

    C->>A: GET /pulp/content/<dist>/<pkg>
    A->>N: content_handler(path)
    N->>W: (monkey-patched)
    W->>N: Call original content_handler
    N-->>W: Response (packument JSON)
    W->>T: POST /analyze (batch PURLs for all versions)
    T-->>W: vulnerability results
    W->>W: Inject deprecated fields
    W-->>A: Modified response
    A-->>C: Packument with deprecated metadata
    C->>C: npm warn deprecated <pkg>@<version>: <reason>
```

### Guard Checks

The wrapper skips processing when any of these conditions is false:

1. `pulp_npm` is installed
2. `TRUSTIFY_DEPRECATE_VULNERABLE` is enabled (default: `True`)
3. Response body is not empty
4. Content-Type is `application/json` or `text/plain` (pulp_npm serves packuments as `text/plain`)
5. Packument has a `versions` object

All checks are fail-safe: any exception during injection is caught, logged at `ERROR` level, and the original response is returned unmodified. The wrapper never blocks a packument response, it only adds metadata.

## How NPM Deprecation Works

NPM's registry protocol includes a `deprecated` field in packument version objects. When present, NPM clients display the deprecation message as a warning during installation. The warning is advisory — clients still allow installation of deprecated versions.

`pulp_trustify` uses this mechanism to surface vulnerability information directly in the package manager workflow. The scanner labels vulnerable packages, and the wrapper translates those labels into `deprecated` fields with Trustify CVE URLs as the reason.

## Version Filtering

When `TRUSTIFY_NPM_BLOCK_DOWNLOADS` is enabled (default: `False`), the packument wrapper removes vulnerable version entries from the JSON response instead of merely marking them deprecated. This makes npm treat filtered versions as non-existent — they cannot be resolved or installed.

> **Why disabled by default:** npm only shows deprecation warnings for packages that successfully download. When a `TrustifyGuard` blocks the tarball with 403, npm aborts before displaying the warning — the developer sees a generic `403 Forbidden` with no Trustify URL. With version filtering disabled and no guard, npm shows `npm warn deprecated pkg@ver: Vulnerable package flagged by Trustify: <url>`, giving developers actionable context. **Do not attach a `TrustifyGuard` to NPM distributions** — use it only for PyPI, where yank warnings display before the download.

```mermaid
sequenceDiagram
    participant C as npm Client
    participant A as Content App
    participant W as Wrapper (_wrapped_content_handler)
    participant T as Trustify API

    C->>A: GET /pulp/content/<dist>/<pkg>
    A->>W: content_handler (wrapped)
    W->>T: POST /analyze (batch PURLs for all versions)
    T-->>W: vulnerability results
    alt BLOCK mode (TRUSTIFY_NPM_BLOCK_DOWNLOADS=True)
        W->>W: Remove vulnerable versions from packument
        W->>W: Re-target dist-tags to latest safe version
        W-->>A: Packument with versions removed
        A-->>C: Response
        C->>C: npm ERR! code ETARGET
        C->>C: npm ERR! notarget No matching version found
    else WARN mode (TRUSTIFY_NPM_BLOCK_DOWNLOADS=False)
        W->>W: Inject deprecated fields
        W-->>A: Packument with deprecated metadata
        A-->>C: Response
        C->>C: npm warn deprecated <pkg>@<version>: <reason>
    end
```

### Fallback Behavior

When **all** versions of a package are vulnerable, version filtering falls back to deprecation mode to avoid serving an empty packument. This ensures the registry remains functional while still warning users about the risk. In this scenario, enable the download guard to enforce blocking at the tarball download stage.

### dist-tag Retargeting

NPM uses `dist-tags` (e.g., `latest`, `next`) as symbolic pointers to specific versions. When version filtering removes the version a tag points to, the wrapper re-targets the tag to the highest remaining safe version (semver sorted). If no safe versions remain, the tag is removed from the packument.

Example: If `lodash@4.17.21` is tagged as `latest` but is vulnerable, and `4.17.20` is safe, the wrapper re-targets `latest` to `4.17.20`.

### Configuration Matrix

| DEPRECATE | BLOCK | Guard | Behavior |
|:----------|:------|:------|:---------|
| `True` | `False` | No | **Warn (default, recommended)** — deprecation warnings with Trustify URLs shown, packages install with advisory |
| `True` | `True` | No | Warn + filter — vulnerable versions hidden from resolution, all-vulnerable fallback shows deprecation warning |
| `True` | `False` | Yes | Warn suppressed — guard blocks tarball download, but npm hides the deprecation warning (poor UX) |
| `True` | `True` | Yes | Strict block — vulnerable versions hidden, guard blocks direct tarball, but no Trustify URL visible to npm |

The recommended configuration for NPM is `DEPRECATE=True`, `BLOCK=False`, **no guard**. This ensures developers see Trustify URLs in `npm install` output. The guard is designed for PyPI distributions where pip shows yank warnings before attempting the download.

### Expected npm Output

When version filtering blocks a version:

```
$ npm install lodash@4.17.21
npm ERR! code ETARGET
npm ERR! notarget No matching version found for lodash@4.17.21.
npm ERR! notarget In most cases you or one of your dependencies are requesting
npm ERR! notarget a package version that doesn't exist.
```

When all versions are vulnerable (fallback to deprecation):

```
$ npm install lodash@4.17.21
npm warn deprecated lodash@4.17.21: Vulnerable package flagged by Trustify: https://trustify.example.com/vulnerabilities/CVE-2024-1234
```

### Defense-in-Depth

Version filtering operates at the packument metadata level. Clients that bypass packument resolution and request tarball URLs directly (e.g., `curl https://pulp.example.com/.../lodash-4.17.21.tgz`) will not encounter version filtering. Attach a `TrustifyGuard` to distributions to block direct tarball downloads. See [Download Guard](guard.md).

## npm CLI

```
$ npm install lodash@4.17.20
npm warn deprecated lodash@4.17.20: Vulnerable package flagged by Trustify:
- https://trustify.example.com/vulnerabilities/CVE-2024-1234
- https://trustify.example.com/vulnerabilities/CVE-2024-5678
- https://trustify.example.com/vulnerabilities/CVE-2024-9012
```

`TRUSTIFY_YANK_MAX_CVES` (default: 3) limits the number of CVE URLs in the reason string. This setting is shared with [Yank Warnings](yank.md).

## Pulp CLI

Check whether deprecation metadata is present in the packument response:

```bash
# Query packument directly (Content App URL)
curl -sSk 'https://pulp.example.com/pulp/content/my-npm-repo/lodash'

# Look for "deprecated" field in version objects
curl -sSk 'https://pulp.example.com/pulp/content/my-npm-repo/lodash' \
  | jq '.versions["4.17.20"].deprecated'
```

Expected output:

```
"Vulnerable package flagged by Trustify:\n- https://trustify.example.com/vulnerabilities/CVE-2024-1234\n- https://trustify.example.com/vulnerabilities/CVE-2024-5678\n- https://trustify.example.com/vulnerabilities/CVE-2024-9012"
```

## Content App vs API App

NPM deprecation **only works with the Content App URL**. The wrapper patches `NpmDistribution.content_handler`, which runs in the Pulp Content App (aiohttp), not in Django's request/response cycle.

This is the **opposite** of [Yank Warnings](yank.md), which only work with the API App URL. The difference is architectural: PyPI Simple API responses are served by Django, while NPM packuments are served by the Content App's async handler.

```bash
# Correct (Content App — packument responses, deprecation active)
npm install --registry https://pulp.example.com/pulp/content/my-npm-repo/ lodash

# Wrong (if using API app URL — no packument responses here)
# NPM does not use the API app for registry operations
```

## Interaction with Download Guard

When both NPM deprecation and download guard are active, they form a two-phase flow:

```mermaid
sequenceDiagram
    participant C as npm Client
    participant A as Content App
    participant W as Deprecation Wrapper
    participant G as TrustifyGuard

    Note over C,G: Phase 1: Packument Resolution (Content App)
    C->>A: GET /pulp/content/<dist>/lodash
    A->>W: content_handler (wrapped)
    W->>W: Inject deprecated fields (live query)
    A-->>C: Packument with deprecated metadata
    C->>C: npm warn deprecated lodash@4.17.20

    Note over C,G: Phase 2: Download (Content App)
    C->>A: GET /pulp/content/<dist>/lodash-4.17.20.tgz
    A->>G: permit(request)
    G->>G: check_purl (analyze + search fallback)
    G-->>A: Deny (PermissionError)
    A-->>C: 403 Forbidden
```

The warning gives context **before** the hard block.

See [Known Limitations — NPM Deprecation](known-limitations.md#npm-deprecation) for caveats.
