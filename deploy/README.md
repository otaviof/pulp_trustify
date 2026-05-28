# Deployment Guide

Deploy `pulp_trustify` to a Kubernetes cluster with the Pulp Operator.

## Quick Start

```bash
# Preview deployment commands without executing
poe deploy --dry-run

# Deploy to the cluster
poe deploy
```

Or invoke the script directly:

```bash
python deploy/deploy.py
python deploy/deploy.py --dry-run
```

## Requirements

- **Python 3.11+**
- **kubectl** configured for your cluster
- **Pulp Operator** installed with an existing `Pulp` CR (default name: `pulp`, override with `--cr-name`)
- **Container image** built and pushed to a registry
- **`.env` file** with Trustify credentials

## What It Does

The deployment script executes three steps:

1. **CA ConfigMap** (conditional) — Creates `trustify-ca-bundle` ConfigMap if `PULP_TRUSTIFY_CA_BUNDLE` is set
2. **Patch CR** — Updates the Pulp CR with image, env vars, and CA trust fields via `kubectl patch --type merge`
3. **Rollout** — Deletes pods, waits for deployments, checks for CrashLoopBackOff

All env vars are patched **directly into the CR as plain values** (no Kubernetes Secret). The tradeoff: values are visible in `kubectl get pulp -o yaml`. For production with strict RBAC, this simplifies debugging and removes a sync point between Secret and CR.

## Environment Variables

### Required

These must be set in your shell environment or `.env` file:

| Variable | Description |
|:---------|:------------|
| `PULP_DEPLOY_NAMESPACE` | Kubernetes namespace (e.g., `pulp`) |
| `IMAGE_REPOSITORY` | Container registry (e.g., `ghcr.io`) |
| `IMAGE_NAMESPACE` | Registry namespace (e.g., `otaviof`) |
| `IMAGE_NAME` | Image name (e.g., `pulp_trustify`) |
| `IMAGE_TAG` | Image tag (e.g., `latest`) |

### Optional

| Variable | Default | Description |
|:---------|:--------|:------------|
| `PULP_TRUSTIFY_CA_BUNDLE` | `""` | Path to CA cert file (e.g., `tmp/ca-bundle.crt`). If unset, CA `ConfigMap` step is skipped. |
| `PULP_TRUSTIFY_*` | — | Any var starting with `PULP_TRUSTIFY_` is patched into the CR as an env var. |

### Variable Precedence

**Shell environment > `.env` > poe defaults**

1. The script reads `.env` to discover which `PULP_TRUSTIFY_*` variables exist
2. For each var, it checks the process environment first
3. Falls back to the `.env` value if unset

**Example:**

```bash
# Override IMAGE_REPOSITORY for one deployment
IMAGE_REPOSITORY=ghcr.io poe deploy

# CI overrides secrets from workflow environment
# (local .env provides defaults)
```

## Script Flags

```
--dry-run         Print commands without executing
--cr-name NAME    Pulp CR instance name (default: pulp)
--env-file PATH   Path to .env file (default: .env)
```

**Dry-run example:**

```bash
python deploy/deploy.py --dry-run
```

## Image Variables

The final image reference is built as:

```
${IMAGE_REPOSITORY}/${IMAGE_NAMESPACE}/${IMAGE_NAME}:${IMAGE_TAG}
```

Poe task defaults (override in shell or `.env`):

- `IMAGE_REPOSITORY=ghcr.io`
- `IMAGE_NAMESPACE=otaviof`
- `IMAGE_NAME=pulp_trustify`
- `IMAGE_TAG=latest`

**Full deployment workflow:**

```bash
# 1. Build and push image
poe image-build
poe image-push

# 2. Deploy to cluster
poe deploy
```

## Manual Deployment (without the script)

The deploy script automates the [Pulp Operator](https://docs.pulpproject.org/pulp_operator/) CR patching, but the plugin only needs three things regardless of how you deploy Pulp:

1. **Container image**: the plugin image must be accessible to the cluster (built from the project `Containerfile`)
2. **Environment variables**: all `PULP_TRUSTIFY_*` vars must be set on the api, content, and worker pods (see the Settings Reference in [README.md](../README.md#settings-reference))
3. **CA trust** (optional): if Trustify uses a private CA, mount the certificate bundle and set `PULP_TRUSTIFY_CA_BUNDLE` to its path inside the container

These requirements apply regardless of the deployment
method (Operator CR, Helm, plain manifests, etc.).

## Example `.env` File

```bash
# Deployment
PULP_DEPLOY_NAMESPACE=pulp
IMAGE_REPOSITORY=ghcr.io
IMAGE_NAMESPACE=otaviof
IMAGE_NAME=pulp_trustify
IMAGE_TAG=latest

# Trustify connection (patched into CR)
PULP_TRUSTIFY_URL=https://trustify.example.com
PULP_TRUSTIFY_ISSUER_URL=https://sso.example.com/realms/trustify
PULP_TRUSTIFY_CLIENT_ID=cli
PULP_TRUSTIFY_CLIENT_SECRET=<secret>
PULP_TRUSTIFY_SEVERITY_THRESHOLD=critical
PULP_TRUSTIFY_FAIL_OPEN=false

# Optional CA bundle
PULP_TRUSTIFY_CA_BUNDLE=/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
```