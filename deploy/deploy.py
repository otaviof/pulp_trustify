#!/usr/bin/env python3
"""Deploy pulp_trustify to a Kubernetes cluster.

Patches the Pulp Operator CR with plugin-specific fields
(image, env vars, CA trust) and waits for rollout.

Requires: kubectl, a running cluster with the Pulp Operator
installed, and an existing Pulp CR (default name: 'pulp',
override with --cr-name).
"""

import argparse
import json
import os
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path

CA_CONFIGMAP = "trustify-ca-bundle"
CA_KEY = "ca-bundle.crt"
COMPONENTS = ("api", "content", "worker")
POD_LABEL = "app.kubernetes.io/component in (api,content,worker)"
ROLLOUT_TIMEOUT = "120s"
HEALTH_DELAY = 5
REQUIRED_VARS = (
    "PULP_DEPLOY_NAMESPACE",
    "IMAGE_REPOSITORY",
    "IMAGE_NAMESPACE",
    "IMAGE_NAME",
    "IMAGE_TAG",
)

DRY_RUN = False
CR_NAME = "pulp"
PULP_DEPLOY_NAMESPACE = ""


def run(
    cmd: Sequence[str],
    *,
    capture: bool = False,
    pipe_input: str | None = None,
) -> subprocess.CompletedProcess[str] | None:
    if DRY_RUN:
        print(f"  [dry-run] {' '.join(cmd)}")
        return None
    try:
        return subprocess.run(
            cmd,
            check=True,
            text=True,
            input=pipe_input,
            capture_output=capture,
        )
    except subprocess.CalledProcessError as exc:
        msg = f"(rc={exc.returncode}): {' '.join(cmd)}"
        print(f"ERROR: command failed {msg}", file=sys.stderr)
        if exc.stderr:
            print(exc.stderr, file=sys.stderr)
        sys.exit(exc.returncode)


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse key=value pairs from a .env file."""
    result: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        result[key.strip()] = val.strip().strip("\"'")
    return result


def step_ca_configmap(ca_cert: str) -> None:
    if not Path(ca_cert).is_file():
        if DRY_RUN:
            print(f"  [dry-run] CA cert {ca_cert} not found, skipping")
            return
        print(f"ERROR: CA cert {ca_cert} not found", file=sys.stderr)
        sys.exit(1)

    print(f"==> Creating configmap {CA_CONFIGMAP}...")
    create = f"""\
kubectl create configmap {CA_CONFIGMAP}
  --namespace={PULP_DEPLOY_NAMESPACE}
  --from-file={CA_KEY}={ca_cert}
  --dry-run=client --output yaml""".split()

    result = run(create, capture=True)
    run(
        "kubectl apply --filename -".split(),
        pipe_input=result.stdout if result else None,
    )


def build_env_list(
    env_vars: dict[str, str],
) -> list[dict[str, str]]:
    return [{"name": k, "value": v} for k, v in sorted(env_vars.items())]


def step_patch_cr(
    image_base: str,
    image_tag: str,
    env_vars: dict[str, str],
    ca_enabled: bool,
) -> None:
    print(f"==> Patching Pulp CR with image {image_base}:{image_tag}...")

    env_list = build_env_list(env_vars)
    spec: dict = {"image": image_base, "image_version": image_tag}
    if ca_enabled:
        spec["mount_trusted_ca"] = True
        spec["mount_trusted_ca_configmap_key"] = f"{CA_CONFIGMAP}:{CA_KEY}"

    for comp in COMPONENTS:
        spec[comp] = {"env_vars": env_list}

    patch = json.dumps({"spec": spec})
    cmd = f"""\
kubectl patch pulp {CR_NAME}
  --namespace={PULP_DEPLOY_NAMESPACE}
  --type merge --patch""".split()
    cmd.append(patch)
    run(cmd)


def step_rollout() -> None:
    print("==> Deleting pods to force image re-pull...")
    cmd = f"""\
kubectl delete pods --namespace={PULP_DEPLOY_NAMESPACE} --wait=false""".split()
    run(cmd + ["--selector", POD_LABEL])

    print("==> Waiting for rollout...")
    for deploy in (f"{CR_NAME}-{c}" for c in COMPONENTS):
        check = f"""\
kubectl get deployment {deploy} --namespace={PULP_DEPLOY_NAMESPACE}""".split()
        rollout = f"""\
kubectl rollout status deployment/{deploy}
  --namespace={PULP_DEPLOY_NAMESPACE}
  --timeout={ROLLOUT_TIMEOUT}""".split()

        if DRY_RUN:
            run(check)
            run(rollout)
            continue

        r = subprocess.run(check, capture_output=True, text=True)
        if r.returncode == 0:
            run(rollout)

    print("==> Checking pod health...")
    if not DRY_RUN:
        time.sleep(HEALTH_DELAY)

    jsonpath = (
        "{.items[?(@.status.containerStatuses[0]"
        '.state.waiting.reason=="CrashLoopBackOff")]'
        ".metadata.name}"
    )
    cmd = f"""\
kubectl get pods --namespace={PULP_DEPLOY_NAMESPACE}""".split()
    cmd += ["--selector", POD_LABEL, "--output", f"jsonpath={jsonpath}"]

    result = run(cmd, capture=True)
    crashed = result.stdout.strip() if result else ""
    if crashed:
        print(f"ERROR: CrashLoopBackOff: {crashed}", file=sys.stderr)
        print(
            f"Check logs: kubectl logs --namespace "
            f"{PULP_DEPLOY_NAMESPACE} "
            f"{crashed.split()[0]}",
            file=sys.stderr,
        )
        sys.exit(1)


def main() -> None:
    global DRY_RUN, CR_NAME, PULP_DEPLOY_NAMESPACE

    parser = argparse.ArgumentParser(
        description="Deploy pulp_trustify to Kubernetes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Steps:
  1. CA ConfigMap  create trustify-ca-bundle (if PULP_TRUSTIFY_CA_BUNDLE is set)
  2. Patch CR      image, env vars, CA fields via kubectl patch --type merge
  3. Rollout       delete pods, wait for deployments, check for CrashLoopBackOff

Environment variables:
  PULP_DEPLOY_NAMESPACE     target namespace (required)
  IMAGE_REPOSITORY          container registry (required)
  IMAGE_NAMESPACE           registry namespace (required)
  IMAGE_NAME                image name (required)
  IMAGE_TAG                 image tag (required)
  PULP_TRUSTIFY_CA_BUNDLE   CA cert path (optional)
  PULP_TRUSTIFY_*           patched into the CR as env vars
""",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print commands without executing",
    )
    parser.add_argument(
        "--cr-name",
        default="pulp",
        help="Pulp CR instance name (default: pulp)",
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        type=Path,
        help="path to .env file (default: .env)",
    )
    opts = parser.parse_args()
    DRY_RUN = opts.dry_run
    CR_NAME = opts.cr_name

    env_file = opts.env_file
    if not env_file.is_file():
        print(
            f"ERROR: {env_file} not found",
            file=sys.stderr,
        )
        sys.exit(1)

    defaults = parse_env_file(env_file)

    def get(key: str) -> str:
        """Shell env > .env fallback."""
        return os.environ.get(key, defaults.get(key, ""))

    missing = [v for v in REQUIRED_VARS if not get(v)]
    if missing:
        print(
            f"ERROR: missing required vars: {', '.join(missing)}",
            file=sys.stderr,
        )
        sys.exit(1)

    PULP_DEPLOY_NAMESPACE = get("PULP_DEPLOY_NAMESPACE")
    ca_cert = get("PULP_TRUSTIFY_CA_BUNDLE")
    image_base = "/".join(
        (
            get("IMAGE_REPOSITORY"),
            get("IMAGE_NAMESPACE"),
            get("IMAGE_NAME"),
        )
    )
    image_tag = get("IMAGE_TAG")

    if DRY_RUN:
        print("[dry-run — no commands will execute]\n")
    print(f"==> Container image: {image_base}:{image_tag}")

    env_vars = {
        k: os.environ.get(k, v)
        for k, v in defaults.items()
        if k.startswith("PULP_TRUSTIFY_")
    }

    ca_enabled = bool(ca_cert)
    if ca_enabled:
        step_ca_configmap(ca_cert)
    else:
        print("==> PULP_TRUSTIFY_CA_BUNDLE not set, skipping CA configmap")

    step_patch_cr(image_base, image_tag, env_vars, ca_enabled)
    step_rollout()
    print("==> Done.")


if __name__ == "__main__":
    main()
