#!/usr/bin/env python3
"""E2E workflow orchestrator for pulp_trustify.

Manages the compose-based test environment (PostgreSQL, Trustify + Pulp) and runs
tests inside a runner container on the same network.  Run with ``--help`` for
subcommands and environment variable reference.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
COMPOSE_FILE = SCRIPT_DIR / "compose.e2e.yml"
FIXTURES_DIR = SCRIPT_DIR / "e2e" / "fixtures"
GATE_OVERRIDE = SCRIPT_DIR / "compose.e2e.gate.yml"


def _require(*names: str) -> dict[str, str]:
    """Read required environment variables or exit.

    Returns a dict of name->value for all requested vars. Prints every missing
    variable before exiting so the caller can fix them all at once.
    """
    values: dict[str, str] = {}
    missing: list[str] = []
    for name in names:
        val = os.environ.get(name, "")
        if not val:
            missing.append(name)
        else:
            values[name] = val
    if missing:
        print(f"ERROR: missing env vars: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)
    return values


def _compose() -> list[str]:
    """Return the compose base command with the file flag."""
    env = _require("COMPOSE")
    return env["COMPOSE"].split() + ["-f", str(COMPOSE_FILE)]


def _compose_gate() -> list[str]:
    """Compose command with gate override."""
    return _compose() + ["-f", str(GATE_OVERRIDE)]


def run(
    cmd: list[str],
    env: dict[str, str] | None = None,
):
    """Run a shell command, exit on failure."""
    print(f"==> Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, env=env or os.environ.copy())
    if result.returncode != 0:
        print(f"ERROR: command failed (rc={result.returncode})", file=sys.stderr)
        sys.exit(result.returncode)


def compose_exec(service: str, cmd: str):
    """Run a command inside a compose service."""
    run(_compose() + ["exec", service, "bash", "-c", cmd])


def cmd_up():
    """Start the compose stack, wait for runner, seed data.

    The runner container depends on pulp (healthy), which depends on trustify
    (healthy), which depends on postgres (healthy).  Once the runner is up, all
    services are ready.
    """
    _require("COMPOSE")

    print("==> Starting compose stack")
    run(_compose() + ["up", "-d", "--build"])

    print("==> Waiting for runner container")
    run(_compose() + ["up", "-d", "runner"])

    print("==> Seeding test advisories")
    cmd_seed()

    print("==> E2E environment ready")
    print("    Trustify: http://trustify:8080 (inside network)")
    print("    Pulp:     http://pulp:80 (inside network)")
    print("    Credentials: admin / password")


def cmd_down():
    """Tear down the compose stack and remove volumes."""
    _require("COMPOSE")
    print("==> Tearing down compose stack")
    run(_compose() + ["down", "-v"])


def cmd_restart_pulp():
    """Restart Pulp with GATE_UPLOADS=true for phase 2.

    Uses a compose override file to inject the gate setting, avoiding host env-var
    propagation issues across container runtimes.
    """
    _require("COMPOSE")

    print("==> Stopping runner and pulp")
    run(_compose() + ["stop", "runner", "pulp"])

    print("==> Removing containers")
    rm = subprocess.run(
        _compose() + ["rm", "-f", "pulp", "runner"],
        capture_output=True,
    )
    if rm.returncode != 0:
        runtime = os.environ.get("CONTAINER_RUNTIME", "podman")
        for svc in (
            "tests_runner_1",
            "tests_pulp_1",
        ):
            subprocess.run([runtime, "rm", "-f", svc], capture_output=True)

    print("==> Starting pulp with GATE_UPLOADS=true")
    run(_compose_gate() + ["up", "-d", "pulp"])

    print("==> Waiting for pulp to become healthy")
    _wait_for_pulp_health()

    print("==> Starting runner")
    run(_compose_gate() + ["up", "-d", "runner"])

    print("==> Cleaning orphaned content from phase 1")
    compose_exec(
        "runner",
        "cd /src && python3 tests/workflow.py cleanup",
    )

    print("==> Re-seeding advisories after restart")
    compose_exec(
        "runner",
        "cd /src && python3 tests/workflow.py seed",
    )

    print("==> Pulp restarted with gating enabled")


def _wait_for_pulp_health(timeout: int = 180):
    """Poll compose ps until pulp reports healthy."""
    import time

    start = time.time()
    while time.time() - start < timeout:
        result = subprocess.run(
            _compose() + ["ps"],
            capture_output=True,
            text=True,
        )
        for line in result.stdout.splitlines():
            if "pulp" in line and "healthy" in line and "postgres" not in line:
                return
        time.sleep(5)
    print(
        f"ERROR: pulp did not become healthy within {timeout}s",
        file=sys.stderr,
    )
    sys.exit(1)


def cmd_seed():
    """Upload OSV advisories to Trustify.

    When TRUSTIFY_URL is set (inside the compose network), uploads directly via
    Python requests.  Otherwise execs into the runner container to re-invoke this
    command.
    """
    advisories = sorted(FIXTURES_DIR.glob("PYSEC-*.json"))
    if not advisories:
        print("WARN: no PYSEC-*.json in fixtures, skipping seed")
        return

    trustify_url = os.environ.get("TRUSTIFY_URL", "")
    if trustify_url:
        _upload_advisories(trustify_url)
    else:
        print("==> Seeding advisories via runner container")
        compose_exec(
            "runner",
            "cd /src && python3 tests/workflow.py seed",
        )


def _upload_advisories(trustify_url: str):
    """POST each advisory JSON to Trustify."""
    import requests as http

    advisories = sorted(FIXTURES_DIR.glob("PYSEC-*.json"))
    if not advisories:
        print("WARN: no PYSEC-*.json files found, skipping seed")
        return

    print(f"==> Seeding {len(advisories)} advisories to {trustify_url}")
    for path in advisories:
        url = f"{trustify_url}/api/v2/advisory?format=osv"
        resp = http.post(
            url,
            data=path.read_bytes(),
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        doc_id = resp.json().get("document_id", "ok")
        print(f"    {path.name}: {doc_id}")
    print("==> Seed successful")


def cmd_cleanup():
    """Delete orphaned content units between test phases.

    Runs inside the runner container where PULP_URL is available.  Triggers Pulp's
    orphan cleanup and waits for the task to complete.
    """
    import time

    import requests as http

    pulp = os.environ.get("PULP_URL", "http://pulp:80")
    auth = (
        os.environ.get("PULP_USERNAME", "admin"),
        os.environ.get("PULP_PASSWORD", "password"),
    )

    resp = http.post(
        f"{pulp}/pulp/api/v3/orphans/cleanup/",
        json={},
        auth=auth,
    )
    resp.raise_for_status()
    task_href = resp.json()["task"]
    print(f"    orphan cleanup task: {task_href}")

    for _ in range(30):
        tr = http.get(f"{pulp}{task_href}", auth=auth)
        tr.raise_for_status()
        state = tr.json()["state"]
        if state == "completed":
            print("    orphan cleanup complete")
            return
        if state == "failed":
            print("ERROR: orphan cleanup failed", file=sys.stderr)
            sys.exit(1)
        time.sleep(2)

    print("ERROR: orphan cleanup timed out", file=sys.stderr)
    sys.exit(1)


def cmd_status():
    """Print health status of Trustify and Pulp.

    When PULP_URL is set (inside the compose network), checks services directly.
    Otherwise execs into the runner container to re-invoke this command.
    """
    pulp_url = os.environ.get("PULP_URL", "")
    if pulp_url:
        _check_health()
    else:
        _require("COMPOSE")
        compose_exec(
            "runner",
            "cd /src && python3 tests/workflow.py status",
        )


def _check_health():
    """Check service health from inside the network."""
    import requests as http

    services = {
        "Trustify": os.environ.get("TRUSTIFY_URL", "http://trustify:8080")
        + "/openapi/",
        "Pulp": os.environ.get("PULP_URL", "http://pulp:80")
        + "/pulp/api/v3/status/",
    }

    print("==> Checking service health")
    for name, url in services.items():
        try:
            resp = http.get(url, timeout=5)
            ok = "OK" if resp.ok else f"FAIL ({resp.status_code})"
        except http.RequestException:
            ok = "FAIL (unreachable)"
        print(f"    {name:12s} {ok}")


def cmd_test():
    """Run E2E tests inside the runner container.

    Executes pytest from /src with the container's env vars (TRUSTIFY_URL,
    PULP_URL, etc.).
    """
    _require("COMPOSE")
    compose_exec(
        "runner",
        "cd /src && pytest -p no:pulp_rpm -m 'e2e and not gate' --verbose",
    )


def cmd_test_gate():
    """Run gate tests inside the runner container."""
    _require("COMPOSE")
    compose_exec(
        "runner",
        "cd /src && pytest -p no:pulp_rpm -m gate --verbose",
    )


def main():
    """Parse subcommands and dispatch."""
    parser = argparse.ArgumentParser(
        description="E2E workflow orchestrator for pulp_trustify",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
environment (set via poe tasks in pyproject.toml):
  COMPOSE            compose command
""",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("up", help="start compose stack and seed data")
    sub.add_parser("down", help="tear down compose stack")
    sub.add_parser("restart-pulp", help="restart Pulp with GATE_UPLOADS=true")
    sub.add_parser("seed", help="seed advisories to Trustify")
    sub.add_parser("cleanup", help="delete orphaned content between phases")
    sub.add_parser("status", help="check service health")
    sub.add_parser("test", help="run E2E tests (status, scan, guard)")
    sub.add_parser(
        "test-gate",
        help="run gate tests (requires GATE_UPLOADS=true)",
    )

    args = parser.parse_args()

    dispatch = {
        "up": cmd_up,
        "down": cmd_down,
        "restart-pulp": cmd_restart_pulp,
        "seed": cmd_seed,
        "cleanup": cmd_cleanup,
        "status": cmd_status,
        "test": cmd_test,
        "test-gate": cmd_test_gate,
    }
    dispatch[args.command]()


if __name__ == "__main__":
    main()
