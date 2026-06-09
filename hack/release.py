#!/usr/bin/env python3
"""Validate, tag, push, and create a GitHub release."""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

DRY_RUN = False


def run(
    cmd: list[str],
    *,
    capture: bool = False,
) -> subprocess.CompletedProcess[str] | None:
    """Execute command with error handling and dry-run support."""
    if DRY_RUN:
        print(f"  [dry-run] {' '.join(cmd)}")
        return None
    try:
        return subprocess.run(
            cmd,
            check=True,
            text=True,
            capture_output=capture,
        )
    except subprocess.CalledProcessError as exc:
        msg = f"(rc={exc.returncode}): {' '.join(cmd)}"
        print(f"ERROR: command failed {msg}", file=sys.stderr)
        if exc.stderr:
            print(exc.stderr, file=sys.stderr)
        sys.exit(exc.returncode)


def get_version() -> str:
    """Read version from VERSION env var."""
    version = os.environ.get("VERSION", "").strip()
    if not version:
        print("ERROR: VERSION env var not set", file=sys.stderr)
        sys.exit(1)
    return version


def extract_changelog(version: str) -> str:
    """Extract changelog section for the given version."""
    content = Path("CHANGELOG.md").read_text()
    pattern = rf"## \[{re.escape(version)}\][^\n]*\n(.*?)(?=\n## \[|\Z)"
    match = re.search(pattern, content, re.DOTALL | re.MULTILINE)
    if not match:
        print(
            f"ERROR: section for version {version} not found in CHANGELOG.md",
            file=sys.stderr,
        )
        sys.exit(1)
    return match.group(1).strip()


def step_validate(version: str) -> None:
    """Validate preconditions before creating the release."""
    print(f"==> Validating release for version {version}...")

    if not re.match(r"^\d+\.\d+\.\d+$", version):
        print(
            f"ERROR: invalid version format '{version}' (expected X.Y.Z)",
            file=sys.stderr,
        )
        sys.exit(1)

    result = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    )
    if result.stdout.strip():
        print(
            "ERROR: working tree is not clean",
            file=sys.stderr,
        )
        sys.exit(1)

    result = subprocess.run(
        ["git", "branch", "--show-current"],
        capture_output=True,
        text=True,
        check=True,
    )
    branch = result.stdout.strip()
    if branch != "main":
        print(
            f"ERROR: not on main branch (current: {branch})",
            file=sys.stderr,
        )
        sys.exit(1)

    changelog_path = Path("CHANGELOG.md")
    if not changelog_path.is_file():
        print(
            "ERROR: CHANGELOG.md not found",
            file=sys.stderr,
        )
        sys.exit(1)

    changelog = changelog_path.read_text()
    if f"## [{version}]" not in changelog:
        print(
            f"ERROR: version {version} not found in CHANGELOG.md",
            file=sys.stderr,
        )
        sys.exit(1)

    result = subprocess.run(
        ["git", "tag", "-l", f"v{version}"],
        capture_output=True,
        text=True,
        check=True,
    )
    if result.stdout.strip():
        print(
            f"ERROR: tag v{version} already exists",
            file=sys.stderr,
        )
        sys.exit(1)


def step_tag_push(version: str) -> None:
    """Create and push the git tag."""
    print(f"==> Creating tag v{version}...")
    run(["git", "tag", f"v{version}"])

    print(f"==> Pushing tag v{version}...")
    run(["git", "push", "origin", f"v{version}"])


def step_github_release(version: str, body: str) -> None:
    """Create the GitHub release with changelog notes."""
    print(f"==> Creating GitHub release v{version}...")
    run(
        [
            "gh",
            "release",
            "create",
            f"v{version}",
            "--title",
            f"v{version}",
            "--notes",
            body,
        ]
    )


def main() -> None:
    """Parse args and execute the release workflow."""
    global DRY_RUN

    parser = argparse.ArgumentParser(
        description="Validate, tag, push, and create GitHub release",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Steps:
  1. Validate   version format, clean tree, main branch, changelog,
                tag existence
  2. Tag        git tag v{VERSION}
  3. Push       git push origin v{VERSION}
  4. Release    gh release create with changelog section

Requires:
  VERSION env var (set by poe release from pyproject.toml)
  Clean working tree on main branch
  CHANGELOG.md with version section
  gh CLI authenticated
""",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print commands without executing",
    )
    opts = parser.parse_args()
    DRY_RUN = opts.dry_run

    if DRY_RUN:
        print("[dry-run — no commands will execute]\n")

    version = get_version()
    step_validate(version)
    body = extract_changelog(version)

    step_tag_push(version)
    step_github_release(version, body)

    print("==> Done.")


if __name__ == "__main__":
    main()
