#!/usr/bin/env python3
"""Create the GitHub release for a version tag, or skip when it exists already.

The release workflow can be triggered twice for the same tag (a re-run, or two
publishers). Treating an existing release as an error leaves a red badge on a
release that actually shipped, so check first and only swallow the
already-exists case. Genuine API failures still fail the step.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Callable, Optional, Sequence


class Result:
    """Minimal stand-in for subprocess.CompletedProcess, easy to fake in tests."""

    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


Runner = Callable[..., Result]


def _run_gh(*args: str) -> Result:
    process = subprocess.run(["gh", *args], capture_output=True, text=True)
    return Result(process.returncode, process.stdout, process.stderr)


def _is_not_found(result: Result) -> bool:
    text = (result.stderr + result.stdout).lower()
    return "release not found" in text or "http 404" in text


def _is_already_exists(result: Result) -> bool:
    text = (result.stderr + result.stdout).lower()
    return "already exists" in text or "already_exists" in text


def create_release(tag: str, run_gh: Runner, out: Callable[[str], None] = print) -> int:
    """Return 0 if the release exists or was created, 1 only on a real failure."""
    if not tag:
        out("TAG is required")
        return 2

    viewed = run_gh("release", "view", tag, "--json", "tagName")
    if viewed.returncode == 0:
        out(f"Release {tag} already exists; skipping creation.")
        return 0
    if not _is_not_found(viewed):
        # Not a confirmed "missing": an API or auth failure must not be papered over.
        out(viewed.stderr.strip() or f"Could not check release {tag}")
        return 1

    created = run_gh(
        "release", "create", tag,
        "--generate-notes", "--verify-tag", "--title", tag,
    )
    if created.returncode == 0:
        return 0

    # Only an already-exists failure, confirmed by a successful view, counts as a race.
    if _is_already_exists(created) and run_gh(
        "release", "view", tag, "--json", "tagName"
    ).returncode == 0:
        out(f"Release {tag} was created concurrently; treating as already released.")
        return 0

    out(created.stderr.strip() or f"Could not create release {tag}")
    return 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    tag = args[0] if args else os.environ.get("TAG", "")
    if not tag:
        print("TAG is required", file=sys.stderr)
        return 2
    if shutil.which("gh") is None:
        print("gh is required", file=sys.stderr)
        return 2
    return create_release(tag, _run_gh)


if __name__ == "__main__":
    raise SystemExit(main())
