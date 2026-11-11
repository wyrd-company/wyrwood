#!/usr/bin/env python3
# ---
# relationships:
#   validates: docs
# ---

"""Check docs/user/docs.yml with the wyrd.foo publisher that publishes it.

The publisher version is the commit pinned by the `uses:` line in
.github/workflows/publish-docs.yml, so the check and the publish move together.
The check runs the publisher's own `validate` command with `--offline`: it
needs no token and no release tag. An unmet publishing requirement, such as a
release that does not exist yet, is a warning; a schema error fails.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parent.parent
PUBLISH_WORKFLOW = Path(".github/workflows/publish-docs.yml")
PUBLISHER_REPOSITORY = "wyrd-company/wyrd.foo"
PUBLISHER_URL = f"https://github.com/{PUBLISHER_REPOSITORY}.git"
REUSABLE_WORKFLOW = f"{PUBLISHER_REPOSITORY}/.github/workflows/publish-docs.yml"
USES = re.compile(rf"^\s*uses:\s*{re.escape(REUSABLE_WORKFLOW)}@(\S+)", re.MULTILINE)
FULL_SHA = re.compile(r"[0-9a-f]{40}")

Runner = Callable[..., subprocess.CompletedProcess]


class CheckError(RuntimeError):
    """The check could not run against the pinned publisher."""


def publisher_pin(workflow: str) -> str:
    """Return the commit that the publish workflow pins the publisher to."""
    refs = USES.findall(workflow)
    if len(refs) != 1:
        raise CheckError(
            f"{PUBLISH_WORKFLOW} must call {REUSABLE_WORKFLOW} exactly once; found {len(refs)}"
        )
    if FULL_SHA.fullmatch(refs[0]) is None:
        raise CheckError(f"{PUBLISH_WORKFLOW} must pin {REUSABLE_WORKFLOW} to a full commit SHA, got {refs[0]!r}")
    return refs[0]


def validate_command(publisher: Path, repository: Path) -> list[str]:
    """The publisher command that checks the repository's working tree."""
    return ["node", str(publisher / "publisher" / "cli.ts"), "validate", str(repository), "--offline"]


def environment() -> dict[str, str]:
    """The process environment without Git repository overrides."""
    clean = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    clean["COREPACK_ENABLE_DOWNLOAD_PROMPT"] = "0"
    return clean


def check_out(pin: str, directory: Path, run: Runner) -> None:
    """Check out the publisher at the pinned commit into an empty directory."""
    env = environment()
    run(["git", "init", "--quiet", str(directory)], check=True, env=env)
    run(["git", "-C", str(directory), "fetch", "--quiet", "--depth", "1", PUBLISHER_URL, pin], check=True, env=env)
    run(["git", "-C", str(directory), "checkout", "--quiet", "--detach", "FETCH_HEAD"], check=True, env=env)
    head = run(
        ["git", "-C", str(directory), "rev-parse", "HEAD"], check=True, env=env, capture_output=True, text=True
    ).stdout.strip()
    if head != pin:
        raise CheckError(f"publisher checkout is at {head}, not the pinned {pin}")


def run_check(repository: Path, publisher: Path, run: Runner = subprocess.run) -> int:
    """Validate the repository with the pinned publisher; return the validate exit code."""
    pin = publisher_pin((repository / PUBLISH_WORKFLOW).read_text(encoding="utf-8"))
    print(f"publisher: {REUSABLE_WORKFLOW}@{pin}", flush=True)
    check_out(pin, publisher, run)
    env = environment()
    run(["corepack", "pnpm", "install", "--frozen-lockfile"], check=True, cwd=publisher, env=env)
    return run(validate_command(publisher, repository), check=False, env=env).returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repository", type=Path, default=ROOT, help="repository to check (default: this one)")
    arguments = parser.parse_args(argv)
    try:
        with tempfile.TemporaryDirectory(prefix="wyrd-foo-publisher-") as temporary:
            return run_check(arguments.repository.resolve(), Path(temporary) / "wyrd.foo")
    except (CheckError, subprocess.CalledProcessError) as error:
        print(f"check-docs-publisher: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
