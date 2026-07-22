#!/usr/bin/env python3
# ---
# relationships:
#   validates: release
# ---

"""Validate that hosted releases select a Go toolchain supported by GoReleaser."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GO_MOD = ROOT / "go.mod"
TASKFILE = ROOT / "Taskfile.yml"
WORKFLOWS = ROOT / ".github" / "workflows"

GORELEASER_VERSION = "v2.17.0"
GORELEASER_MINIMUM_GO = (1, 26, 4)
SETUP_GO_ACTION = "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16"


class ContractError(ValueError):
    """The release toolchain declarations are inconsistent."""


def parse_version(value: str, label: str) -> tuple[int, int, int]:
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value) is None:
        raise ContractError(f"{label} must be an exact three-part Go version, got {value!r}")
    major, minor, patch = value.split(".")
    return int(major), int(minor), int(patch)


def module_go_version() -> tuple[int, int, int]:
    matches = re.findall(r"^go\s+(\S+)\s*$", GO_MOD.read_text(encoding="utf-8"), re.MULTILINE)
    if len(matches) != 1:
        raise ContractError("go.mod must contain exactly one Go directive")
    return parse_version(matches[0], "go.mod Go directive")


def validate_goreleaser_pins() -> None:
    taskfile = TASKFILE.read_text(encoding="utf-8")
    module_pins = set(
        re.findall(r"github\.com/goreleaser/goreleaser/v2@(v[0-9]+\.[0-9]+\.[0-9]+)", taskfile)
    )
    if module_pins != {GORELEASER_VERSION}:
        raise ContractError(
            f"Taskfile GoReleaser pins must be exactly {GORELEASER_VERSION}, got {sorted(module_pins)}"
        )

    release_workflow = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    action_versions = set(
        re.findall(
            r"^\s+version:\s+(v[0-9]+\.[0-9]+\.[0-9]+)\s*$",
            release_workflow,
            re.MULTILINE,
        )
    )
    if action_versions != {GORELEASER_VERSION}:
        raise ContractError(
            f"release workflow GoReleaser version must be exactly {GORELEASER_VERSION}, got {sorted(action_versions)}"
        )


def validate_setup_go_steps() -> None:
    setup_steps: list[tuple[Path, str]] = []
    for workflow in sorted(WORKFLOWS.iterdir()):
        if workflow.suffix not in {".yml", ".yaml"}:
            continue
        text = workflow.read_text(encoding="utf-8")
        steps = re.findall(r"(?ms)^      - name:.*?(?=^      - name:|\Z)", text)
        for step in steps:
            if "uses: actions/setup-go@" in step:
                setup_steps.append((workflow, step))

    if len(setup_steps) != 2:
        raise ContractError(f"expected two hosted setup-go steps, found {len(setup_steps)}")

    expected_use = f"uses: {SETUP_GO_ACTION}"
    for workflow, step in setup_steps:
        if expected_use not in step:
            raise ContractError(f"{workflow.relative_to(ROOT)} must pin {SETUP_GO_ACTION}")
        if re.search(r"^\s+go-version-file:\s+go\.mod\s*$", step, re.MULTILINE) is None:
            raise ContractError(f"{workflow.relative_to(ROOT)} setup-go must use go.mod")
        if re.search(r"^\s+go-version:\s+", step, re.MULTILINE) is not None:
            raise ContractError(
                f"{workflow.relative_to(ROOT)} must not override the go.mod toolchain"
            )


def main() -> int:
    try:
        selected_go = module_go_version()
        validate_goreleaser_pins()
        validate_setup_go_steps()
        if selected_go < GORELEASER_MINIMUM_GO:
            selected = ".".join(map(str, selected_go))
            required = ".".join(map(str, GORELEASER_MINIMUM_GO))
            raise ContractError(
                f"go.mod selects Go {selected}, but GoReleaser {GORELEASER_VERSION} requires Go >= {required}"
            )
    except (ContractError, OSError, UnicodeError) as error:
        print(f"check-release-toolchain: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
