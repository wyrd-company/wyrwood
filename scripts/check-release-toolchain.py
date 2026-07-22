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

SUPPORTED_GORELEASER = {"v2.17.0": (1, 26, 4)}
SETUP_GO_ACTION = "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16"


class ContractError(ValueError):
    """The release toolchain declarations are inconsistent."""


def parse_version(value: str, label: str) -> tuple[int, int, int]:
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value) is None:
        raise ContractError(f"{label} must be an exact three-part Go version, got {value!r}")
    major, minor, patch = value.split(".")
    return int(major), int(minor), int(patch)


def module_go_version() -> tuple[int, int, int]:
    contents = GO_MOD.read_text(encoding="utf-8")
    if re.search(r"^\s*toolchain\b", contents, re.MULTILINE) is not None:
        raise ContractError(
            "go.mod must not contain a toolchain directive; its Go directive is the release source"
        )
    matches = re.findall(r"^go\s+(\S+)\s*$", contents, re.MULTILINE)
    if len(matches) != 1:
        raise ContractError("go.mod must contain exactly one Go directive")
    return parse_version(matches[0], "go.mod Go directive")


def workflow_step_blocks() -> list[tuple[Path, str]]:
    blocks: list[tuple[Path, str]] = []
    for workflow in sorted(WORKFLOWS.iterdir()):
        if workflow.suffix not in {".yml", ".yaml"}:
            continue
        lines = workflow.read_text(encoding="utf-8").splitlines(keepends=True)
        for index, line in enumerate(lines):
            item = re.match(r"^(\s*)-\s+", line)
            if item is None:
                continue
            indentation = len(item.group(1).expandtabs())
            end = index + 1
            while end < len(lines):
                candidate = lines[end]
                if candidate.strip() == "" or candidate.lstrip().startswith("#"):
                    end += 1
                    continue
                candidate_indentation = len(candidate) - len(candidate.lstrip())
                if candidate_indentation <= indentation:
                    break
                end += 1
            blocks.append((workflow, "".join(lines[index:end])))
    return blocks


def action_steps(action: str) -> list[tuple[Path, str]]:
    pattern = re.compile(rf"^\s*(?:-\s*)?uses:\s+{re.escape(action)}", re.MULTILINE)
    return [(workflow, step) for workflow, step in workflow_step_blocks() if pattern.search(step)]


def goreleaser_contract() -> tuple[str, tuple[int, int, int]]:
    taskfile = TASKFILE.read_text(encoding="utf-8")
    module_pins = set(
        re.findall(r"github\.com/goreleaser/goreleaser/v2@(v[0-9]+\.[0-9]+\.[0-9]+)", taskfile)
    )
    if len(module_pins) != 1:
        raise ContractError(
            f"Taskfile must use one GoReleaser version, got {sorted(module_pins)}"
        )
    version = next(iter(module_pins))

    release_steps = action_steps("goreleaser/goreleaser-action@")
    if len(release_steps) != 1:
        raise ContractError(f"expected one hosted GoReleaser action step, found {len(release_steps)}")
    _, release_step = release_steps[0]
    action_versions = set(
        re.findall(
            r"^\s+version:\s+(v[0-9]+\.[0-9]+\.[0-9]+)\s*$",
            release_step,
            re.MULTILINE,
        )
    )
    if action_versions != {version}:
        raise ContractError(
            f"hosted and Taskfile GoReleaser versions must both be {version}, got {sorted(action_versions)}"
        )
    if version not in SUPPORTED_GORELEASER:
        raise ContractError(
            f"GoReleaser {version} has no reviewed minimum Go version in SUPPORTED_GORELEASER"
        )
    return version, SUPPORTED_GORELEASER[version]


def validate_setup_go_steps() -> None:
    setup_steps = action_steps("actions/setup-go@")

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
        goreleaser_version, minimum_go = goreleaser_contract()
        validate_setup_go_steps()
        if selected_go < minimum_go:
            selected = ".".join(map(str, selected_go))
            required = ".".join(map(str, minimum_go))
            raise ContractError(
                f"go.mod selects Go {selected}, but GoReleaser {goreleaser_version} requires Go >= {required}"
            )
    except (ContractError, OSError, UnicodeError) as error:
        print(f"check-release-toolchain: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
