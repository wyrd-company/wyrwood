#!/usr/bin/env python3
# ---
# relationships: {}
# ---

"""Tests for the docs.yml publisher check."""

from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
import unittest.mock
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-docs-publisher.py")
SPEC = importlib.util.spec_from_file_location("check_docs_publisher", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

PIN = "0123456789abcdef0123456789abcdef01234567"
OTHER = "fedcba9876543210fedcba9876543210fedcba98"
CALL = f"    uses: wyrd-company/wyrd.foo/.github/workflows/publish-docs.yml@{PIN} # 1.0.0\n"


class FakeRunner:
    """Records commands; answers rev-parse with `head` and validate with `validate_code`."""

    def __init__(self, *, head: str = PIN, validate_code: int = 0) -> None:
        self.head = head
        self.validate_code = validate_code
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, args: list[str], **options) -> subprocess.CompletedProcess:
        self.calls.append((args, options))
        if args[-2:] == ["rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(args, 0, stdout=f"{self.head}\n", stderr="")
        if "validate" in args:
            return subprocess.CompletedProcess(args, self.validate_code)
        return subprocess.CompletedProcess(args, 0)

    def commands(self) -> list[list[str]]:
        return [args for args, _ in self.calls]


class PublisherPinTests(unittest.TestCase):
    def test_reads_the_repository_publish_workflow_pin(self) -> None:
        workflow = (MODULE.ROOT / MODULE.PUBLISH_WORKFLOW).read_text(encoding="utf-8")
        pin = MODULE.publisher_pin(workflow)
        self.assertRegex(pin, r"^[0-9a-f]{40}$")
        self.assertIn(f"{MODULE.REUSABLE_WORKFLOW}@{pin}", workflow)

    def test_reads_one_call(self) -> None:
        self.assertEqual(MODULE.publisher_pin(f"jobs:\n  publish:\n{CALL}"), PIN)

    def test_ignores_a_commented_call(self) -> None:
        commented = f"    # uses: wyrd-company/wyrd.foo/.github/workflows/publish-docs.yml@{OTHER}\n"
        self.assertEqual(MODULE.publisher_pin(commented + CALL), PIN)

    def test_refuses_no_call(self) -> None:
        with self.assertRaisesRegex(MODULE.CheckError, "exactly once; found 0"):
            MODULE.publisher_pin("jobs: {}\n")

    def test_refuses_two_calls(self) -> None:
        with self.assertRaisesRegex(MODULE.CheckError, "exactly once; found 2"):
            MODULE.publisher_pin(CALL + CALL.replace(PIN, OTHER))

    def test_refuses_a_tag_ref(self) -> None:
        with self.assertRaisesRegex(MODULE.CheckError, "full commit SHA, got '2.3.0'"):
            MODULE.publisher_pin(CALL.replace(PIN, "2.3.0"))

    def test_refuses_a_short_sha(self) -> None:
        with self.assertRaisesRegex(MODULE.CheckError, "full commit SHA"):
            MODULE.publisher_pin(CALL.replace(PIN, PIN[:12]))


class RunCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repository = Path(temporary.name) / "repository"
        (self.repository / ".github" / "workflows").mkdir(parents=True)
        (self.repository / MODULE.PUBLISH_WORKFLOW).write_text(f"jobs:\n  publish:\n{CALL}", encoding="utf-8")
        self.publisher = Path(temporary.name) / "publisher"

    def test_validates_offline_with_the_publisher_at_the_pin(self) -> None:
        runner = FakeRunner()
        self.assertEqual(MODULE.run_check(self.repository, self.publisher, runner), 0)
        commands = runner.commands()
        self.assertIn(
            ["git", "-C", str(self.publisher), "fetch", "--quiet", "--depth", "1", MODULE.PUBLISHER_URL, PIN],
            commands,
        )
        self.assertEqual(MODULE.PUBLISHER_URL, "https://github.com/wyrd-company/wyrd.foo.git")
        install = commands.index(["corepack", "pnpm", "install", "--frozen-lockfile"])
        self.assertEqual(runner.calls[install][1]["cwd"], self.publisher)
        self.assertEqual(
            commands[-1],
            ["node", str(self.publisher / "publisher" / "cli.ts"), "validate", str(self.repository), "--offline"],
        )
        self.assertNotIn("--strict", commands[-1])

    def test_returns_the_validate_failure(self) -> None:
        runner = FakeRunner(validate_code=1)
        self.assertEqual(MODULE.run_check(self.repository, self.publisher, runner), 1)

    def test_refuses_a_checkout_at_another_commit(self) -> None:
        runner = FakeRunner(head=OTHER)
        with self.assertRaisesRegex(MODULE.CheckError, f"at {OTHER}, not the pinned {PIN}"):
            MODULE.run_check(self.repository, self.publisher, runner)
        self.assertFalse(any("validate" in command for command in runner.commands()))

    def test_drops_git_repository_overrides(self) -> None:
        runner = FakeRunner()
        with unittest.mock.patch.dict("os.environ", {"GIT_DIR": "/elsewhere/.git"}):
            MODULE.run_check(self.repository, self.publisher, runner)
        for _, options in runner.calls:
            self.assertNotIn("GIT_DIR", options["env"])


COMMAND = "python3 scripts/check-docs-publisher.py"


def block(text: str, header: str) -> str:
    """The lines under `header` until the next line at the same or lower indentation."""
    lines = text.splitlines()
    start = lines.index(header)
    indentation = len(header) - len(header.lstrip())
    body = []
    for line in lines[start + 1 :]:
        if line.strip() and len(line) - len(line.lstrip()) <= indentation:
            break
        body.append(line)
    return "\n".join(body)


class WiringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ci = (MODULE.ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.job = block(self.ci, "  docs-publisher:")

    def test_ci_runs_on_pull_requests(self) -> None:
        self.assertIn("pull_request:", block(self.ci, "on:").split())

    def test_ci_job_runs_the_task_command(self) -> None:
        taskfile = (MODULE.ROOT / "Taskfile.yml").read_text(encoding="utf-8")
        task_lines = [line.strip() for line in block(taskfile, "  docs:publisher:").splitlines()]
        job_lines = [line.strip() for line in self.job.splitlines()]
        self.assertEqual(task_lines.count(f"- {COMMAND}"), 1)
        self.assertEqual(job_lines.count(f"run: {COMMAND}"), 1)

    def test_ci_job_uses_no_secret(self) -> None:
        self.assertNotIn("secrets.", self.job)
        self.assertNotIn("persist-credentials: true", self.job)
        self.assertIn("persist-credentials: false", self.job)

    def test_ci_job_fetches_tags(self) -> None:
        self.assertIn("fetch-depth: 0", [line.strip() for line in self.job.splitlines()])


if __name__ == "__main__":
    unittest.main()
