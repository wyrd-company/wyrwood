#!/usr/bin/env python3
# ---
# relationships: {}
# ---

"""Tests for the Wyrwood package release manifest generator."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("create-release-manifest.py")
SPEC = importlib.util.spec_from_file_location("create_release_manifest", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReleaseManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.version = "1.2.3"
        for _, _, _, filename in MODULE.expected_artifacts(self.version):
            (self.directory / filename).write_bytes(filename.encode())

    def run_generator(self, *, version: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--artifacts-dir",
                str(self.directory),
                "--version",
                version or self.version,
                "--commit",
                "0123456789abcdef0123456789abcdef01234567",
                "--output",
                str(self.directory / "release-manifest.json"),
            ],
            check=False,
            text=True,
            capture_output=True,
        )

    def test_creates_canonical_six_artifact_manifest(self) -> None:
        result = self.run_generator()
        self.assertEqual(result.returncode, 0, result.stderr)

        manifest = json.loads((self.directory / "release-manifest.json").read_text())
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["version"], self.version)
        self.assertEqual(manifest["tag"], self.version)
        self.assertEqual(manifest["package"]["license"], "Apache-2.0")
        self.assertEqual(manifest["publish"]["aur"]["package"], "wyrwood-bin")
        self.assertEqual(len(manifest["artifacts"]), 6)
        for artifact in manifest["artifacts"]:
            contents = artifact["filename"].encode()
            self.assertEqual(artifact["sha256"], hashlib.sha256(contents).hexdigest())
            self.assertEqual(
                artifact["url"],
                f"https://github.com/wyrd-company/wyrwood/releases/download/1.2.3/{artifact['filename']}",
            )

    def test_rejects_missing_artifact(self) -> None:
        next(self.directory.glob("*.rpm")).unlink()
        result = self.run_generator()
        self.assertEqual(result.returncode, 2)
        self.assertIn("missing:", result.stderr)

    def test_rejects_unexpected_package_artifact(self) -> None:
        (self.directory / "unrelated_1.2.3_linux_x86_64.deb").write_bytes(b"unexpected")
        result = self.run_generator()
        self.assertEqual(result.returncode, 2)
        self.assertIn("unexpected:", result.stderr)

    def test_rejects_prerelease_version(self) -> None:
        result = self.run_generator(version="1.2.3-rc.1")
        self.assertEqual(result.returncode, 2)
        self.assertIn("bare stable SemVer", result.stderr)


if __name__ == "__main__":
    unittest.main()
