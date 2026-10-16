# ---
# relationships:
#   verifies: test-ci
# ---

"""Exercise the CI runner with a controlled Go command."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


RUNNER = Path(__file__).with_name("test-ci.sh")


class CIRunnerTests(unittest.TestCase):
    def run_runner(self, output, status=0):
        with tempfile.TemporaryDirectory() as directory:
            go = Path(directory) / "go"
            go.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*" > "$ARGUMENTS"\n'
                'printf "%s\\n" "$OUTPUT"\nexit "$STATUS"\n',
                encoding="utf-8",
            )
            go.chmod(0o755)
            arguments = Path(directory) / "arguments"
            result = subprocess.run(
                ["bash", str(RUNNER)],
                env={**os.environ, "PATH": directory + os.pathsep + os.environ["PATH"],
                     "ARGUMENTS": str(arguments), "OUTPUT": output, "STATUS": str(status)},
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(arguments.read_text().strip(), "test -count=1 -v ./...")
            self.assertIn(output, result.stdout)
            return result

    def test_pass(self):
        self.assertEqual(self.run_runner("PASS").returncode, 0)

    def test_go_failure_propagates(self):
        self.assertNotEqual(self.run_runner("FAIL", 1).returncode, 0)

    def test_missing_prerequisites_fail(self):
        for reason in ["bao executable not available; set WYRWOOD_BAO",
                       "Docker Engine not reachable", "test image alpine:3.22 not present"]:
            with self.subTest(reason=reason):
                result = self.run_runner(reason + "\n--- SKIP: TestFixture (0.00s)\nPASS")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("a prerequisite was missing", result.stderr)

    def test_explicit_environment_skips_remain_visible(self):
        for reason in ["cgroup v2 memory.max unavailable", "sshd test requires root"]:
            with self.subTest(reason=reason):
                self.assertEqual(self.run_runner(reason + "\n--- SKIP: TestFixture\nPASS").returncode, 0)


if __name__ == "__main__":
    unittest.main()
