"""Offline executor-model checks: system-op builders and the utun lifecycle.

Builds and runs native/network-helper/system_ops_test.mm. Nothing here touches
the network; real utun creation stays behind the privileged executor.
"""
import platform
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(platform.system() == "Darwin", "Apple SDK required")
class SystemOpsModelTests(unittest.TestCase):
    def test_executor_model_is_clean(self):
        with tempfile.TemporaryDirectory(prefix="system-ops-model-") as temporary:
            binary = Path(temporary) / "system-ops-test"
            build = subprocess.run([
                "xcrun", "clang++", "-std=c++17", "-O1", "-Wall", "-Wextra", "-Werror",
                "-framework", "Foundation",
                str(ROOT / "native/network-helper/system_ops_test.mm"), "-o", str(binary),
            ], capture_output=True, timeout=90)
            self.assertEqual(build.returncode, 0, build.stderr.decode())
            run = subprocess.run([str(binary)], capture_output=True, timeout=20)
            self.assertEqual(run.returncode, 0, run.stderr.decode())
            self.assertEqual(run.stdout, b"")


if __name__ == "__main__":
    unittest.main()
