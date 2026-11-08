"""Offline daemon-policy checks for the tunnel transaction driver.

Builds and runs native/network-helper/tunnel_transaction_test.mm, whose
scenarios drive real wire frames through the audited parser and fake
executor. Nothing touches the network or launchd.
"""
import platform
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(platform.system() == "Darwin", "Apple SDK required")
class TunnelTransactionTests(unittest.TestCase):
    def test_daemon_policy_scenarios_pass(self):
        with tempfile.TemporaryDirectory(prefix="tunnel-transaction-") as temporary:
            binary = Path(temporary) / "tunnel-transaction-test"
            build = subprocess.run([
                "xcrun", "clang++", "-std=c++17", "-O1", "-Wall", "-Wextra", "-Werror",
                "-framework", "Foundation", "-framework", "Security", "-lbsm",
                str(ROOT / "native/network-helper/tunnel_transaction_test.mm"),
                str(ROOT / "native/network-helper/ipc.mm"), "-o", str(binary),
            ], capture_output=True, timeout=120)
            self.assertEqual(build.returncode, 0, build.stderr.decode())
            run = subprocess.run([str(binary)], capture_output=True, timeout=20)
            self.assertEqual(run.returncode, 0, run.stderr.decode())
            self.assertEqual(run.stdout, b"")


if __name__ == "__main__":
    unittest.main()
