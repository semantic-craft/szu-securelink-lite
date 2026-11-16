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
    def _run_mm_scenarios(self, source_name: str):
        with tempfile.TemporaryDirectory(prefix="tunnel-transaction-") as temporary:
            binary = Path(temporary) / Path(source_name).stem
            build = subprocess.run([
                "xcrun", "clang++", "-std=c++17", "-O1", "-Wall", "-Wextra", "-Werror",
                "-framework", "Foundation", "-framework", "Security", "-lbsm",
                str(ROOT / "native/network-helper" / source_name),
                str(ROOT / "native/network-helper/ipc.mm"), "-o", str(binary),
            ], capture_output=True, timeout=120)
            self.assertEqual(build.returncode, 0, build.stderr.decode())
            run = subprocess.run([str(binary)], capture_output=True, timeout=60)
            self.assertEqual(run.returncode, 0, run.stderr.decode())
            self.assertEqual(run.stdout, b"")

    def test_daemon_policy_scenarios_pass(self):
        self._run_mm_scenarios("tunnel_transaction_test.mm")

    def test_engine_transaction_scenarios_pass(self):
        self._run_mm_scenarios("engine_transaction_test.mm")


if __name__ == "__main__":
    unittest.main()
