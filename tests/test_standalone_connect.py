"""Gate for the standalone connection entry: offline suites pass, the real
tunnel mode refuses until the privileged executor unit lands."""
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "scripts/standalone-connect"


class StandaloneConnectTests(unittest.TestCase):
    def test_entry_exists_and_is_executable(self):
        self.assertTrue(ENTRY.is_file())
        self.assertTrue(ENTRY.stat().st_mode & 0o111)

    def test_self_test_passes_offline(self):
        run = subprocess.run([str(ENTRY), "--self-test"], capture_output=True,
                             text=True, timeout=600)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        for name in ("plan-ops-operations", "plan-ops-scenarios", "system-ops",
                     "tunnel-transaction", "engine-transaction"):
            self.assertIn(f"{name}: ok", run.stdout)

    def test_tunnel_mode_refuses_until_full_orchestration(self):
        run = subprocess.run([str(ENTRY), "tunnel"], capture_output=True,
                             text=True, timeout=60)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("refused", run.stderr)
        self.assertIn("not wired yet", run.stderr)


if __name__ == "__main__":
    unittest.main()
