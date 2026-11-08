from pathlib import Path
import platform
import subprocess
import tempfile
import unittest


@unittest.skipUnless(platform.system() == "Darwin", "Darwin peer authentication APIs")
class NetworkHelperIPCTests(unittest.TestCase):
    def test_offline_protocol_lifecycle_and_fd_boundary(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="network-helper-ipc-") as temporary:
            binary = Path(temporary) / "ipc-test"
            build = subprocess.run([
                "xcrun", "clang++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                "-framework", "Security", "-framework", "CoreFoundation", "-lbsm",
                str(root / "native/network-helper/ipc.mm"),
                str(root / "native/network-helper/ipc_test.mm"), "-o", str(binary),
            ], capture_output=True, timeout=60)
            self.assertEqual(build.returncode, 0, build.stderr.decode())
            result = subprocess.run([str(binary)], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stdout, b"")
