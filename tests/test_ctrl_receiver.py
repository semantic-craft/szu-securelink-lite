"""Offline receiver contract using the project's fixed OpenVPN CSV lexer."""
import pathlib
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "out/openvpn3/source"


class CtrlReceiverTests(unittest.TestCase):
    @unittest.skipUnless((SOURCE / "openvpn/common/options.hpp").is_file(), "optional pinned dependency not fetched")
    def test_control_generation_compression_and_privacy(self):
        revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                                  capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(revision, "4f3bdef73245d4ee9e8216c5d65baccc9568f6ef")
        flags = shlex.split(subprocess.run(["pkg-config", "--cflags", "--libs", "liblz4"],
                                          capture_output=True, text=True, check=True).stdout)
        with tempfile.TemporaryDirectory(prefix="ctrl-receiver-") as directory:
            binary = pathlib.Path(directory) / "receiver"
            compiled = subprocess.run(
                [shutil.which("clang++") or "c++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                 "-DUSE_ASIO", "-DASIO_STANDALONE", "-isystem", str(ROOT / "out/openvpn3/asio/asio/include"),
                 "-isystem", str(SOURCE), str(ROOT / "native/ctrl-policy/receiver_test.cpp"),
                 "-o", str(binary), *flags], capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "ctrl receiver: passed\n")
            self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
