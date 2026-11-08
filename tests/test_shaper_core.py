"""Compile and exercise the standalone, offline C++ shaper scheduling model."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ShaperCoreTests(unittest.TestCase):
    def test_synthetic_window_contract(self):
        compiler = shutil.which("clang++") or shutil.which("c++")
        self.assertIsNotNone(compiler, "C++17 compiler required")
        with tempfile.TemporaryDirectory(prefix="shaper-core-") as directory:
            executable = pathlib.Path(directory) / "codec-test"
            subprocess.run(
                [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                 str(ROOT / "native/openvpn3-handshake/shaper_test.cpp"),
                 "-o", str(executable)],
                check=True, capture_output=True, text=True, timeout=60,
            )
            result = subprocess.run(
                [str(executable)], check=True, capture_output=True,
                text=True, timeout=20,
            )
            self.assertEqual(result.stdout, "shaper core: passed\n")
            self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
