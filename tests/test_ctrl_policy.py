"""Compile and run the bounded ctrl static-mapping contract without network."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class CtrlPolicyTests(unittest.TestCase):
    def test_static_mapping_transaction_and_rejection_boundaries(self):
        with tempfile.TemporaryDirectory(prefix="ctrl-policy-") as folder:
            binary = pathlib.Path(folder) / "test"
            compile_result = subprocess.run(
                [shutil.which("clang++") or "c++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                 str(ROOT / "native/ctrl-policy/parser_test.cpp"), "-o", str(binary)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "ctrl static policy parser: passed\n")
            self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
