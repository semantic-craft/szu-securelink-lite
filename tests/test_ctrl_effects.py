"""Pure ctrl destination/initial route intents, with no system effects."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class CtrlEffectsTests(unittest.TestCase):
    def test_destination_not_source_and_replacement(self):
        with tempfile.TemporaryDirectory(prefix="ctrl-effects-") as folder:
            binary = pathlib.Path(folder) / "test"
            result = subprocess.run(
                [shutil.which("clang++") or "c++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=address,undefined", str(ROOT / "native/ctrl-policy/effects_test.cpp"),
                 "-o", str(binary)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "ctrl effects: passed\n")
            self.assertEqual(result.stderr, "")
