import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class DNSReplyTests(unittest.TestCase):
    def test_compressed_answers_and_untrusted_reply_boundaries(self):
        with tempfile.TemporaryDirectory(prefix="dns-reply-") as folder:
            binary = pathlib.Path(folder) / "test"
            result = subprocess.run([shutil.which("clang++") or "c++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                str(ROOT / "native/dns-message/reply_test.cpp"), "-lresolv", "-o", str(binary)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=5)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stdout, "DNS reply parser: passed\n")
