"""Offline checks for the status-helper build, contract and install scripts.

These tests never touch /Library, /var/run or launchd; they verify the pure
pieces (plist, root script, wire codec, daemon logic) and the safety shape of
the root command.
"""
import json
import os
import platform
import plistlib
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import helper_install  # noqa: E402
import helper_status  # noqa: E402
import helper_uninstall  # noqa: E402


@unittest.skipUnless(platform.system() == "Darwin", "Apple SDK required")
class StatusDaemonLogicTests(unittest.TestCase):
    def test_offline_logic_binary_is_clean(self):
        with tempfile.TemporaryDirectory(prefix="status-daemon-logic-") as temporary:
            binary = Path(temporary) / "logic-test"
            build = subprocess.run([
                "xcrun", "clang++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                "-framework", "Foundation",
                str(ROOT / "native/network-helper/status_daemon_test.mm"), "-o", str(binary),
            ], capture_output=True, timeout=60)
            self.assertEqual(build.returncode, 0, build.stderr.decode())
            run = subprocess.run([str(binary)], capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr.decode())
            self.assertEqual(run.stdout, b"")

    def test_daemon_main_compiles_under_strict_warnings(self):
        with tempfile.TemporaryDirectory(prefix="status-daemon-main-") as temporary:
            binary = Path(temporary) / "daemon"
            build = subprocess.run([
                "xcrun", "clang++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-O1",
                "-framework", "Foundation",
                str(ROOT / "native/network-helper/status_daemon_main.mm"), "-o", str(binary),
            ], capture_output=True, timeout=90)
            self.assertEqual(build.returncode, 0, build.stderr.decode())


class WireContractTests(unittest.TestCase):
    def test_request_is_exactly_five_bytes(self):
        self.assertEqual(helper_status.REQUEST, b"\x00\x00\x00\x01\x01")

    def test_required_keys_are_fixed(self):
        self.assertEqual(helper_status.REQUIRED_KEYS,
                         {"schemaVersion", "helper", "services", "epoch"})


class PlistContractTests(unittest.TestCase):
    def test_generated_plist_matches_design(self):
        raw = helper_install.generate_plist(501)
        job = plistlib.loads(raw)
        self.assertEqual(job["Label"], helper_install.LABEL)
        self.assertEqual(job["ProgramArguments"][0], helper_install.HELPER_DEST)
        self.assertIn("--allowed-uid", job["ProgramArguments"])
        self.assertIn("501", job["ProgramArguments"])
        listener = job["Sockets"]["Listeners"]
        self.assertEqual(listener["SockPathName"], helper_install.SOCKET_PATH)
        self.assertEqual(listener["SockPathMode"], 0o666)
        self.assertEqual(listener["SockType"], "STREAM")
        self.assertFalse(job["RunAtLoad"])
        self.assertFalse(job["KeepAlive"])

    def test_implausible_uid_rejected(self):
        for uid in (-1, 1000001):
            with self.assertRaises(ValueError):
                helper_install.generate_plist(uid)


class RootScriptSafetyTests(unittest.TestCase):
    def setUp(self):
        self.script = helper_install.build_root_script(
            Path("/tmp/staged/helper"), Path("/tmp/staged/helper.plist"),
            "a" * 64, "b" * 64)

    def test_digest_verification_precedes_copy(self):
        verify_at = self.script.index("/usr/bin/shasum -a 256")
        copy_at = self.script.index("/bin/cp -f")
        self.assertLess(verify_at, copy_at)
        self.assertIn("[ \"${actual%% *}\" = " + "a" * 64, self.script)

    def test_no_shell_or_destructive_operations(self):
        for forbidden in ("rm -rf", "curl", "eval", "| sh"):
            self.assertNotIn(forbidden, self.script)

    def test_immutable_flag_cleared_before_replacing(self):
        nouch = self.script.index("chflags nouchg")
        copy = self.script.index("/bin/cp -f")
        self.assertLess(nouch, copy)

    def test_bootout_tolerant_bootstrap_strict(self):
        self.assertIn("bootout system/local.szu.securelink.helper >/dev/null 2>&1 || true",
                      self.script)
        self.assertIn("launchctl bootstrap system", self.script)

    def test_destinations_quoted_and_absolute(self):
        for target in (helper_install.HELPER_DEST, helper_install.PLIST_DEST):
            self.assertIn(shlex.quote(target), self.script)


class UninstallScriptSafetyTests(unittest.TestCase):
    def test_uninstall_verifies_absence(self):
        script = helper_uninstall.build_root_script()
        self.assertIn("launchctl bootout system/local.szu.securelink.helper", script)
        self.assertIn("chflags nouchg", script)
        self.assertIn("exit 66", script)
        self.assertIn("exit 67", script)
        self.assertNotIn("rm -rf", script)


class StatusQueryContractTests(unittest.TestCase):
    def test_query_round_trip_against_fake_helper(self):
        path = tempfile.mktemp(prefix="helper-status-test-")
        received = []

        def serve():
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(path)
                listener.listen(1)
                ready.set()
                connection, _ = listener.accept()
                with connection:
                    received.append(connection.recv(64))
                    body = json.dumps({
                        "schemaVersion": 1,
                        "helper": {"label": helper_install.LABEL, "sha256": "0" * 64,
                                   "allowedUid": os.getuid()},
                        "services": {"com.securelink.client": {"state": "exit", "exitCode": 113}},
                        "epoch": 1700000000,
                    }).encode()
                    connection.sendall(len(body).to_bytes(4, "big") + body)

        ready = threading.Event()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.assertTrue(ready.wait(timeout=2), "fake helper did not start")
        try:
            report = helper_status.query(path)
            self.assertEqual(received, [helper_status.REQUEST])
            self.assertEqual(report["schemaVersion"], 1)
            self.assertIn("com.securelink.client", report["services"])
        finally:
            thread.join(timeout=2)
            if os.path.exists(path):
                os.unlink(path)


if __name__ == "__main__":
    unittest.main()
