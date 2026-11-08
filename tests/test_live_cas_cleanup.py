import importlib.machinery
import importlib.util
import json
import os
import signal
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


loader = importlib.machinery.SourceFileLoader("live_cas_test", str(Path(__file__).resolve().parents[1] / "scripts/live-cas-test"))
spec = importlib.util.spec_from_loader(loader.name, loader)
live = importlib.util.module_from_spec(spec)
loader.exec_module(live)


class CleanupTests(unittest.TestCase):
    def test_observed_login_cooldown_blocks_early_retries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "out").mkdir()
            self.assertEqual(live.login_cooldown_remaining(root, now=100), 0)
            path = root / "out/login-cooldown.json"
            path.write_text('{"notBeforeUnix":700}')
            self.assertEqual(live.login_cooldown_remaining(root, now=100), 601)
            self.assertEqual(live.login_cooldown_remaining(root, now=701), 0)
            for value in [True, "700", float("nan"), float("inf")]:
                path.write_text(json.dumps({"notBeforeUnix": value}))
                with self.assertRaises(ValueError):
                    live.login_cooldown_remaining(root, now=100)

    def test_restores_handler_and_only_stops_owned_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "out").mkdir()
            run = root / "run"
            run.mkdir()
            backup = root / "out/cas-handler-backup.json"
            backup.write_text(json.dumps({"originalHandler": "com.wangsu.securelink"}))
            process = Mock()
            process.poll.return_value = None
            process.wait.side_effect = [subprocess.TimeoutExpired("owned", 5), 0]
            invoke = Mock()
            with patch.object(live.subprocess, "check_output", return_value="com.wangsu.securelink\n"):
                self.assertTrue(live.cleanup(process, run, invoke, root))
            process.terminate.assert_called_once()
            process.kill.assert_called_once()
            self.assertFalse(backup.exists())
            self.assertTrue((run / "handler-backup.json").exists())
            receipt = json.loads((run / "cleanup.json").read_text())
            self.assertTrue(receipt["handlerRestored"])
            self.assertFalse(receipt["connectionRestored"])
            self.assertEqual(invoke.call_count, 2)

    def test_restore_failure_preserves_backup_and_still_opens_official(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "out").mkdir()
            run = root / "run"
            run.mkdir()
            backup = root / "out/cas-handler-backup.json"
            backup.write_text('{"originalHandler":"com.wangsu.securelink"}')
            invoke = Mock(side_effect=[RuntimeError("restore failed"), None])
            self.assertFalse(live.cleanup(None, run, invoke, root))
            self.assertTrue(backup.exists())
            self.assertEqual(invoke.call_args_list[-1].args[0], ["/usr/bin/open", "-b", "com.wangsu.securelink"])

    def test_process_error_does_not_skip_restoration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "out").mkdir()
            (root / "out/cas-handler-backup.json").write_text('{"originalHandler":"com.wangsu.securelink"}')
            run = root / "run"
            run.mkdir()
            process = Mock()
            process.poll.return_value = None
            process.terminate.side_effect = OSError("gone")
            invoke = Mock()
            with patch.object(live.subprocess, "check_output", return_value="com.wangsu.securelink"):
                self.assertFalse(live.cleanup(process, run, invoke, root))
            self.assertEqual(invoke.call_count, 2)
            receipt = json.loads((run / "cleanup.json").read_text())
            self.assertTrue(receipt["handlerRestored"])
            self.assertIn("test-process-cleanup-failed", receipt["errors"])

    @unittest.skipUnless((live.ROOT / "out/openvpn3/build/szu-openvpn3-handshake").is_file(), "optional helper not built")
    def test_foundation_helper_dies_with_owned_trial_group(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "launcher.swift"
            binary = Path(directory) / "launcher"
            source.write_text(r"""import Foundation
import Darwin
let child = Process()
child.executableURL = URL(fileURLWithPath: CommandLine.arguments[1])
child.arguments = ["--validate-input"]
let pipe = Pipe()
child.standardInput = pipe
child.standardOutput = FileHandle.nullDevice
child.standardError = FileHandle.nullDevice
try child.run()
for _ in 0..<100 {
    if getpgid(child.processIdentifier) == getpgrp() { break }
    Thread.sleep(forTimeInterval: 0.01)
}
print("\(child.processIdentifier) \(getpgid(child.processIdentifier))")
fflush(stdout)
child.waitUntilExit()
""")
            subprocess.run(["swiftc", str(source), "-o", str(binary)], check=True, capture_output=True, timeout=30)
            process = subprocess.Popen([str(binary), str(live.ROOT / "out/openvpn3/build/szu-openvpn3-handshake")],
                                       stdout=subprocess.PIPE, text=True, start_new_session=True)
            child = None
            try:
                child, group = map(int, process.stdout.readline().split())
                self.assertEqual(group, process.pid)
                live.stop_owned_group(process)
                with self.assertRaises(ProcessLookupError):
                    os.kill(child, 0)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                if child is not None:
                    try: os.kill(child, signal.SIGKILL)
                    except ProcessLookupError: pass
                process.stdout.close()

    def test_group_failure_defers_official_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            invoke = Mock()
            with patch.object(live, "stop_owned_group", side_effect=RuntimeError("still running")):
                self.assertFalse(live.cleanup(Mock(), run, invoke, run, owned_group=True))
            invoke.assert_not_called()
            receipt = json.loads((run / "cleanup.json").read_text())
            self.assertFalse(receipt["officialLaunchRequested"])
            self.assertIn("official-client-launch-deferred-active-test-process", receipt["errors"])

    def test_no_backup_or_process_does_not_claim_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / "run"
            run.mkdir()
            invoke = Mock()
            self.assertTrue(live.cleanup(None, run, invoke, root))
            receipt = json.loads((run / "cleanup.json").read_text())
            self.assertFalse(receipt["handlerRestored"])
            invoke.assert_called_once()




class AcceptanceTests(unittest.TestCase):
    def test_backend_acceptance_never_uses_gui_initialization_as_proof(self):
        self.assertFalse(live.accepted_report({"finished": True, "phases": ["initialized"]}, backend_auth=True))
        valid = {"finished": True, "transportFailed": False,
                 "mode": "bounded-direct-backend-preauthentication", "officialIPCUsed": False,
                 "backendAuthenticationValidated": True, "backendUserLogout": "accepted", "phases": ["backend-authenticated"]}
        self.assertTrue(live.accepted_report(valid, backend_auth=True))
        for key, value in [("officialIPCUsed", True), ("finished", False), ("transportFailed", True),
                           ("backendAuthenticationValidated", False), ("backendUserLogout", "cancelled"),
                           ("backendUserLogout", "failed"), ("mode", "bounded-cas-connection")]:
            self.assertFalse(live.accepted_report({**valid, key: value}, backend_auth=True))
        self.assertFalse(live.accepted_report(valid))
        config = {**valid, "mode": "bounded-direct-backend-configuration", "backendConfigurationValidated": True,
                  "phases": ["backend-authenticated", "backend-configuration-received"]}
        self.assertTrue(live.accepted_report(config, backend_config=True))
        self.assertFalse(live.accepted_report(config, backend_auth=True))
        self.assertFalse(live.accepted_report({**config, "backendConfigurationValidated": False}, backend_config=True))
        evaluation = {"accepted": True, "mode": "offline-config-evaluation", "networkOpened": False, "tunnelStarted": False}
        self.assertFalse(live.accepted_report(config, backend_config=True, engine_evaluation=True))
        self.assertTrue(live.accepted_report({**config, "backendEngineEvaluation": evaluation}, backend_config=True, engine_evaluation=True))
        for field in ["networkOpened", "tunnelStarted"]:
            self.assertFalse(live.accepted_report({**config, "backendEngineEvaluation": {**evaluation, field: True}}, backend_config=True, engine_evaluation=True))
        boundary = {"mode": "bounded-handshake-probe", "reason": "tunnel-boundary", "connectCalled": True,
                    "tunnelSetupRequested": True, "connected": False, "tunnelStarted": False,
                    "routesChanged": False, "dnsChanged": False, "unexpectedConnected": False}
        value = {**config, "backendHandshake": boundary}
        self.assertFalse(live.accepted_report(value, backend_config=True, handshake=True, handshake_network=True, capture_plan=True))
        captured = {**config, "backendHandshake": {**boundary, "planCaptureRequested": True, "planComplete": True}}
        self.assertTrue(live.accepted_report(captured, backend_config=True, handshake=True, handshake_network=True, capture_plan=True))
        self.assertFalse(live.accepted_report(captured, backend_config=True, capture_plan=True))
        for field in ["planCaptureRequested", "planComplete"]:
            for invalid in [False, None, 1, "true"]:
                rejected = {**captured, "backendHandshake": {**captured["backendHandshake"], field: invalid}}
                self.assertFalse(live.accepted_report(rejected, backend_config=True, handshake=True, handshake_network=True, capture_plan=True))
        self.assertTrue(live.accepted_report(value, backend_config=True, handshake=True, handshake_network=True))
        self.assertFalse(live.accepted_report(config, backend_config=True, handshake=True, handshake_network=True))
        for field, wrong in [("reason", "connection-ended"), ("tunnelSetupRequested", False),
                             ("connectCalled", False), ("unexpectedConnected", True), ("connected", True)]:
            self.assertFalse(live.accepted_report({**config, "backendHandshake": {**boundary, field: wrong}},
                                                 backend_config=True, handshake=True, handshake_network=True))



if __name__ == "__main__":
    unittest.main()
