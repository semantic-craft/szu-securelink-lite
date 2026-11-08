"""Offline coverage for the merged data-session engine and the live driver's
data-session acceptance. Nothing here touches the executor socket, the
network or the system: the engine cases run --self-test and invalid-argument
receipts; the driver cases exercise accepted_report shapes and argparse
refusals, which all exit before any gate is evaluated."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "out/executor-build/executor-engine"
DRIVER = ROOT / "scripts/live-cas-test"


def load_live_module():
    loader = importlib.machinery.SourceFileLoader("live_cas_test_data", str(DRIVER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def session_report(**overrides):
    receipt = {
        "mode": "bounded-data-session", "engine": "data-engine-1",
        "reason": "data-session-verified", "phase": "active", "interface": "utun9",
        "fdAccepted": True, "connectCalled": True, "socketObserved": True,
        "tunnelSetupRequested": True, "tunnelStarted": True, "connectedInDataMode": True,
        "pingRan": True, "pingExitStatus": 0, "pingTransmitted": 3, "pingReceived": 3,
        "digRan": False, "digExitStatus": -1, "digStatus": None, "digAnswers": -1,
        "digServer": None, "digName": None,
        "planCaptureRequested": True, "planComplete": True,
        "holdMs": 60000, "heartbeatsSent": 42, "disconnectSent": True,
        "deadlineReached": False, "unexpectedConnected": False, "eventsDropped": False,
        "events": ["CONNECTING", "CONNECTED"],
    }
    receipt.update(overrides)
    return {
        "finished": True, "transportFailed": False,
        "backendAuthenticationValidated": True, "backendConfigurationValidated": True,
        "backendUserLogout": "accepted", "phases": ["initialized"],
        "backendDataSession": receipt,
    }


def dig_report(**overrides):
    return session_report(**{
        "digRan": True, "digExitStatus": 0, "digStatus": "NOERROR", "digAnswers": 2,
        "digServer": "192.168.247.6", "digName": "szu.edu.cn", **overrides})


@unittest.skipUnless(ENGINE.is_file(), "merged data engine not built")
class DataEngineSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        result = subprocess.run([str(ENGINE), "--self-test"], capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr.decode()[-400:])
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["mode"], "data-engine-self-test")
        self.assertIs(receipt["passed"], True)

    def test_invalid_arguments_fail_closed_without_stdin(self):
        for args in (
            ["--data-session"],
            ["--data-session", "--socket", "/var/run/x", "--hold-ms", "0", "--ping-peer", "1.1.96.1"],
            ["--data-session", "--socket", "/var/run/x", "--hold-ms", "60000", "--ping-peer", "secret.example.edu"],
            ["--data-session", "--socket", "/var/run/x", "--hold-ms", "60000", "--ping-peer", "1.1.96.1", "--ping-count", "99"],
            ["--data-session", "--socket", "/var/run/x", "--hold-ms", "200000", "--ping-peer", "1.1.96.1"],
            ["--data-session", "--socket", "/var/run/x", "--hold-ms", "60000", "--ping-peer", "1.1.96.1", "--dig-server", "192.168.247.6"],
            ["--data-session", "--socket", "/var/run/x", "--hold-ms", "60000", "--ping-peer", "1.1.96.1", "--dig-name", "szu.edu.cn"],
            ["--data-session", "--socket", "/var/run/x", "--hold-ms", "60000", "--ping-peer", "1.1.96.1", "--dig-server", "resolver.example", "--dig-name", "szu.edu.cn"],
            ["--data-session", "--socket", "/var/run/x", "--hold-ms", "60000", "--ping-peer", "1.1.96.1", "--dig-server", "192.168.247.6", "--dig-name", "bad name"],
            ["--data-session", "--socket", "/var/run/x", "--hold-ms", "60000", "--ping-peer", "1.1.96.1", "--dig-server", "192.168.247.6", "--dig-name", "-leading.hyphen"],
            ["--data-session", "--socket", "/var/run/x", "--hold-ms", "60000", "--ping-peer", "1.1.96.1", "--resolve-domains", "bad domain,szu.edu.cn"],
        ):
            result = subprocess.run([str(ENGINE), *args], input=b"", capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 3, args)
            receipt = json.loads(result.stdout)
            self.assertEqual(receipt["reason"], "invalid-input", args)
            self.assertIs(receipt["connectCalled"], False)
            self.assertIs(receipt["fdAccepted"], False)


class LiveDataSessionDriverAcceptance(unittest.TestCase):
    def setUp(self):
        self.live = load_live_module()

    def test_verified_session_passes(self):
        self.assertTrue(self.live.accepted_report(session_report(), data_session=True))

    def test_finance_receipt_carries_tunnel_and_campus_truth(self):
        def finance_report(**overrides):
            value = session_report(**{
                "digRan": True, "digExitStatus": 0, "digStatus": "NOERROR", "digAnswers": 2,
                "digServer": "192.168.247.6", "digName": "szu.edu.cn", **overrides})
            value["mode"] = "bounded-standalone-finance"
            value["tunnel"] = "connected"
            value["campusValidated"] = True
            value["financeHomepageValidated"] = True
            value["officialBackendStillRequired"] = False
            value["sensitiveFieldsRecorded"] = False
            return value
        self.assertTrue(self.live.accepted_report(finance_report(), data_session=True, finance=True))
        for key, bad in (("tunnel", "disconnected"), ("campusValidated", False),
                         ("financeHomepageValidated", False),
                         ("officialBackendStillRequired", True),
                         ("sensitiveFieldsRecorded", True), ("mode", "bounded-direct-backend-configuration")):
            value = finance_report()
            value[key] = bad
            self.assertFalse(self.live.accepted_report(value, data_session=True, finance=True), key)
        # finance=True without data_session is a caller contract violation.
        self.assertFalse(self.live.accepted_report(finance_report(), data_session=False, finance=True))
        # The plain data-session path stays unaffected by the finance fields.
        self.assertTrue(self.live.accepted_report(finance_report(), data_session=True, finance=False))

    def test_in_tunnel_dns_probe_gates_acceptance(self):
        self.assertTrue(self.live.accepted_report(dig_report(), data_session=True, dig_requested=True))
        # Without the probe requested, dig evidence is irrelevant.
        self.assertTrue(self.live.accepted_report(session_report(), data_session=True, dig_requested=False))
        for overrides in (
            {"digRan": False, "digExitStatus": -1, "digStatus": None, "digAnswers": -1},
            {"digStatus": "SERVFAIL", "digAnswers": 0},
            {"digAnswers": 0},
            {"digExitStatus": 9},
            {"digAnswers": "2"},
        ):
            self.assertFalse(
                self.live.accepted_report(dig_report(**overrides), data_session=True, dig_requested=True),
                overrides)

    def test_tampered_session_claims_fail(self):
        for key, value in (
            ("reason", "data-session-ended"), ("fdAccepted", False), ("tunnelStarted", False),
            ("connectedInDataMode", False), ("disconnectSent", False), ("pingRan", False),
            ("pingReceived", 0), ("pingReceived", "3"), ("interface", "en0"),
            ("planComplete", False), ("unexpectedConnected", True), ("mode", "bounded-handshake-probe"),
        ):
            self.assertFalse(self.live.accepted_report(session_report(**{key: value}), data_session=True),
                             f"{key}={value}")

    def test_missing_or_foreign_receipt_fails(self):
        report = session_report()
        del report["backendDataSession"]
        self.assertFalse(self.live.accepted_report(report, data_session=True))
        report["backendDataSession"] = "SECRET-STRING"
        self.assertFalse(self.live.accepted_report(report, data_session=True))
        # Handshake and data-session paths are mutually exclusive.
        self.assertFalse(self.live.accepted_report(
            session_report(backendHandshake={}), data_session=True, handshake=True))


class LiveDataSessionDriverArguments(unittest.TestCase):
    def test_data_session_requires_engine_and_numeric_peer(self):
        base = [sys.executable, str(DRIVER), "--allow-session-interruption",
                "--allow-protocol-change", "--data-session"]
        for extra in (
            [],
            ["--engine", "/bin/false", "--ping-peer", "secret.example.edu"],
            ["--engine", "/bin/false", "--ping-peer", "1.1.96.1", "--hold-ms", "0"],
            ["--engine", "/bin/false", "--ping-peer", "1.1.96.1", "--ping-count", "99"],
            ["--engine", str(ROOT / "docs/nonexistent"), "--ping-peer", "1.1.96.1"],
            ["--engine", "/bin/false", "--ping-peer", "1.1.96.1", "--allow-handshake"],
        ):
            result = subprocess.run([*base, *extra], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2, extra)
            self.assertIn("usage:", result.stderr)


if __name__ == "__main__":
    unittest.main()
