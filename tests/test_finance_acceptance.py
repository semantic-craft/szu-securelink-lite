import importlib.machinery
import importlib.util
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader("finance_acceptance", str(ROOT / "scripts/finance_acceptance.py"))
spec = importlib.util.spec_from_loader(loader.name, loader)
finance = importlib.util.module_from_spec(spec)
loader.exec_module(finance)

LEASE = {"sessionID": "11111111-1111-4111-8111-111111111111", "interface": "utun9", "ifindex": 42,
         "handleIdentity": "22222222-2222-4222-8222-222222222222"}
PLISTED = "State:/Network/Service/szu-securelink-11111111/DNS"

NETSTAT = """Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.50.3       UGScg        en0
10.20/16           10.20.0.7          UGSc         utun9
127                127.0.0.1          UCS          lo0
"""
IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.50.34 netmask 0xffffff00 broadcast 192.168.50.255
utun9: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400
\tinet 10.20.0.7 --> 10.20.0.1 netmask 0xffff0000
"""
SCUTIL = """DNS configuration

resolver #1
  nameserver[0] : 192.168.50.1
  if_index : 6 (en0)
  flags    : Request A records

resolver #2
  domain   : szu.edu.cn
  nameserver[0] : 10.20.0.53
  if_index : 42 (utun9)
"""
LAUNCHCTL = """PID\tStatus\tLabel\n-\t0\tcom.apple.rcd\n43794\t0\tapplication.com.wangsu.securelink.331773213\n"""


def snapshot(*, tunnel=False, planned_route=False, supplemental=False):
    interfaces = [{"name": "en0", "mtu": 1500, "addresses": [{"address": "192.168.50.34", "peer": None}]}]
    routes = [{"destination": "default", "gateway": "192.168.50.3", "flags": "UGScg", "interface": "en0"},
              {"destination": "192.168.50/24", "gateway": "192.168.50.34", "flags": "UGSc", "interface": "en0"}]
    resolvers = [{"domains": [], "nameservers": ["192.168.50.1"], "ifIndex": 6}]
    if tunnel:
        interfaces.append({"name": "utun9", "mtu": 1400,
                           "addresses": [{"address": "10.20.0.7", "peer": "10.20.0.1"}]})
    if planned_route:
        routes.append({"destination": "10.20/16", "gateway": "10.20.0.7", "flags": "UGSc", "interface": "utun9"})
    if supplemental:
        resolvers.append({"domains": ["szu.edu.cn"], "nameservers": ["10.20.0.53"], "ifIndex": 42})
    return {"observedAt": "2026-11-05T03:00:00+00:00",
            "defaultRoutes": [{"gateway": "192.168.50.3", "interface": "en0"}],
            "routes": routes, "interfaces": interfaces, "resolvers": resolvers}


def evidence():
    return {
        "process-evidence.json": {
            "observedAt": "2026-11-05T03:00:00+00:00", "officialGUIRunning": False, "officialGUIProcesses": [],
            "officialBackendProcesses": [], "officialLaunchdLoaded": False, "officialLoadedLabels": [],
            "userLaunchdServiceLabels": [], "userLaunchdChecked": True, "systemLaunchdChecked": True,
            "installedServicePlists": [{"path": "/Library/LaunchDaemons/com.securelink.client.plist",
                                        "label": "com.securelink.client", "domain": "LaunchDaemons"}],
            "nativeProcesses": [{"name": "szu-securelink", "pids": [4242]}]},
        "network-before.json": snapshot(),
        "network-after.json": snapshot(tunnel=True, planned_route=True, supplemental=True),
        "network-restored.json": snapshot(),
        "plan-journal.json": {
            "lease": LEASE,
            "created": [{"kind": "owned-interface", "key": "interface:utun9"},
                        {"kind": "interface-route", "key": "route:10.20/16"},
                        {"kind": "supplemental-resolver", "key": PLISTED,
                         "value": {"ServerAddresses": ["10.20.0.53"], "SupplementalMatchDomains": ["szu.edu.cn"]}}],
            "cleanup": {"removals": ["route:10.20/16", PLISTED, "interface:utun9"], "issues": []}},
        "homepage-observation.json": {
            "windowTitle": finance.HOMEPAGE_TITLE, "snapshot": "ws-1-finance", "onCurrentSpace": True,
            "criteria": {name: True for name in finance.HOMEPAGE_CRITERIA}, "afterExplicitReload": True,
            "loggedIn": True, "loginFormPresent": False, "officialGUIRunning": False,
            "sensitiveFieldsRecorded": False},
        "acceptance-observation.json": {
            "finished": True, "transportFailed": False, "mode": finance.SESSION_MODE, "officialIPCUsed": False,
            "tunnel": "connected", "campusValidated": True, "officialBackendStillRequired": False,
            "financeHomepageValidated": True, "sensitiveFieldsRecorded": False, "schemaVersion": 1,
            "phases": ["discovering", "backend-authenticated", "backend-configuration-received",
                       "standalone-tunnel-connected", "finance-homepage-validated"]},
        "cleanup.json": {"handlerRestored": True, "officialLaunchRequested": True, "connectionRestored": False,
                         "tunnelRemoved": True, "errors": []},
        "restoration-observation.json": {"officialGUIConnected": True},
    }


def write_run(directory: Path, payloads=None):
    directory.mkdir(parents=True, exist_ok=True)
    for name, value in (payloads or evidence()).items():
        (directory / name).write_text(json.dumps(value, ensure_ascii=False) + "\n")
    return directory


class FinanceAcceptanceTests(unittest.TestCase):
    def test_complete_standalone_run_passes(self):
        with tempfile.TemporaryDirectory() as temporary:
            verdict = finance.evaluate_run(write_run(Path(temporary) / "run"))
        self.assertTrue(verdict["passed"], verdict["blockers"])
        self.assertEqual(verdict["blockers"], [])
        self.assertEqual(verdict["stage"], "finance")
        self.assertTrue(verdict["standaloneValidated"])
        self.assertIn("acceptance-observation.json", verdict["checkedFiles"])

    def test_every_missing_or_malformed_file_blocks(self):
        base = evidence()
        for name in finance.EVIDENCE_FILES:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                payloads = {key: value for key, value in base.items() if key != name}
                verdict = finance.evaluate_run(write_run(Path(temporary) / "run", payloads))
                self.assertFalse(verdict["passed"])
                self.assertIn("missing-" + name[:-len(".json")], verdict["blockers"])
            with self.subTest(name=name + "-malformed"), tempfile.TemporaryDirectory() as temporary:
                run = write_run(Path(temporary) / "run", base)
                (run / name).write_text("{not json")
                verdict = finance.evaluate_run(run)
                self.assertFalse(verdict["passed"])
                self.assertIn("malformed-" + name[:-len(".json")], verdict["blockers"])
        with tempfile.TemporaryDirectory() as temporary:
            verdict = finance.evaluate_run(Path(temporary) / "absent")
        self.assertEqual(verdict["blockers"], ["missing-run-directory"])

    def test_official_presence_or_unverified_launchd_blocks(self):
        for mutation, expected in [
                ({"officialGUIRunning": True}, "official-gui-running"),
                ({"officialBackendProcesses": [{"name": "SecureLink_Core", "pids": [61145]}]}, "official-backend-running"),
                ({"officialLaunchdLoaded": True}, "official-services-loaded"),
                ({"systemLaunchdChecked": False}, "system-launchd-unverified"),
                ({"nativeProcesses": []}, "native-client-absent"),
                ({"officialBackendProcesses": "none"}, "process-evidence-incomplete")]:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temporary:
                payloads = evidence()
                payloads["process-evidence.json"] = {**payloads["process-evidence.json"], **mutation}
                verdict = finance.evaluate_run(write_run(Path(temporary) / "run", payloads))
                self.assertFalse(verdict["passed"])
                self.assertIn(expected, verdict["blockers"])

    def test_network_ownership_and_restoration_block(self):
        cases = [
            ("network-after.json", snapshot(planned_route=True, supplemental=True), "tunnel-interface-absent"),
            ("network-restored.json", snapshot(tunnel=True), "tunnel-not-removed"),
            ("network-after.json", snapshot(tunnel=True, supplemental=True), "planned-route-missing"),
            ("network-restored.json", snapshot(planned_route=True), "planned-route-not-removed"),
            ("network-after.json", snapshot(tunnel=True, planned_route=True), "planned-dns-missing"),
            ("network-restored.json", snapshot(supplemental=True), "supplemental-resolver-retained"),
            ("network-after.json", snapshot(), "network-unchanged"),
            ("network-before.json", {**snapshot(), "defaultRoutes": [
                {"gateway": "172.16.0.1", "interface": "en1"}]}, "default-route-not-restored"),
            ("network-restored.json", {**snapshot(), "resolvers": [
                {"domains": [], "nameservers": ["10.20.0.53"], "ifIndex": 6}]}, "dns-not-restored"),
            ("network-after.json", {"observedAt": "x"}, "network-after-incomplete"),
        ]
        for name, replacement, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temporary:
                payloads = evidence()
                payloads[name] = replacement
                verdict = finance.evaluate_run(write_run(Path(temporary) / "run", payloads))
                self.assertFalse(verdict["passed"])
                self.assertIn(expected, verdict["blockers"])

    def test_journal_without_proven_ownership_blocks(self):
        good = evidence()["plan-journal.json"]
        cases = [
            ({**good, "lease": {**LEASE, "interface": "en0"}}, "journal-lease-invalid"),
            ({**good, "lease": {**LEASE, "ifindex": True}}, "journal-lease-invalid"),
            ({**good, "created": []}, "journal-created-empty"),
            ({**good, "created": [good["created"][1], good["created"][0]]}, "journal-ownership-unproven"),
            ({**good, "created": [good["created"][0], good["created"][0]]}, "journal-ownership-unproven"),
            ({**good, "cleanup": {"removals": [], "issues": ["record-drift"]}}, "journal-cleanup-issues"),
            ({**good, "cleanup": {}}, "journal-cleanup-missing"),
            ({k: v for k, v in good.items() if k != "cleanup"}, "journal-cleanup-missing"),
        ]
        for journal, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temporary:
                payloads = evidence()
                payloads["plan-journal.json"] = journal
                verdict = finance.evaluate_run(write_run(Path(temporary) / "run", payloads))
                self.assertFalse(verdict["passed"])
                self.assertIn(expected, verdict["blockers"])

    def test_homepage_and_session_markers_block(self):
        homepage = evidence()["homepage-observation.json"]
        session = evidence()["acceptance-observation.json"]
        incomplete = {**homepage, "criteria": {**homepage["criteria"], "审批系统": False}}
        cases = [
            ("homepage-observation.json", incomplete, "homepage-criteria-incomplete"),
            ("homepage-observation.json", {**homepage, "windowTitle": "登录"}, "homepage-title-mismatch"),
            ("homepage-observation.json", {**homepage, "afterExplicitReload": False}, "homepage-not-reloaded"),
            ("homepage-observation.json", {**homepage, "loginFormPresent": True}, "homepage-login-form-present"),
            ("homepage-observation.json", {**homepage, "loggedIn": False}, "homepage-not-logged-in"),
            ("homepage-observation.json", {**homepage, "officialGUIRunning": True}, "homepage-official-gui-running"),
            ("homepage-observation.json", {**homepage, "sensitiveFieldsRecorded": True}, "sensitive-fields-recorded"),
            ("homepage-observation.json", {k: v for k, v in homepage.items()
                                           if k != "sensitiveFieldsRecorded"}, "sensitive-fields-unattested"),
            ("acceptance-observation.json", {**session, "tunnel": "unavailable"}, "tunnel-not-connected"),
            ("acceptance-observation.json", {**session, "campusValidated": False}, "campus-not-validated"),
            ("acceptance-observation.json", {**session, "officialIPCUsed": True}, "official-ipc-used"),
            ("acceptance-observation.json", {**session, "mode": "bounded-cas-connection"}, "session-mode-not-standalone"),
            ("acceptance-observation.json", {**session, "officialBackendStillRequired": True}, "official-backend-still-required"),
            ("acceptance-observation.json", {**session, "financeHomepageValidated": False}, "homepage-not-validated-by-session"),
            ("cleanup.json", {"handlerRestored": True, "officialLaunchRequested": True, "tunnelRemoved": True,
                              "errors": ["handler-restoration-failed-backup-retained"]}, "cleanup-errors"),
            ("cleanup.json", {"handlerRestored": False, "officialLaunchRequested": True, "tunnelRemoved": True,
                              "errors": []}, "handler-not-restored"),
            ("cleanup.json", {"handlerChanged": False, "officialLaunchRequested": True, "tunnelRemoved": True,
                              "errors": []}, None),
            ("cleanup.json", {"handlerRestored": True, "officialLaunchRequested": True, "tunnelRemoved": False,
                              "errors": []}, "tunnel-not-removed-by-cleanup"),
            ("restoration-observation.json", {"officialGUIConnected": False}, "official-not-reconnected"),
        ]
        for name, replacement, expected in cases:
            with self.subTest(name=name, expected=expected), tempfile.TemporaryDirectory() as temporary:
                payloads = evidence()
                payloads[name] = replacement
                verdict = finance.evaluate_run(write_run(Path(temporary) / "run", payloads))
                if expected is None:
                    self.assertTrue(verdict["passed"], verdict["blockers"])
                else:
                    self.assertFalse(verdict["passed"])
                    self.assertIn(expected, verdict["blockers"])

    def test_gui_era_receipt_never_counts_as_standalone(self):
        legacy = {"nativeSession": {"finished": False, "transportFailed": False, "mode": "bounded-cas-connection",
                                    "officialIPCUsed": False, "tunnel": "connected", "campusValidated": False,
                                    "phases": ["initialized"]},
                  "homepage": {"ok": True, "windowTitle": finance.HOMEPAGE_TITLE, "onCurrentSpace": True,
                               "criteria": {name: True for name in finance.HOMEPAGE_CRITERIA},
                               "afterExplicitReload": True},
                  "officialGUIRunning": False, "officialBackendStillRequired": True,
                  "financeHomepageValidated": True}
        with tempfile.TemporaryDirectory() as temporary:
            run = Path(temporary) / "run"
            run.mkdir()
            (run / "acceptance.json").write_text(json.dumps(legacy, ensure_ascii=False))
            verdict = finance.evaluate_run(run)
        self.assertFalse(verdict["passed"])
        for expected in ("legacy-receipt-shape", "official-backend-still-required", "campus-not-validated",
                         "session-not-finished", "session-mode-not-standalone", "missing-process-evidence",
                         "missing-plan-journal", "homepage-not-logged-in", "homepage-login-form-present",
                         "sensitive-fields-unattested"):
            self.assertIn(expected, verdict["blockers"])


class CollectorTests(unittest.TestCase):
    def runner(self, calls, *, gui=True, root=False):
        def run(command):
            calls.append(tuple(str(part) for part in command))
            name = Path(str(command[0])).name
            if name == "pgrep":
                target = command[2]
                known = {"SecureLink": "43794", "SecureLink_Client": "19682", "SecureLink_Agent": "61050",
                         "SecureLink_Core": "61145", "SecureLink_DP": "61149"}
                if target in known and gui:
                    return known[target] + "\n"
                raise subprocess.CalledProcessError(1, command, output="")
            if name == "launchctl":
                if command[1] == "list":
                    return LAUNCHCTL
                return ""
            if name == "netstat":
                return NETSTAT
            if name == "ifconfig":
                return IFCONFIG
            if name == "scutil":
                return SCUTIL
            raise AssertionError("unexpected command " + str(command))
        return run

    def test_parsers_match_real_command_output(self):
        routes, defaults = finance._parse_routes(NETSTAT)
        self.assertEqual(defaults, [{"gateway": "192.168.50.3", "interface": "en0"}])
        self.assertIn({"destination": "10.20/16", "gateway": "10.20.0.7", "flags": "UGSc", "interface": "utun9"}, routes)
        self.assertNotIn("Destination", [route["destination"] for route in routes])
        interfaces = finance._parse_interfaces(IFCONFIG)
        utun9 = next(item for item in interfaces if item["name"] == "utun9")
        self.assertEqual(utun9["addresses"], [{"address": "10.20.0.7", "peer": "10.20.0.1"}])
        self.assertEqual(utun9["mtu"], 1400)
        resolvers = finance._parse_resolvers(SCUTIL)
        self.assertEqual(resolvers[0]["nameservers"], ["192.168.50.1"])
        self.assertEqual(resolvers[1]["domains"], ["szu.edu.cn"])
        self.assertEqual(resolvers[1]["ifIndex"], 42)

    def test_process_collection_separates_gui_registration_from_services(self):
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            daemons = root / "Library/LaunchDaemons"
            daemons.mkdir(parents=True)
            (daemons / "com.securelink.client.plist").write_bytes(plistlib.dumps({"Label": "com.securelink.client"}))
            report = finance.collect_processes(self.runner(calls), root=root, euid=501)
        self.assertTrue(report["officialGUIRunning"])
        self.assertEqual(report["officialBackendProcesses"], [{"name": name, "pids": [pid]} for name, pid in
                                                             [("SecureLink_Client", 19682), ("SecureLink_Agent", 61050),
                                                              ("SecureLink_Core", 61145), ("SecureLink_DP", 61149)]])
        self.assertEqual(report["userLaunchdServiceLabels"], [])  # application.* is a GUI registration
        self.assertFalse(report["systemLaunchdChecked"])
        self.assertEqual(report["installedServicePlists"][0]["label"], "com.securelink.client")
        self.assertTrue(all(Path(call[0]).name in {"pgrep", "launchctl"} for call in calls), calls)

    def test_root_path_checks_system_domain_and_reports_loaded_service(self):
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            daemons = root / "Library/LaunchDaemons"
            daemons.mkdir(parents=True)
            (daemons / "com.securelink.client.plist").write_bytes(plistlib.dumps({"Label": "com.securelink.client"}))
            report = finance.collect_processes(self.runner(calls), root=root, euid=0)
        self.assertTrue(report["systemLaunchdChecked"])
        self.assertTrue(report["officialLaunchdLoaded"])
        self.assertEqual(report["officialLoadedLabels"], ["com.securelink.client"])
        self.assertIn(("/bin/launchctl", "print", "system/com.securelink.client"), calls)

    def test_own_daemon_namespace_is_never_an_official_service(self):
        # The status helper and the executor live under local.szu.securelink;
        # counting them as official services would block every own-tunnel run.
        self.assertFalse(finance._is_official_label("local.szu.securelink.helper"))
        self.assertFalse(finance._is_official_label("local.szu.securelink.helper-executor"))
        self.assertTrue(finance._is_official_label("com.securelink.client"))
        self.assertTrue(finance._is_official_label("com.wangsu.edlp.service"))
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            daemons = root / "Library/LaunchDaemons"
            daemons.mkdir(parents=True)
            (daemons / "local.szu.securelink.helper.plist").write_bytes(
                plistlib.dumps({"Label": "local.szu.securelink.helper"}))
            (daemons / "com.securelink.client.plist").write_bytes(
                plistlib.dumps({"Label": "com.securelink.client"}))
            report = finance.collect_processes(self.runner(calls), root=root, euid=0)
        self.assertEqual(report["officialLoadedLabels"], ["com.securelink.client"])

    def test_network_collection_is_read_only(self):
        calls = []
        report = finance.collect_network(self.runner(calls))
        self.assertEqual(report["defaultRoutes"], [{"gateway": "192.168.50.3", "interface": "en0"}])
        self.assertIn("utun9", {item["name"] for item in report["interfaces"]})
        self.assertEqual(report["resolvers"][1]["nameservers"], ["10.20.0.53"])
        self.assertTrue(all(Path(call[0]).name in {"netstat", "ifconfig", "scutil"} for call in calls), calls)

    def test_prerequisites_fail_closed_without_touching_system_state(self):
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "out").mkdir()
            (root / "scripts").mkdir()
            verdict = finance.prerequisites(root, root / "out/finance-test", self.runner(calls), euid=501)
            self.assertFalse(verdict["passed"])
            self.assertEqual(verdict["mode"], "read-only-prerequisites")
            self.assertFalse(verdict["mutatedSystemState"])
            for expected in ("official-gui-running", "official-backend-running", "system-launchd-unverified",
                             "native-client-absent", "own-tunnel-not-implemented",
                             "live-orchestration-not-implemented"):
                self.assertIn(expected, verdict["blockers"])
            self.assertIn("own-tunnel-not-implemented", verdict["details"])
            processes = json.loads((root / "out/finance-test/process-evidence.json").read_text())
            self.assertTrue(processes["officialGUIRunning"])
            self.assertTrue((root / "out/finance-test/network-before.json").is_file())
        allowed = {"pgrep", "launchctl", "netstat", "ifconfig", "scutil"}
        self.assertTrue(all(Path(call[0]).name in allowed for call in calls), calls)

    def test_prerequisites_reject_evidence_outside_out(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "out").mkdir()
            for target in (root / "elsewhere", Path("/tmp/szu-finance-evidence")):
                with self.subTest(target=target), self.assertRaises(ValueError):
                    finance.prerequisites(root, target, self.runner([]), euid=501)
            self.assertFalse(Path("/tmp/szu-finance-evidence").exists())

    def test_prerequisites_entry_readiness_decides_tunnel_blocker(self):
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "out").mkdir()
            (root / "scripts").mkdir()
            entry = root / finance.STANDALONE_ENTRY
            entry.write_text("#!/bin/sh\nexit 1\n")
            # A stub file does not clear the blocker; only a ready executor does.
            verdict = finance.prerequisites(root, root / "out/finance-test", self.runner(calls),
                                            euid=501, entry_ready=True)
            self.assertNotIn("own-tunnel-not-implemented", verdict["blockers"])
            self.assertIn("live-orchestration-not-implemented", verdict["blockers"])
            self.assertFalse(verdict["passed"])
            verdict = finance.prerequisites(root, root / "out/finance-test", self.runner(calls),
                                            euid=501, entry_ready=False)
            self.assertIn("own-tunnel-not-implemented", verdict["blockers"])
            self.assertFalse(verdict["passed"])


class HelperLaunchdIntegrationTests(unittest.TestCase):
    """The optional helper query must decide honestly: evidence or unverified."""

    @staticmethod
    def quiet_runner(_argv):
        return ""

    @staticmethod
    def helper_report(loaded_labels):
        labels = [
            item["label"] for item in finance._installed_service_plists(Path("/"))
            if item.get("label") and finance._is_official_label(item["label"])
        ] or [
            "com.securelink.client",
            "com.wangsu.edlp.service",
            "com.wangsu.securebox.service",
        ]
        services = {label: {"state": "loaded" if label in loaded_labels else "exit",
                            "exitCode": 0 if label in loaded_labels else 113}
                    for label in labels if label}
        return {"schemaVersion": 1, "epoch": 1700000000,
                "helper": {"label": "local.szu.securelink.helper", "sha256": "c" * 64,
                           "allowedUid": 501},
                "services": services}

    def prerequisites_with_helper(self, helper):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "out").mkdir()
            (root / "scripts").mkdir()
            verdict = finance.prerequisites(root, root / "out/finance-test", self.quiet_runner,
                                            euid=501, helper_query=helper)
            evidence = json.loads((root / "out/finance-test/process-evidence.json").read_text())
        return verdict, evidence

    def test_helper_unloaded_vendors_clears_unverified(self):
        verdict, evidence = self.prerequisites_with_helper(lambda: self.helper_report(set()))
        self.assertTrue(evidence["systemLaunchdChecked"])
        self.assertTrue(evidence["systemLaunchdViaHelper"])
        self.assertEqual(evidence["helperSha256"], "c" * 64)
        self.assertEqual(evidence["serviceVerdicts"][0]["state"], "exit")
        self.assertNotIn("system-launchd-unverified", verdict["blockers"])
        self.assertNotIn("official-services-loaded", verdict["blockers"])
        self.assertTrue(verdict["helperAttempted"])

    def test_helper_loaded_vendor_blocks(self):
        installed = [
            item["label"] for item in finance._installed_service_plists(Path("/"))
            if item.get("label") and finance._is_official_label(item["label"])
        ] or [
            "com.securelink.client",
        ]
        loaded = {installed[0]} if installed else set()
        verdict, evidence = self.prerequisites_with_helper(lambda: self.helper_report(loaded))
        self.assertTrue(evidence["systemLaunchdChecked"])
        self.assertTrue(evidence["officialLaunchdLoaded"])
        for label in loaded:
            self.assertIn(label, evidence["officialLoadedLabels"])
        self.assertIn("official-services-loaded", verdict["blockers"])

    def test_helper_failure_keeps_unverified_and_records_error(self):
        def broken():
            raise OSError("socket missing")
        verdict, evidence = self.prerequisites_with_helper(broken)
        self.assertFalse(evidence["systemLaunchdChecked"])
        self.assertTrue(evidence["helperAttempted"])
        self.assertIn("helperError", evidence)
        self.assertIn("OSError", evidence["helperError"])
        self.assertIn("system-launchd-unverified", verdict["blockers"])

    def test_helper_malformed_response_treated_as_failure(self):
        verdict, evidence = self.prerequisites_with_helper(lambda: {"unexpected": True})
        self.assertFalse(evidence["systemLaunchdChecked"])
        self.assertIn("helperError", evidence)
        self.assertIn("system-launchd-unverified", verdict["blockers"])

    def test_no_helper_request_stays_deterministic(self):
        verdict, evidence = self.prerequisites_with_helper(None)
        self.assertFalse(evidence["helperAttempted"])
        self.assertFalse(evidence["systemLaunchdChecked"])
        self.assertIn("system-launchd-unverified", verdict["blockers"])


class CommandLineTests(unittest.TestCase):
    def verify(self, *arguments):
        return subprocess.run([sys.executable, str(ROOT / "scripts/verify-backend"), *arguments],
                              capture_output=True, text=True, timeout=120)

    def test_receipt_mode_reports_verdict_and_exit_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            good = write_run(Path(temporary) / "good")
            result = self.verify("finance", "--receipt", str(good))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(json.loads(result.stdout)["passed"])
            broken = write_run(Path(temporary) / "broken")
            (broken / "plan-journal.json").unlink()
            result = self.verify("finance", "--receipt", str(broken))
            self.assertEqual(result.returncode, 1)
            self.assertIn("missing-plan-journal", json.loads(result.stdout)["blockers"])

    def test_live_mode_needs_explicit_flags_and_rejects_probe_options(self):
        self.assertEqual(self.verify("finance").returncode, 2)
        self.assertEqual(self.verify("finance", "--allow-handshake").returncode, 2)
        self.assertEqual(self.verify("finance", "--capture-plan").returncode, 2)

    def test_live_mode_collects_read_only_evidence_and_fails_closed(self):
        result = self.verify("finance", "--allow-session-interruption", "--allow-protocol-change")
        self.assertEqual(result.returncode, 1)
        verdict = json.loads(result.stdout)
        self.addCleanup(shutil.rmtree, Path(verdict.get("runDirectory", ROOT / "out/missing")), True)
        self.assertEqual(verdict["mode"], "read-only-prerequisites")
        # The executor unit (3e) is installed and verified, so this blocker
        # clears; the full orchestration blocker keeps the gate closed.
        self.assertNotIn("own-tunnel-not-implemented", verdict["blockers"])
        self.assertIn("live-orchestration-not-implemented", verdict["blockers"])
        self.assertFalse((ROOT / "out/cas-handler-backup.json").exists())
        run = Path(verdict["runDirectory"])
        self.assertTrue((run / "process-evidence.json").is_file())
        self.assertTrue((run / "network-before.json").is_file())
        self.assertEqual(sorted(path.name for path in run.iterdir()),
                         ["network-before.json", "process-evidence.json"])


if __name__ == "__main__":
    unittest.main()
