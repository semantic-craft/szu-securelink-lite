"""All cases use validate-input/self-test; none opts into network handshake."""
import json
from pathlib import Path
import subprocess
import unittest

BINARY = Path(__file__).resolve().parents[1] / "out/openvpn3/build/szu-openvpn3-handshake"
VALID = {"config": "client\ndev tun\nremote 192.0.2.1 1194 udp\nauth-user-pass\n", "username": "SECRET-USER", "password": "SECRET-PASSWORD"}


@unittest.skipUnless(BINARY.is_file(), "optional source handshake probe not built")
class OpenVPN3HandshakeTests(unittest.TestCase):
    def run_probe(self, payload, args=("--validate-input",)):
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        result = subprocess.run([str(BINARY), *args], input=raw, capture_output=True, timeout=5)
        self.assertEqual(result.stderr, b"")
        self.assertNotIn(b"SECRET", result.stdout)
        self.assertLess(len(result.stdout), 4096)
        receipt = json.loads(result.stdout)
        for field in ("connectCalled", "socketObserved", "tunnelStarted", "connected", "routesChanged", "dnsChanged"):
            self.assertIs(receipt[field], False)
        return result.returncode, receipt

    def test_validate_input_does_not_call_connect(self):
        code, receipt = self.run_probe(VALID)
        self.assertEqual(code, 0)
        self.assertEqual(receipt["reason"], "input-validated")
        self.assertEqual(receipt["events"], [])

    def test_missing_explicit_mode_never_connects(self):
        for args in ((), ("SECRET-ARGV",), ("--validate-input", "SECRET-ARGV")):
            code, receipt = self.run_probe(VALID, args)
            self.assertEqual((code, receipt["reason"]), (3, "invalid-input"))

    def test_invalid_input_is_private(self):
        for payload in (b"SECRET NOT JSON", [], {**VALID, "unknown": "SECRET"}, {**VALID, "password": 1}, {**VALID, "username": ""}, {**VALID, "password": "SECRET\0"}, b"x" * (2 * 1024 * 1024 + 1)):
            code, receipt = self.run_probe(payload)
            self.assertEqual((code, receipt["reason"]), (3, "invalid-input"))

    def test_invalid_profile_is_private(self):
        code, receipt = self.run_probe({**VALID, "config": "client\nremote SECRET invalid-port\n"})
        self.assertEqual((code, receipt["reason"]), (2, "profile-rejected"))

    def test_uv_values_bypass_config_parser_length_and_keep_fixed_keys(self):
        code, receipt = self.run_probe({**VALID, "peerInfo": {"UV_CODE": "SECRET" * 100, "UV_EXTRA_PARAM_3": "SECRET"}})
        self.assertEqual((code, receipt["reason"]), (0, "input-validated"))
        for extra in ({"SECRET-KEY": "SECRET"}, {"UV_CODE": "SECRET\nINJECTED=value"}, {"UV_CODE": "SECRET\0"}, {"UV_CODE": "X" * 8193}, {"UV_CODE": False}):
            code, receipt = self.run_probe({**VALID, "peerInfo": extra})
            self.assertEqual((code, receipt["reason"]), (3, "invalid-input"))

    def test_synthetic_tun_barrier_event_whitelist_and_deadline(self):
        code, receipt = self.run_probe(b"", ("--self-test",))
        self.assertEqual((code, receipt["reason"]), (0, "self-test-passed"))
        self.assertIs(receipt["tunnelSetupRequested"], True)
        self.assertIs(receipt["deadlineReached"], True)
        self.assertIs(receipt["eventsDropped"], True)
        self.assertEqual(receipt["events"], ["AUTH_FAILED"] * 32)

    def test_confusion_and_deferred_features_are_explicit_tcp_only(self):
        tcp = {**VALID, "config": VALID["config"].replace("1194 udp", "1194 tcp"),
               "vendorConfusion": True, "activeShapingNotExercised": True, "gmsslRenegotiationNotExercised": True}
        code, receipt = self.run_probe(tcp)
        self.assertEqual((code, receipt["reason"]), (0, "input-validated"))
        for field in ["vendorConfusion", "clientCertificateSuppressed", "activeShapingNotExercised", "gmsslRenegotiationNotExercised"]:
            self.assertIs(receipt[field], True)
        code, receipt = self.run_probe({**tcp, "config": VALID["config"]})
        self.assertEqual((code, receipt["reason"]), (2, "profile-rejected"))
        for field in ["vendorConfusion", "activeShapingNotExercised", "gmsslRenegotiationNotExercised"]:
            for invalid in [1, "true", None, []]:
                code, receipt = self.run_probe({**tcp, field: invalid})
                self.assertEqual((code, receipt["reason"]), (3, "invalid-input"))

    def test_capture_flag_is_explicit_and_offline_validation_has_no_plan(self):
        code, receipt = self.run_probe(VALID, ("--validate-input", "--capture-plan"))
        self.assertEqual((code, receipt["reason"]), (0, "input-validated"))
        self.assertIs(receipt["planCaptureRequested"], True)
        self.assertIs(receipt["planComplete"], False)
        self.assertIsNone(receipt["plan"])
        for args in [("--capture-plan",), ("--capture-plan", "--allow-handshake"),
                     ("--validate-input", "--capture-plan", "SECRET")]:
            code, receipt = self.run_probe(VALID, args)
            self.assertEqual((code, receipt["reason"]), (3, "invalid-input"))

    def test_capture_production_callbacks_are_bounded_private_and_never_open_tun(self):
        code, receipt = self.run_probe(b"", ("--plan-self-test",))
        self.assertEqual((code, receipt["reason"]), (0, "plan-self-test-passed"))
        self.assertIs(receipt["planComplete"], True)
        plan = receipt["plan"]
        self.assertEqual(set(plan), {"version", "complete", "failure", "layer", "mtu", "remote", "addresses", "routes",
                                     "excludedRoutes", "routeMetricDefault", "redirect", "dns", "allowIPv4", "allowIPv6",
                                     "allowLocalDNS", "sessionNameDiscarded", "domainOptionsCaptured", "domainOptions", "ctrlOptionsCaptured", "ctrlOptionCount", "ctrlDuplicateKeys", "ctrlDuplicateDomains", "ctrlMappings"})
        self.assertEqual((plan["version"], plan["layer"], plan["mtu"]), (2, 3, 1400))
        self.assertIsNone(plan["failure"])
        self.assertEqual(plan["remote"], {"address": "192.0.2.1", "ipv6": False})
        self.assertEqual(plan["addresses"][0], {"address": "10.8.0.2", "prefixLength": 24, "gateway": "10.8.0.1", "ipv6": False, "net30": False})
        self.assertEqual(plan["routes"][0], {"address": "10.20.0.0", "prefixLength": 16, "metric": -1, "ipv6": False})
        self.assertEqual(plan["excludedRoutes"][0]["address"], "192.0.2.1")
        self.assertIs(plan["allowIPv6"], False)  # Capture preserves requirements; execution validator must decide.
        self.assertEqual(plan["dns"]["servers"][0]["domains"], ["example.edu"])
        self.assertEqual(plan["dns"]["searchDomains"], ["dept.example.edu"])
        self.assertIs(plan["sessionNameDiscarded"], True)

    def test_upstream_unspecified_mtu_is_complete_without_inventing_effective_value(self):
        code, receipt = self.run_probe(b"", ("--plan-default-mtu-self-test",))
        self.assertEqual(code, 0)
        self.assertIs(receipt["planComplete"], True)
        self.assertIs(receipt["plan"]["complete"], True)
        self.assertIsNone(receipt["plan"]["mtu"])
        self.assertIsNone(receipt["plan"]["failure"])
        self.assertNotIn("effectiveMTU", receipt["plan"])
        self.assertTrue(receipt["plan"]["ctrlOptionsCaptured"])
        self.assertEqual(receipt["plan"]["ctrlOptionCount"], 1)
        self.assertEqual(receipt["plan"]["ctrlMappings"], [{"domain": "portal.example.edu", "addresses": ["192.0.2.5", "192.0.2.6"], "addressPolicy": "any"}])
        self.assertIs(receipt["plan"]["domainOptionsCaptured"], True)
        self.assertEqual(receipt["plan"]["domainOptions"], ["finance.example.edu", "*.example.edu", ".another.example.edu"])

    def test_default_barrier_does_not_capture_any_network_values(self):
        code, receipt = self.run_probe(b"", ("--self-test",))
        self.assertEqual(code, 0)
        self.assertIs(receipt["planCaptureRequested"], False)
        self.assertIs(receipt["planComplete"], False)
        self.assertIsNone(receipt["plan"])
