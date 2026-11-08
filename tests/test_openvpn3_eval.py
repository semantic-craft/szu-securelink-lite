"""Real upstream parser with synthetic in-memory input only; no campus access."""
import json
from pathlib import Path
import subprocess
import unittest

BINARY = Path(__file__).resolve().parents[1] / "out/openvpn3/build/szu-openvpn3-eval"
VALID = b"client\ndev tun\nremote 192.0.2.1 1194 udp\nauth-user-pass\n"


@unittest.skipUnless(BINARY.is_file(), "optional source evaluator not built; run scripts/build-openvpn3-eval --fetch once")
class OpenVPN3EvaluationTests(unittest.TestCase):
    def evaluate(self, data, args=()):
        result = subprocess.run([str(BINARY), *args], input=data, capture_output=True, timeout=12)
        self.assertEqual(result.stderr, b"")
        self.assertNotIn(b"SECRET", result.stdout)
        self.assertLess(len(result.stdout), 1024)
        receipt = json.loads(result.stdout)
        self.assertEqual(set(receipt), {"accepted", "mode", "networkOpened", "tunnelStarted", "reason"})
        self.assertEqual(receipt["mode"], "offline-config-evaluation")
        self.assertIs(receipt["networkOpened"], False)
        self.assertIs(receipt["tunnelStarted"], False)
        return result.returncode, receipt

    def test_valid_profile_is_evaluated_without_connection(self):
        code, receipt = self.evaluate(VALID)
        self.assertEqual(code, 0)
        self.assertIs(receipt["accepted"], True)

    def test_missing_remote_and_malformed_port_reject_without_echo(self):
        for data, reason in ((b"client\n", "missing-remote"), (b"client\nremote SECRET-SENTINEL invalid-port\n", "rejected")):
            code, receipt = self.evaluate(data)
            self.assertEqual(code, 2)
            self.assertEqual(receipt["reason"], reason)

    def test_argv_cannot_supply_a_configuration(self):
        code, receipt = self.evaluate(b"", ["SECRET-SENTINEL"])
        self.assertEqual(code, 3)
        self.assertEqual(receipt["reason"], "invalid-input")

    def test_empty_nul_and_oversized_input_are_rejected(self):
        for data in (b"", VALID + b"\0SECRET", b"X" * (2 * 1024 * 1024 + 1)):
            code, receipt = self.evaluate(data)
            self.assertEqual(code, 3)
            self.assertEqual(receipt["reason"], "invalid-input")

    def test_success_does_not_prove_vendor_directive_support(self):
        # The upstream helper deliberately only performs preliminary evaluation.
        # This passes despite gmtls not being a supported OpenVPN 3 extension.
        code, receipt = self.evaluate(VALID + b"gmtls\n")
        self.assertEqual(code, 0)
        self.assertIs(receipt["tunnelStarted"], False)

    def test_inline_secrets_never_leave_process(self):
        code, _ = self.evaluate(VALID + b"<auth-user-pass>\nSECRET-USER\nSECRET-PASSWORD\n</auth-user-pass>\n")
        self.assertIn(code, (0, 2))
