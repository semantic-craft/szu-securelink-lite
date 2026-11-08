"""Differential test: plan_ops.hpp must match network_plan.py exactly.

operations() strings compare byte-for-byte and the ten Journal scenarios run
in lockstep on both implementations. tests are pure offline models.
"""
import importlib.machinery
import importlib.util
import json
import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))  # network_plan imports vendor_dns_routes
loader = importlib.machinery.SourceFileLoader("network_plan", str(ROOT / "scripts/network_plan.py"))
spec = importlib.util.spec_from_loader(loader.name, loader)
plan = importlib.util.module_from_spec(spec)
loader.exec_module(plan)

SESSION = "f50ed258-6ef7-4f2c-9b63-c0838c89c9fa"
HANDLE = "b5c9d692-528e-44d3-966c-9f3772fbc3a9"


def python_plan():
    context = plan.Context(SESSION, 120, 443, ("campus.example",))
    result = plan.validate_capture(plan.decode_capture(json_capture().encode()), context)
    if result.issues or result.plan is None:
        raise AssertionError(f"fixture plan invalid: {result.issues}")
    return result.plan


def json_capture():
    return (
        '{"version": 2, "ctrlOptionsCaptured": true, "ctrlOptionCount": 0, "ctrlDuplicateKeys": 0,'
        ' "ctrlDuplicateDomains": 0, "ctrlMappings": [], "domainOptionsCaptured": true,'
        ' "domainOptions": [], "complete": true, "failure": null, "layer": 3, "mtu": 1400,'
        ' "remote": {"address": "198.51.100.4", "ipv6": false},'
        ' "addresses": [{"address": "10.20.0.2", "prefixLength": 30, "gateway": "10.20.0.1",'
        ' "ipv6": false, "net30": false}],'
        ' "routes": [{"address": "10.30.0.0", "prefixLength": 16, "metric": -1, "ipv6": false}],'
        ' "excludedRoutes": [], "routeMetricDefault": -1, "redirect": null,'
        ' "dns": {"fromDhcp": true, "searchDomains": [], "servers": [{"priority": 0,'
        ' "addresses": [{"address": "10.30.0.53", "port": 0}],'
        ' "domains": ["campus.example", "finance.campus.example"]}]},'
        ' "allowIPv4": true, "allowIPv6": null, "allowLocalDNS": true, "sessionNameDiscarded": true}'
    )


LEASE = plan.InterfaceLease(SESSION, "utun9", 9, HANDLE)


def describe(removals, issues):
    keys = ",".join(op.key for op in removals) or "-"
    codes = ",".join(f"{issue.code}:{issue.path}" for issue in issues) or "-"
    return f"removals={keys} issues={codes}\n"


def python_scenarios():
    ops_list = plan.operations(python_plan(), LEASE)
    out = []

    # S1 all created, full cleanup
    journal = plan.Journal(python_plan(), LEASE)
    for index in range(len(ops_list)):
        journal.record(index, outcome="created", before=None, after=ops_list[index])
    current = {op.key: op for op in ops_list}
    removals, issues = journal.cleanup(current, LEASE)
    out.append(("S1 " + describe(removals, issues)))

    # S2 only interface created
    journal = plan.Journal(python_plan(), LEASE)
    journal.record(0, outcome="created", before=None, after=ops_list[0])
    removals, issues = journal.cleanup({ops_list[0].key: ops_list[0]}, LEASE)
    out.append(("S2 " + describe(removals, issues)))

    # S3 interface record drifted
    journal = plan.Journal(python_plan(), LEASE)
    journal.record(0, outcome="created", before=None, after=ops_list[0])
    journal.record(1, outcome="created", before=None, after=ops_list[1])
    drifted = plan.Operation(ops_list[0].kind, ops_list[0].key, '{"drift":true}')
    removals, issues = journal.cleanup(
        {drifted.key: drifted, ops_list[1].key: ops_list[1]}, LEASE)
    out.append(("S3 " + describe(removals, issues)))

    # S4 foreign record bound to our interface
    journal = plan.Journal(python_plan(), LEASE)
    journal.record(0, outcome="created", before=None, after=ops_list[0])
    foreign = plan.Operation(
        "interface-route", "route:198.51.100.0/24",
        '{"gateway":"198.51.100.1","handleIdentity":"b5c9d692-528e-44d3-966c-9f3772fbc3a9",'
        '"ifindex":9,"interface":"utun9","metric":-1,"network":"198.51.100.0/24",'
        '"origin":"foreign","scope":"unscoped","sessionID":"f50ed258-6ef7-4f2c-9b63-c0838c89c9fa"}')
    removals, issues = journal.cleanup(
        {ops_list[0].key: ops_list[0], foreign.key: foreign}, LEASE)
    out.append(("S4 " + describe(removals, issues)))

    # S5 route recorded without owning the interface
    journal = plan.Journal(python_plan(), LEASE)
    try:
        journal.record(1, outcome="created", before=None, after=ops_list[1])
        out.append("S5 NO-ERROR\n")
    except ValueError as error:
        out.append(f"S5 ERROR {error}\n")

    # S6 duplicate success receipt
    journal = plan.Journal(python_plan(), LEASE)
    journal.record(0, outcome="created", before=None, after=ops_list[0])
    try:
        journal.record(0, outcome="created", before=None, after=ops_list[0])
        out.append("S6 NO-ERROR\n")
    except ValueError as error:
        out.append(f"S6 ERROR {error}\n")

    # S7 cleanup under a replaced lease
    journal = plan.Journal(python_plan(), LEASE)
    replaced = plan.InterfaceLease(SESSION, "utun10", 9, HANDLE)
    current = {op.key: op for op in ops_list}
    removals, issues = journal.cleanup(current, replaced)
    out.append(("S7 " + describe(removals, issues)))

    # S8 invalid outcome
    journal = plan.Journal(python_plan(), LEASE)
    try:
        journal.record(2, outcome="bogus", before=ops_list[2], after=None)
        out.append("S8 NO-ERROR\n")
    except ValueError as error:
        out.append(f"S8 ERROR {error}\n")

    # S9 preexisting never grants ownership; a later created claim is rejected
    journal = plan.Journal(python_plan(), LEASE)
    journal.record(1, outcome="preexisting", before=ops_list[1], after=None)
    try:
        journal.record(1, outcome="created", before=None, after=ops_list[1])
        out.append("S9 NO-ERROR\n")
    except ValueError as error:
        out.append(f"S9 ERROR {error}\n")
    removals, issues = journal.cleanup({}, LEASE)
    out.append(("S9b " + describe(removals, issues)))

    # S10 uncreated-but-present expected record retains the interface
    journal = plan.Journal(python_plan(), LEASE)
    journal.record(0, outcome="created", before=None, after=ops_list[0])
    current = {ops_list[0].key: ops_list[0], ops_list[2].key: ops_list[2]}
    removals, issues = journal.cleanup(current, LEASE)
    out.append(("S10 " + describe(removals, issues)))
    return out


@unittest.skipUnless(platform.system() == "Darwin", "Apple SDK required")
class PlanOpsDifferentialTests(unittest.TestCase):
    binary: Path = None
    temp: tempfile.TemporaryDirectory = None

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="plan-ops-diff-")
        cls.binary = Path(cls.temp.name) / "plan-ops"
        build = subprocess.run([
            "xcrun", "clang++", "-std=c++17", "-O1", "-Wall", "-Wextra", "-Werror",
            str(ROOT / "native/network-helper/plan_ops_main.mm"), "-o", str(cls.binary),
        ], capture_output=True, timeout=120)
        if build.returncode != 0:
            raise AssertionError("plan-ops build failed: " + build.stderr.decode())

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def cpp(self, mode):
        if isinstance(mode, str):
            mode = [mode]
        run = subprocess.run([str(self.binary), *mode], capture_output=True, text=True, timeout=20)
        self.assertEqual(run.returncode, 0, run.stderr)
        return run.stdout

    def test_operations_strings_match_exactly(self):
        expected = plan.operations(python_plan(), LEASE)
        python_lines = [f"{op.kind}|{op.key}|{op.value}" for op in expected]
        self.assertEqual("\n".join(python_lines) + "\n", self.cpp("operations"))

    def test_static_route_operations_match_exactly(self):
        # Vendor local policy: split tunnel, school-internal ranges only; a
        # static route already covered by the session plan is skipped.
        static_file = self.temp.name + "/static.json"
        Path(static_file).write_text(json.dumps({
            "staticRoutes": ["10.30.0.0/16", "172.31.132.60/32", "172.31.0.0/16"]}))
        base = python_plan()
        expected = plan.static_route_operations(base, LEASE, ("10.30.0.0/16", "172.31.132.60/32", "172.31.0.0/16"))
        self.assertEqual([op.key for op in expected], ["route:172.31.132.60/32", "route:172.31.0.0/16"])
        self.assertIn('"origin":"vendor-static-route"', expected[0].value)
        self.assertIn('"gateway":"10.20.0.1"', expected[0].value)
        python_lines = [f"{op.kind}|{op.key}|{op.value}" for op in expected]
        self.assertEqual("\n".join(python_lines) + "\n", self.cpp(["static-route-operations", static_file]))
        with self.assertRaises(ValueError) as raised:
            wrong = plan.InterfaceLease("ffffffff-ffff-4fff-8fff-ffffffffffff", "utun9", 9, HANDLE)
            plan.static_route_operations(base, wrong, ("10.30.0.0/16",))
        self.assertEqual(str(raised.exception), "invalid-interface-lease")

    def test_push_operations_strings_match_exactly(self):
        # Push deltas carry only pushed-prefix route ops with origin ctrl-push;
        # the delta capture's address fields never produce owned-interface ops.
        base = python_plan()
        delta = plan.Plan(context=base.context, remote=base.remote, mtu=base.mtu,
                          addresses=base.addresses, routes=("10.30.0.0/16",),
                          dns_servers=(), dns_domains=())
        expected = plan.push_operations(delta, LEASE)
        self.assertEqual([op.kind for op in expected], ["interface-route"])
        self.assertIn('"origin":"ctrl-push"', expected[0].value)
        self.assertIn('"network":"10.30.0.0/16"', expected[0].value)
        self.assertIn('"gateway":"10.20.0.1"', expected[0].value)
        python_lines = [f"{op.kind}|{op.key}|{op.value}" for op in expected]
        self.assertEqual("\n".join(python_lines) + "\n", self.cpp("push-operations"))
        with self.assertRaises(ValueError) as raised:
            wrong = plan.InterfaceLease("ffffffff-ffff-4fff-8fff-ffffffffffff", "utun9", 9, HANDLE)
            plan.push_operations(delta, wrong)
        self.assertEqual(str(raised.exception), "invalid-interface-lease")

    def test_operations_rejects_lease_mismatch(self):
        with self.assertRaises(ValueError) as raised:
            wrong = plan.InterfaceLease("ffffffff-ffff-4fff-8fff-ffffffffffff", "utun9", 9, HANDLE)
            plan.operations(python_plan(), wrong)
        self.assertEqual(str(raised.exception), "invalid-interface-lease")
        self.assertEqual("ERROR invalid-interface-lease\n", self.cpp("lease-mismatch"))

    def test_journal_scenarios_match_exactly(self):
        self.assertEqual("".join(python_scenarios()), self.cpp("scenarios"))

    def test_python_operations_shape_sanity(self):
        ops_list = plan.operations(python_plan(), LEASE)
        self.assertEqual([op.kind for op in ops_list],
                         ["owned-interface", "interface-route", "interface-route",
                          "interface-route", "supplemental-resolver"])
        self.assertIn('"SupplementalMatchDomainsNoSearch":1', ops_list[4].value)
        # interface-prefix uses the interface address itself as gateway;
        # the pushed prefix uses the first IPv4 peer as gateway; the vendor
        # DNS host route pins its resolver /32 to that peer.
        self.assertIn('"gateway":"10.20.0.2"', ops_list[1].value)
        self.assertIn('"gateway":"10.20.0.1"', ops_list[2].value)
        self.assertIn('"origin":"vendor-dns-host-route"', ops_list[3].value)
        self.assertIn('"network":"10.30.0.53/32"', ops_list[3].value)
        self.assertIn('"gateway":"10.20.0.1"', ops_list[3].value)
        self.assertIn('"gatewayKind":"ip"', ops_list[2].value)


if __name__ == "__main__":
    unittest.main()
