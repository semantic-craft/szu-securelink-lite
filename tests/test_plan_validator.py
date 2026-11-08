"""Differential test: the C++ plan validator must agree with network_plan.py.

Every case is judged by both implementations and the issue sets plus plan
fields must match exactly. This is the authority for the 3a C++ mirror; any
drift fails the project gate.
"""
import copy
import importlib.machinery
import importlib.util
import json
import platform
import random
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
CONTEXT = {"sessionID": SESSION, "durationSeconds": 120, "remotePort": 443,
           "verifiedDNSSuffixes": ["campus.example"]}
CONTEXT_NO_SUFFIX = dict(CONTEXT, verifiedDNSSuffixes=[])


def capture():
    return {
        "version": 2, "ctrlOptionsCaptured": True, "ctrlOptionCount": 0, "ctrlDuplicateKeys": 0,
        "ctrlDuplicateDomains": 0, "ctrlMappings": [], "domainOptionsCaptured": True,
        "domainOptions": [], "complete": True, "failure": None, "layer": 3, "mtu": 1400,
        "remote": {"address": "198.51.100.4", "ipv6": False},
        "addresses": [{"address": "10.20.0.2", "prefixLength": 30, "gateway": "10.20.0.1",
                       "ipv6": False, "net30": False}],
        "routes": [{"address": "10.30.0.0", "prefixLength": 16, "metric": -1, "ipv6": False}],
        "excludedRoutes": [], "routeMetricDefault": -1, "redirect": None,
        "dns": {"fromDhcp": True, "searchDomains": [], "servers": [
            {"priority": 0, "addresses": [{"address": "10.30.0.53", "port": 0}],
             "domains": ["campus.example", "finance.campus.example"]}]},
        "allowIPv4": True, "allowIPv6": None, "allowLocalDNS": True,
        "sessionNameDiscarded": True,
    }


def python_context(context=CONTEXT):
    return plan.Context(context["sessionID"], context["durationSeconds"], context["remotePort"],
                        tuple(context["verifiedDNSSuffixes"]))


@unittest.skipUnless(platform.system() == "Darwin", "Apple SDK required")
class DifferentialTests(unittest.TestCase):
    binary: Path = None
    temp: tempfile.TemporaryDirectory = None

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="plan-validator-diff-")
        cls.binary = Path(cls.temp.name) / "plan-validate"
        build = subprocess.run([
            "xcrun", "clang++", "-std=c++17", "-O1", "-Wall", "-Wextra", "-Werror",
            str(ROOT / "native/network-helper/plan_validate_main.mm"), "-o", str(cls.binary),
        ], capture_output=True, timeout=120)
        if build.returncode != 0:
            raise AssertionError("validator CLI build failed: " + build.stderr.decode())

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def cpp_verdict(self, value, context=CONTEXT):
        capture_path = Path(self.temp.name) / "capture.json"
        context_path = Path(self.temp.name) / "context.json"
        capture_path.write_text(json.dumps(value, ensure_ascii=False))
        context_path.write_text(json.dumps(context))
        run = subprocess.run([str(self.binary), str(context_path), str(capture_path)],
                             capture_output=True, text=True, timeout=20)
        self.assertEqual(run.returncode, 0, run.stderr)
        lines = [line.split("\t") for line in run.stdout.splitlines() if line]
        if lines and lines[0][0] == "DECODE":
            return ("decode", lines[0][1]), None
        if not lines or lines[0][0] != "PLAN":
            return frozenset((line[0], line[1]) for line in lines), None
        issues = frozenset()  # a valid plan carries no issues by construction
        plan_fields = {"remote": None, "mtu": None, "addresses": [], "routes": [],
                       "servers": [], "domains": [], "hostRoutes": []}
        for line in lines:
            if line[0] == "remote":
                plan_fields["remote"] = line[1]
            elif line[0] == "mtu":
                plan_fields["mtu"] = int(line[1])
            elif line[0] == "address":
                parts = line[1].split(",")
                plan_fields.setdefault("addresses", []).append((parts[0], int(parts[1]), parts[2]))
            elif line[0] == "route":
                plan_fields.setdefault("routes", []).append(line[1])
            elif line[0] == "server":
                plan_fields.setdefault("servers", []).append(line[1])
            elif line[0] == "domain":
                plan_fields.setdefault("domains", []).append(line[1])
            elif line[0] == "hostroute":
                destination, gateway = line[1].split(",")
                plan_fields.setdefault("hostRoutes", []).append((destination, gateway))
        return issues, plan_fields

    def python_verdict(self, value, context=CONTEXT):
        try:
            result = plan.validate_capture(value, python_context(context))
        except ValueError as error:
            return ("decode", str(error)), None
        issues = frozenset((issue.code, issue.path) for issue in result.issues)
        if not result.issues and result.plan is not None:
            fields = {"remote": result.plan.remote, "mtu": result.plan.mtu,
                      "addresses": [tuple(entry) for entry in result.plan.addresses],
                      "routes": list(result.plan.routes), "servers": list(result.plan.dns_servers),
                      "domains": list(result.plan.dns_domains),
                      "hostRoutes": [tuple(entry) for entry in result.plan.dns_host_routes]}
            return issues, fields
        return issues, None

    def assert_agrees(self, value, context=CONTEXT, label=""):
        py_issues, py_plan = self.python_verdict(value, context)
        cpp_issues, cpp_plan = self.cpp_verdict(value, context)
        label = label or "case"
        self.assertEqual(py_issues, cpp_issues, f"{label}: issues differ")
        self.assertEqual(py_plan, cpp_plan, f"{label}: plan fields differ")

    def curated_cases(self):
        cases = []
        base = capture()
        cases.append(("baseline", copy.deepcopy(base)))

        value = capture(); value["ctrlOptionCount"] = 1
        value["ctrlMappings"] = [{"domain": "portal.campus.example", "addresses": ["10.30.0.5"],
                                  "addressPolicy": "any"}]
        cases.append(("ctrl-intent", value))
        value = capture(); value["ctrlOptionsCaptured"] = False
        cases.append(("ctrl-uncaptured", value))
        value = capture(); value["version"] = 1
        cases.append(("version-old", value))
        value = capture(); value["domainOptionsCaptured"] = False
        cases.append(("domain-uncaptured", value))
        value = capture(); value["domainOptionsCaptured"] = True; value["domainOptions"] = [".campus.example"]
        cases.append(("domain-dynamic", value))
        value = capture(); value["routes"][0]["address"] = "203.0.113.0"; value["routes"][0]["prefixLength"] = 24
        cases.append(("public-prefix", value))
        value = capture(); value["SECRET-UNKNOWN"] = "sudo route delete default"
        cases.append(("unknown-field", value))
        for key in ["proxy", "commands", "sessionName", "privateKey"]:
            value = capture(); value[key] = "SECRET"
            cases.append((f"unknown-{key}", value))
        for network, length in [("0.0.0.0", 0), ("128.0.0.0", 1)]:
            value = capture(); value["routes"].append(
                {"address": network, "prefixLength": length, "metric": -1, "ipv6": False})
            cases.append((f"global-{network}", value))
        value = capture()
        value["routes"] = [{"address": "128.0.0.0", "prefixLength": 1, "metric": -1, "ipv6": False},
                           {"address": "10.30.0.0", "prefixLength": 16, "metric": -1, "ipv6": False}]
        cases.append(("half-split-union", value))
        value = capture(); value["remote"] = {"address": "10.30.0.9", "ipv6": False}
        cases.append(("remote-in-route", value))
        value = capture(); value["remote"] = {"address": "10.20.0.2", "ipv6": False}
        cases.append(("remote-in-interface", value))
        value = capture(); value["addresses"][0]["ipv6"] = True
        cases.append(("family-mismatch-interface", value))
        value = capture(); value["routes"][0]["ipv6"] = True
        cases.append(("family-mismatch-route", value))
        for redirect in [None, {"ipv4": False, "ipv6": False, "flags": 0},
                         {"ipv4": False, "ipv6": False, "flags": 256},
                         {"ipv4": True, "ipv6": False, "flags": 256},
                         {"ipv4": False, "ipv6": False, "flags": 1}]:
            value = capture(); value["redirect"] = redirect
            cases.append((f"redirect-{redirect}", value))
        value = capture(); value["addresses"][0]["prefixLength"] = 33
        cases.append(("prefix-too-big", value))
        value = capture(); value["addresses"][0]["address"] = "0.0.0.5"
        cases.append(("zero-octet-address", value))
        value = capture(); value["addresses"][0]["address"] = "240.1.1.1"
        cases.append(("reserved-address", value))
        value = capture(); value["addresses"][0]["gateway"] = "10.20.0.2"
        cases.append(("gateway-equals-address", value))
        value = capture(); value["addresses"][0]["net30"] = True
        cases.append(("net30", value))
        value = capture()
        value["addresses"].append({"address": "10.40.0.2", "prefixLength": 24, "gateway": "",
                                   "ipv6": False, "net30": False})
        cases.append(("two-v4-addresses", value))
        value = capture(); value["mtu"] = 1279
        cases.append(("mtu-low", value))
        value = capture(); value["mtu"] = 9001
        cases.append(("mtu-high", value))
        value = capture(); value["addresses"][0]["prefixLength"] = 1
        cases.append(("interface-global-prefix", value))
        value = capture(); value["addresses"] = []
        cases.append(("no-addresses", value))
        value = capture()
        value["routes"] = [{"address": "2001:db8::", "prefixLength": 64, "metric": -1, "ipv6": True}]
        cases.append(("v6-route-no-v6-address", value))
        value = capture()
        value["routes"] = [{"address": "10.30.0.0", "prefixLength": 16, "metric": 0, "ipv6": False}]
        cases.append(("route-metric", value))
        value = capture()
        value["routes"] = [{"address": "10.30.0.5", "prefixLength": 16, "metric": -1, "ipv6": False}]
        cases.append(("route-host-bits", value))
        value = capture(); value["addresses"][0]["gateway"] = ""
        cases.append(("no-gateway", value))
        value = capture()
        value["dns"]["servers"][0]["domains"] = ["other.example"]
        cases.append(("unverified-domain", value))
        value = capture()
        value["dns"]["servers"][0]["domains"] = []
        cases.append(("global-dns", value))
        value = capture()
        value["dns"]["servers"][0]["addresses"] = [{"address": "10.30.0.53", "port": 8}]
        cases.append(("dns-port", value))
        value = capture()
        value["dns"]["servers"].append({"priority": 1, "addresses": [], "domains": ["campus.example"]})
        cases.append(("two-resolvers", value))
        value = capture(); value["dns"] = None
        cases.append(("dns-null", value))
        value = capture(); value["allowLocalDNS"] = False
        cases.append(("block-policy", value))
        value = capture(); value["sessionNameDiscarded"] = None
        cases.append(("flag-not-bool", value))
        value = capture(); value["complete"] = False
        cases.append(("incomplete", value))
        value = capture(); value["failure"] = "timeout"
        cases.append(("failure-text", value))
        value = capture(); value["excludedRoutes"] = [{"address": "10.9.0.0", "prefixLength": 24,
                                                       "metric": -1, "ipv6": False}]
        cases.append(("excluded-routes", value))
        value = capture(); value["routeMetricDefault"] = 100
        cases.append(("metric-default", value))
        # IPv6 end-to-end positive path
        value = capture()
        value["remote"] = {"address": "2001:db8::4", "ipv6": True}
        value["addresses"] = [{"address": "fd00:0:0:1::2", "prefixLength": 64, "gateway": "",
                               "ipv6": True, "net30": False}]
        value["routes"] = [{"address": "fd00:0:0:2::", "prefixLength": 64, "metric": -1, "ipv6": True}]
        cases.append(("ipv6-positive", value))
        # Vendor DNS host-route derivation: reachable conflicts and skips.
        value = capture()
        value["dns"]["servers"][0]["addresses"].append({"address": "192.0.2.53", "port": 53})
        cases.append(("dns-hostroute-two-servers", value))
        value = capture()
        value["allowIPv4"] = False
        cases.append(("dns-hostroute-ipv4-disabled", value))
        value = capture()
        value["dns"]["servers"][0]["addresses"] = [{"address": "2001:db8::53", "port": 0}]
        cases.append(("dns-hostroute-ipv6-server", value))
        value = capture()
        value["addresses"] = [{"address": "fd00:0:0:1::2", "prefixLength": 64, "gateway": "",
                               "ipv6": True, "net30": False}]
        value["routes"] = [{"address": "fd00:0:0:2::", "prefixLength": 64, "metric": -1, "ipv6": True}]
        cases.append(("dns-hostroute-no-ipv4-gateway", value))
        value = capture()
        value["dns"]["servers"][0]["addresses"] = [{"address": "10.20.0.1", "port": 0}]
        cases.append(("dns-hostroute-gateway-conflict", value))
        value = capture()
        value["dns"]["servers"][0]["addresses"] = [{"address": "10.20.0.2", "port": 0}]
        cases.append(("dns-hostroute-local-address-conflict", value))
        value = capture()
        value["dns"]["servers"][0]["addresses"] = [{"address": "10.20.0.7", "port": 0}]
        cases.append(("dns-hostroute-remote-conflict", value))
        value = capture()
        value["routes"].append({"address": "10.30.0.53", "prefixLength": 32, "metric": -1, "ipv6": False})
        cases.append(("dns-hostroute-covered-by-32", value))
        value = capture()
        value["dns"]["fromDhcp"] = False
        cases.append(("dns-hostroute-non-dhcp-source", value))
        return cases

    def fuzz_cases(self):
        rng = random.Random(20261105)
        strings = ["10.0.0.1", "10.20.0.2", "fd00::1", "campus.example", "x", "", "0.0.0.0",
                   "::1", "999.1.1.1", "1:2:3:4:5:6:7:8", "%eth0", "240.0.0.1"]
        scalars = [None, True, False, 0, 1, -1, 2, 300, 443, 64, 8192, 1.5, "2", [], {},
                   9007199254740993, "10.30.0.0"]
        paths = [
            ("version",), ("layer",), ("mtu",), ("complete",), ("failure",), ("remote",),
            ("addresses",), ("routes",), ("dns",), ("redirect",), ("excludedRoutes",),
            ("routeMetricDefault",), ("allowIPv4",), ("allowIPv6",), ("allowLocalDNS",),
            ("sessionNameDiscarded",), ("ctrlOptionCount",), ("ctrlMappings",),
            ("domainOptions",), ("domainOptionsCaptured",), ("ctrlOptionsCaptured",),
            ("addresses", 0, "prefixLength"), ("addresses", 0, "gateway"), ("addresses", 0, "net30"),
            ("addresses", 0, "ipv6"), ("addresses", 0, "address"),
            ("remote", "address"), ("remote", "ipv6"),
            ("routes", 0, "prefixLength"), ("routes", 0, "metric"), ("routes", 0, "ipv6"),
            ("routes", 0, "address"), ("dns", "fromDhcp"), ("dns", "searchDomains"),
            ("dns", "servers"), ("dns", "servers", 0, "priority"),
            ("dns", "servers", 0, "addresses"), ("dns", "servers", 0, "domains"),
            ("dns", "servers", 0, "addresses", 0, "port"),
            ("dns", "servers", 0, "addresses", 0, "address"),
        ]

        def set_path(target, path, value):
            node = target
            for key in path[:-1]:
                if isinstance(key, int):
                    if not isinstance(node, list) or key >= len(node):
                        return False
                    node = node[key]
                else:
                    if not isinstance(node, dict) or key not in node:
                        return False
                    node = node[key]
            if isinstance(path[-1], int):
                if not isinstance(node, list) or path[-1] >= len(node):
                    return False
                node[path[-1]] = value
            else:
                if not isinstance(node, dict):
                    return False
                node[path[-1]] = value
            return True

        cases = []
        for index in range(400):
            value = capture()
            action = rng.random()
            path = rng.choice(paths)
            if action < 0.15:
                value[rng.choice([str(i) for i in range(20)] + ["version", "dns"])] = "SECRET"
            elif action < 0.75:
                replacement = rng.choice(strings + scalars)
                if not set_path(value, path, replacement):
                    continue
            elif action < 0.9:
                replacement = rng.choice(strings)
                if not set_path(value, path, replacement):
                    continue
            else:
                key = path[-1]
                parent = value
                ok = True
                for step in path[:-1]:
                    try:
                        parent = parent[step]
                    except (KeyError, IndexError, TypeError):
                        ok = False
                        break
                if ok and isinstance(parent, dict):
                    duplicate = {}
                    for member, member_value in parent.items():
                        duplicate[member] = member_value
                        if member == key:
                            duplicate[member + "_dup"] = member_value
                    value[path[0]] if len(path) == 1 else None
                    # represent the duplicate only when the parent is the root
                    if len(path) == 1:
                        value = duplicate
            cases.append((f"fuzz-{index}", value))
        return cases

    def test_curated_cases_agree(self):
        for label, value in self.curated_cases():
            with self.subTest(case=label):
                self.assert_agrees(value, label=label)

    def test_fuzz_cases_agree(self):
        for label, value in self.fuzz_cases():
            with self.subTest(case=label):
                self.assert_agrees(value, label=label)

    def test_context_variants_agree(self):
        for context in [CONTEXT, CONTEXT_NO_SUFFIX,
                        dict(CONTEXT, sessionID="bad"),
                        dict(CONTEXT, durationSeconds=301),
                        dict(CONTEXT, durationSeconds=0),
                        dict(CONTEXT, remotePort=0),
                        dict(CONTEXT, verifiedDNSSuffixes=["example"]),
                        dict(CONTEXT, verifiedDNSSuffixes=["CAMPUS.EXAMPLE"])]:
            with self.subTest(context=context["sessionID"][:8] + str(context.get("durationSeconds"))):
                value = capture()
                self.assert_agrees(value, context=context, label="context-variant")
                value = capture()
                value["dns"]["servers"][0]["domains"] = ["Campus.Example", "a.campus.example"]
                self.assert_agrees(value, context=context, label="context-variant-dns")

    def test_decode_errors_agree(self):
        raw_cases = [
            '{"version":1,"version":1}', '{"x":NaN}', '{"x":Infinity}', "\xff", "[" * 2000,
            "x" * 65537, '{"a":1}trailing', '{"a"', '{"a":}', '{"a":01}', "'x'",
        ]
        context_path = Path(self.temp.name) / "context.json"
        context_path.write_text(json.dumps(CONTEXT))
        for index, raw in enumerate(raw_cases):
            with self.subTest(raw_index=index):
                path = Path(self.temp.name) / f"raw-{index}.json"
                path.write_text(raw)
                run = subprocess.run([str(self.binary), str(context_path), str(path)],
                                     capture_output=True, text=True, timeout=20)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertTrue(run.stdout.startswith("DECODE\t"), run.stdout)
                reason = run.stdout.split("\t")[1].strip()
                with self.assertRaises(ValueError):
                    plan.decode_capture(raw.encode())
                self.assertIn(reason, {"duplicate-field", "invalid-number", "invalid-capture-json"})

    def test_valid_json_wrong_shape_agrees(self):
        # These parse as JSON but fail the capture shape check on both sides.
        for raw in ("[]", "null", "42", '"text"'):
            with self.subTest(raw=raw):
                self.assert_agrees(json.loads(raw), label=f"shape-{raw}")

    def test_baseline_plan_matches_python_fields(self):
        value = capture()
        py_issues, py_fields = self.python_verdict(value)
        cpp_issues, cpp_fields = self.cpp_verdict(value)
        self.assertEqual(py_issues, cpp_issues)
        self.assertIsNotNone(py_fields)
        self.assertEqual(py_fields, cpp_fields)
        self.assertEqual(py_fields["routes"], ["10.30.0.0/16"])
        self.assertEqual(py_fields["addresses"], [("10.20.0.2", 30, "10.20.0.1")])


if __name__ == "__main__":
    unittest.main()
