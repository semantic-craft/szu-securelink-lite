import copy
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import sys
import unittest


spec = importlib.util.spec_from_file_location("network_plan", Path(__file__).resolve().parents[1] / "scripts/network_plan.py")
plan = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plan
spec.loader.exec_module(plan)

SESSION = "f50ed258-6ef7-4f2c-9b63-c0838c89c9fa"
HANDLE = "b5c9d692-528e-44d3-966c-9f3772fbc3a9"
CONTEXT = plan.Context(SESSION, 120, 443, ("campus.example",))


def capture():
    return {
        "version": 2, "ctrlOptionsCaptured": True, "ctrlOptionCount": 0, "ctrlDuplicateKeys": 0, "ctrlDuplicateDomains": 0, "ctrlMappings": [], "domainOptionsCaptured": True, "domainOptions": [], "complete": True, "failure": None, "layer": 3, "mtu": 1400,
        "remote": {"address": "198.51.100.4", "ipv6": False},
        "addresses": [{"address": "10.20.0.2", "prefixLength": 30, "gateway": "10.20.0.1", "ipv6": False, "net30": False}],
        "routes": [{"address": "10.30.0.0", "prefixLength": 16, "metric": -1, "ipv6": False}],
        "excludedRoutes": [], "routeMetricDefault": -1, "redirect": None,
        "dns": {"fromDhcp": True, "searchDomains": [], "servers": [
            {"priority": 0, "addresses": [{"address": "10.30.0.53", "port": 0}],
             "domains": ["campus.example", "finance.campus.example"]}]},
        "allowIPv4": True, "allowIPv6": None, "allowLocalDNS": True,
        "sessionNameDiscarded": True,
    }


class ValidationTests(unittest.TestCase):
    def reject(self, value, code=None, context=CONTEXT):
        result = plan.validate_capture(value, context)
        self.assertIsNone(result.plan)
        self.assertTrue(result.issues)
        if code:
            self.assertIn(code, [issue.code for issue in result.issues])
        return result

    def test_static_control_intent_requires_an_execution_consumer(self):
        value = capture()
        value["ctrlOptionCount"] = 1
        value["ctrlMappings"] = [{"domain": "portal.campus.example", "addresses": ["10.30.0.5"], "addressPolicy": "any"}]
        self.reject(value, "unapplied-static-control-policy")
        value = capture()
        value["ctrlOptionsCaptured"] = False
        self.reject(value, "uncaptured-control-policy")
        value = capture()
        value["version"] = 1
        self.reject(value, "unsupported-version")

    def test_domain_policy_cannot_be_silently_dropped(self):
        value = capture()
        value["domainOptionsCaptured"] = False
        self.reject(value, "uncaptured-domain-policy")
        value["domainOptionsCaptured"] = True
        value["domainOptions"] = [".campus.example"]
        self.reject(value, "unsupported-dynamic-domain-policy")

    def test_bounded_capture_and_private_public_prefixes(self):
        value = capture()
        before = copy.deepcopy(value)
        result = plan.validate_capture(plan.decode_capture(json.dumps(value).encode()), CONTEXT)
        self.assertFalse(result.issues)
        self.assertEqual(result.plan.routes, ("10.30.0.0/16",))
        self.assertEqual(value, before)
        value["routes"][0]["address"] = "203.0.113.0"
        value["routes"][0]["prefixLength"] = 24
        self.assertIsNotNone(plan.validate_capture(value, CONTEXT).plan)

    def test_strict_json_rejects_duplicates_invalid_numbers_and_size(self):
        for data in [b'{"version":1,"version":1}', b'{"x":NaN}', b"\xff", b"[" * 2000, b"x" * 65537]:
            with self.subTest(data_length=len(data)):
                with self.assertRaises(ValueError):
                    plan.decode_capture(data)

    def test_unknown_fields_commands_and_secret_names_do_not_escape(self):
        value = capture()
        value["SECRET-UNKNOWN"] = "sudo route delete default"
        result = self.reject(value, "unexpected-fields")
        self.assertNotIn("SECRET", repr(result))
        self.assertNotIn("sudo", repr(result))
        for key in ["proxy", "commands", "sessionName", "privateKey"]:
            value = capture()
            value[key] = "SECRET"
            self.reject(value, "unexpected-fields")

    def test_global_routing_is_rejected_including_union_and_interface_side_effect(self):
        for network, length in [("0.0.0.0", 0), ("128.0.0.0", 1)]:
            value = capture()
            value["routes"][0].update(address=network, prefixLength=length)
            self.reject(value, "global-route")
        value = capture()
        value["routes"] = [{"address": address, "prefixLength": 2, "metric": -1, "ipv6": False}
                           for address in ["0.0.0.0", "64.0.0.0", "128.0.0.0", "192.0.0.0"]]
        self.reject(value, "global-route-union")
        value = capture()
        value["addresses"][0]["prefixLength"] = 1
        self.reject(value, "global-interface-prefix")
        value = capture()
        value["redirect"] = {"ipv4": False, "ipv6": False, "flags": 1}
        self.reject(value, "unsupported-redirect")

    def test_control_channel_and_family_mismatches(self):
        value = capture()
        value["routes"][0].update(address="198.51.100.0", prefixLength=24)
        self.reject(value, "control-endpoint-overlap")
        value = capture()
        value["addresses"][0].update(address="198.51.100.2", prefixLength=24, gateway="")
        self.reject(value, "control-endpoint-overlap")
        value = capture()
        value["routes"][0].update(address="2001:db8:2::", prefixLength=48, ipv6=True)
        self.reject(value, "missing-address-family")
        value["addresses"].append({"address": "2001:db8:1::2", "prefixLength": 64, "gateway": "", "ipv6": True, "net30": False})
        self.assertIsNotNone(plan.validate_capture(value, CONTEXT).plan)

    def test_disabled_redirect_accepts_only_known_inert_default(self):
        for flags in (0, 256):
            value = capture()
            value["redirect"] = {"ipv4": False, "ipv6": False, "flags": flags}
            self.assertIsNotNone(plan.validate_capture(value, CONTEXT).plan)
        for flags in (True, 4, 257, 512, 65536, -1):
            value = capture()
            value["redirect"] = {"ipv4": False, "ipv6": False, "flags": flags}
            self.reject(value, "unsupported-redirect")
        # mtu absent/None is the school's real behavior: upstream default applies.
        value = capture()
        value["mtu"] = None
        accepted = plan.validate_capture(value, CONTEXT)
        self.assertIsNotNone(accepted.plan)
        self.assertEqual(accepted.plan.mtu, 1400)

    def test_strict_address_prefix_mtu_and_count(self):
        for address in ["10.0.0.1\nup evil", "example.test", "::1", "fe80::1%utun1", "0.0.0.0", "224.0.0.1", "255.255.255.255"]:
            value = capture()
            value["addresses"][0]["address"] = address
            self.reject(value, "invalid-interface-address")
        for mtu in [True, 1279, 9001, "1400"]:
            value = capture()
            value["mtu"] = mtu
            self.reject(value, "unsupported-mtu")
        for prefix in [True, -1, 33, "24"]:
            value = capture()
            value["routes"][0]["prefixLength"] = prefix
            self.reject(value, "invalid-route")
        value = capture()
        value["routes"][0]["address"] = "10.30.0.1"
        self.reject(value, "invalid-route")
        value = capture()
        value["routes"] *= 65
        self.reject(value, "invalid-count")

    def test_unsupported_policy_is_not_silently_omitted(self):
        for key, update, code in [
            ("allowIPv4", False, "unsupported-block-policy"),
            ("allowIPv6", False, "unsupported-block-policy"),
            ("allowLocalDNS", False, "unsupported-block-policy"),
            ("routeMetricDefault", 1, "unsupported-route-metric"),
            ("excludedRoutes", [capture()["routes"][0]], "unsupported-excluded-routes"),
            ("redirect", {"ipv4": True, "ipv6": False, "flags": 0}, "unsupported-redirect"),
            ("failure", "SECRET-FROM-REMOTE", "incomplete-capture"),
        ]:
            value = capture()
            value[key] = update
            self.reject(value, code)
        value = capture()
        value["addresses"][0]["net30"] = True
        self.reject(value, "unsupported-net30")

    def test_dns_must_be_scoped_verified_and_never_primary_search(self):
        for domains, code in [(["."], "invalid-domain"),
                              (["evilcampus.example"], "unverified-domain"), (["example"], "unverified-domain"),
                              (["campus.example\nSECRET"], "invalid-domain")]:
            value = capture()
            value["dns"]["servers"][0]["domains"] = domains
            self.reject(value, code)
        # Empty domains with verified suffixes is the school's real behavior:
        # scoped to the verified suffixes (journaled deviation), not global.
        value = capture()
        value["dns"]["servers"][0]["domains"] = []
        accepted = plan.validate_capture(value, CONTEXT)
        self.assertIsNotNone(accepted.plan)
        self.assertEqual(accepted.plan.dns_domains, ("campus.example",))
        # Empty domains with NO verified suffixes still fails closed.
        no_suffix = replace(CONTEXT, verified_dns_suffixes=())
        value = capture()
        value["dns"]["servers"][0]["domains"] = []
        self.reject(value, "global-dns", no_suffix)
        value = capture()
        value["dns"]["searchDomains"] = ["campus.example"]
        self.reject(value, "unsupported-search-domains")
        value = capture()
        value["dns"]["servers"][0]["addresses"][0]["port"] = 853
        self.reject(value, "unsupported-dns-address")
        value = capture()
        value["dns"]["servers"][0]["priority"] = -1
        self.reject(value, "unsupported-resolver-priority")
        value = capture()
        value["dns"]["servers"] *= 2
        self.reject(value, "unsupported-resolver-priorities")

    def test_context_cannot_be_supplied_by_server_or_use_unbounded_lifetime(self):
        for context in [replace(CONTEXT, session_id="bad"), replace(CONTEXT, duration_seconds=901),
                        replace(CONTEXT, duration_seconds=True),
                        replace(CONTEXT, remote_port=0),
                        replace(CONTEXT, verified_dns_suffixes=("example",))]:
            self.reject(capture(), context=context)


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.plan = plan.validate_capture(capture(), CONTEXT).plan
        self.lease = plan.InterfaceLease(SESSION, "utun123", 321, HANDLE)
        self.journal = plan.Journal(self.plan, self.lease)
        self.expected = self.journal.expected

    def created(self, index):
        self.journal.record(index, outcome="created", before=None, after=self.expected[index])

    def test_fixed_typed_operations_no_shell_and_unique_resolver(self):
        self.assertEqual([operation.kind for operation in self.expected],
                         ["owned-interface", "interface-route", "interface-route",
                          "interface-route", "supplemental-resolver"])
        route = json.loads(self.expected[2].value)
        self.assertEqual(route["scope"], "unscoped")
        self.assertEqual(route["gateway"], "10.20.0.1")
        self.assertNotIn("interfaceScoped", route)
        self.assertEqual(json.loads(self.expected[1].value)["network"], "10.20.0.0/30")
        # Vendor DNS host route: the captured resolver rides the tunnel peer.
        host_route = json.loads(self.expected[3].value)
        self.assertEqual(host_route["network"], "10.30.0.53/32")
        self.assertEqual(host_route["gateway"], "10.20.0.1")
        self.assertEqual(host_route["origin"], "vendor-dns-host-route")
        resolver = self.expected[-1]
        self.assertEqual(resolver.key, f"State:/Network/Service/szu-securelink-{SESSION}/DNS")
        data = json.loads(resolver.value)
        self.assertNotIn("SearchDomains", data)
        self.assertEqual(data["SupplementalMatchDomainsNoSearch"], 1)
        with self.assertRaises(ValueError):
            plan.operations(self.plan, replace(self.lease, name="en0"))
        with self.assertRaises(ValueError):
            plan.operations(self.plan, replace(self.lease, session_id=HANDLE))

    def test_reverse_cleanup_only_successfully_created_matching_records(self):
        for index in range(len(self.expected)):
            self.created(index)
        current = {item.key: item for item in self.expected}
        current["unrelated:local"] = plan.Operation("route", "unrelated:local", "untouched")
        actions, issues = self.journal.cleanup(current, self.lease)
        self.assertFalse(issues)
        self.assertEqual(actions, tuple(reversed(self.expected)))
        self.assertIn("unrelated:local", current)
        self.assertEqual(self.journal.cleanup({}, self.lease), ((), ()))

    def test_failed_or_preexisting_add_never_grants_ownership(self):
        self.created(0)
        self.journal.record(1, outcome="failed", before=None, after=None)
        self.journal.record(2, outcome="preexisting", before=self.expected[2], after=self.expected[2])
        actions, issues = self.journal.cleanup({item.key: item for item in self.expected}, self.lease)
        self.assertFalse(actions)
        self.assertIn("unowned-dependent-record", [issue.code for issue in issues])
        with self.assertRaises(ValueError):
            self.journal.record(1, outcome="created", before=self.expected[1], after=self.expected[1])

    def test_route_or_dns_drift_retains_foreign_changes_and_interface(self):
        for index in range(len(self.expected)):
            self.created(index)
        for index in [1, 3]:
            current = {item.key: item for item in self.expected}
            current[self.expected[index].key] = replace(self.expected[index], value="changed-by-another-owner")
            actions, issues = self.journal.cleanup(current, self.lease)
            self.assertNotIn(self.expected[index], actions)
            self.assertNotIn(self.expected[0], actions)
            self.assertIn("record-drift", [issue.code for issue in issues])
            self.assertIn("interface-retained-for-drift", [issue.code for issue in issues])

    def test_lease_replacement_and_success_spoof_are_rejected(self):
        with self.assertRaises(ValueError):
            self.created(1)
        self.created(0)
        with self.assertRaises(ValueError):
            self.created(0)
        with self.assertRaises(ValueError):
            self.journal.record(1, outcome="created", before=None, after=replace(self.expected[1], value="spoof"))
        actions, issues = self.journal.cleanup({item.key: item for item in self.expected},
                                             replace(self.lease, handle_identity=SESSION))
        self.assertFalse(actions)
        self.assertEqual(issues[0].code, "interface-ownership-lost")


if __name__ == "__main__":
    unittest.main()
