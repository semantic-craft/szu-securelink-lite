"""Pure macOS network planning model. No executor, commands or OS mutation.

Capture is server intent, not authority. A valid plan still requires review.
Runtime leases/receipts must come from an executor verifying its owned utun fd,
not from capture JSON. This module does not implement that privileged executor.
"""
from dataclasses import dataclass, field
import ipaddress
import json
import re
import uuid

import vendor_dns_routes  # single DNS host-route authority, reused verbatim


@dataclass(frozen=True)
class Issue:
    code: str
    path: str


@dataclass(frozen=True, repr=False)
class Context:
    session_id: str
    duration_seconds: int
    remote_port: int
    verified_dns_suffixes: tuple[str, ...] = ()


@dataclass(frozen=True, repr=False)
class Plan:
    context: Context
    remote: str
    mtu: int
    addresses: tuple[tuple[str, int, str], ...]
    routes: tuple[str, ...]
    dns_servers: tuple[str, ...]
    dns_domains: tuple[str, ...]
    dns_domains_fallback: bool = False  # school sent unscoped; scoped to verified suffixes
    # Vendor DNS host-route candidates (vendor_dns_routes authority): the
    # dhcp-option DNS branch adds /32 tunnel routes so resolvers stay reachable
    # off-campus. Empty when there are no servers or a non-dhcp DNS source.
    dns_host_routes: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Validation:
    issues: tuple[Issue, ...]
    plan: Plan | None = field(default=None, repr=False)


def decode_capture(data: bytes):
    """Bounded JSON; reject duplicate names before dictionaries erase them."""
    if not isinstance(data, bytes) or len(data) > 65536:
        raise ValueError("capture-size")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate-field")
            result[key] = value
        return result

    def invalid_constant(_):
        raise ValueError("invalid-number")

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("invalid-capture-json") from None


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except ValueError:
        return False


def _domain(value):
    return (isinstance(value, str) and 1 <= len(value) <= 253
            and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                    for part in value.split(".")))


def _ip(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 45 or "%" in value:
        return None
    try:
        address = ipaddress.ip_address(value)
        if (address.is_unspecified or address.is_loopback or address.is_multicast
                or address.is_link_local or address.is_reserved
                or (address.version == 4 and address in ipaddress.ip_network("0.0.0.0/8"))):
            return None
        return address
    except ValueError:
        return None


def validate_capture(capture, context: Context) -> Validation:
    """Reject unsupported intent explicitly; never silently delete server policy.

    Initial slice: new L3 utun, literal addresses, unscoped campus-prefix routes,
    one supplemental resolver with verified suffixes. Public campus prefixes are
    permitted; default, half-default and combined global routes are not.
    """
    issues = []

    def issue(code, path):
        issues.append(Issue(code, path))

    def shape(value, keys, path):
        if not isinstance(value, dict) or set(value) != set(keys.split()):
            issue("unexpected-fields", path)
            return False
        return True

    def array(value, maximum, path):
        if not isinstance(value, list) or len(value) > maximum:
            issue("invalid-count", path)
            return []
        return value

    if not isinstance(context, Context):
        return Validation((Issue("invalid-context", "context"),))
    if not _uuid(context.session_id):
        issue("invalid-session", "context.sessionID")
    # Audited transaction lifetime: the unit-4 observation window needs up to
    # 15 minutes; official sessions run longer, so this is our own bound.
    if not _integer(context.duration_seconds, 1, 900):
        issue("invalid-duration", "context.durationSeconds")
    if not _integer(context.remote_port, 1, 65535):
        issue("invalid-port", "context.remotePort")
    suffixes = context.verified_dns_suffixes
    if (not isinstance(suffixes, tuple) or len(suffixes) > 32
            or any(not _domain(suffix) or "." not in suffix for suffix in suffixes)):
        issue("invalid-domain-authority", "context.verifiedDNSSuffixes")
        suffixes = ()
    suffixes = tuple(suffix.lower() for suffix in suffixes)
    keys = ("version ctrlOptionsCaptured ctrlOptionCount ctrlDuplicateKeys ctrlDuplicateDomains ctrlMappings domainOptionsCaptured domainOptions complete failure layer mtu remote addresses routes excludedRoutes "
            "routeMetricDefault redirect dns allowIPv4 allowIPv6 allowLocalDNS sessionNameDiscarded")
    if not shape(capture, keys, "capture"):
        return Validation(tuple(issues))
    if capture["ctrlOptionsCaptured"] is not True:
        issue("uncaptured-control-policy", "ctrlOptionsCaptured")
    if (not _integer(capture["ctrlOptionCount"], 0, 64) or not _integer(capture["ctrlDuplicateKeys"], 0, 8192)
            or not _integer(capture["ctrlDuplicateDomains"], 0, 64)):
        issue("invalid-control-summary", "ctrlOptionCount")
    mappings = array(capture["ctrlMappings"], 64, "ctrlMappings")
    if mappings or capture["ctrlOptionCount"] != 0 or capture["ctrlDuplicateKeys"] != 0 or capture["ctrlDuplicateDomains"] != 0:
        issue("unapplied-static-control-policy", "ctrlMappings")
    if capture["domainOptionsCaptured"] is not True:
        issue("uncaptured-domain-policy", "domainOptionsCaptured")
    domain_options = array(capture["domainOptions"], 64, "domainOptions")
    if domain_options:
        issue("unsupported-dynamic-domain-policy", "domainOptions")
    if type(capture["version"]) is not int or capture["version"] != 2:
        issue("unsupported-version", "version")
    if capture["complete"] is not True or capture["failure"] is not None:
        issue("incomplete-capture", "complete")
    if type(capture["layer"]) is not int or capture["layer"] != 3:
        issue("unsupported-layer", "layer")
    mtu_value = capture["mtu"]
    if mtu_value is None:
        mtu_value = 1400  # school omits mtu; upstream tun default applies
    if not _integer(mtu_value, 1280, 9000):
        issue("unsupported-mtu", "mtu")
    if type(capture["sessionNameDiscarded"]) is not bool:
        issue("invalid-flag", "sessionNameDiscarded")
    for key in ("allowIPv4", "allowIPv6", "allowLocalDNS"):
        if capture[key] is not None and capture[key] is not True:
            issue("unsupported-block-policy", key)
    if type(capture["routeMetricDefault"]) is not int or capture["routeMetricDefault"] != -1:
        issue("unsupported-route-metric", "routeMetricDefault")
    excluded = array(capture["excludedRoutes"], 64, "excludedRoutes")
    if excluded:
        issue("unsupported-excluded-routes", "excludedRoutes")
    redirect = capture["redirect"]
    if redirect is not None and shape(redirect, "ipv4 ipv6 flags", "redirect"):
        if (redirect["ipv4"] is not False or redirect["ipv6"] is not False
                or type(redirect["flags"]) is not int or redirect["flags"] not in (0, 256)):
            issue("unsupported-redirect", "redirect")
    remote = None
    if shape(capture["remote"], "address ipv6", "remote"):
        remote = _ip(capture["remote"]["address"])
        if remote is None or capture["remote"]["ipv6"] is not (remote.version == 6):
            issue("invalid-address", "remote")
    addresses = []
    for index, item in enumerate(array(capture["addresses"], 8, "addresses")):
        path = f"addresses[{index}]"
        if not shape(item, "address prefixLength gateway ipv6 net30", path):
            continue
        address = _ip(item["address"])
        peer = _ip(item["gateway"]) if item["gateway"] != "" else None
        if (address is None or item["ipv6"] is not (address.version == 6)
                or not _integer(item["prefixLength"], 1, address.max_prefixlen)
                or (item["gateway"] != "" and (peer is None or peer.version != address.version or peer == address))):
            issue("invalid-interface-address", path)
            continue
        if item["net30"] is not False:
            issue("unsupported-net30", path)
        assigned_network = ipaddress.ip_network((address, item["prefixLength"]), strict=False)
        if assigned_network.prefixlen <= 1:
            issue("global-interface-prefix", path)
        if (address == remote or peer == remote
                or (remote is not None and remote.version == address.version and remote in assigned_network)):
            issue("control-endpoint-overlap", path)
        entry = (str(address), item["prefixLength"], str(peer) if peer else "")
        if any(old[0] == entry[0] for old in addresses):
            issue("duplicate-address", path)
        addresses.append(entry)
    if not addresses:
        issue("missing-interface-address", "addresses")
    for family in (4, 6):
        selected = [entry for entry in addresses if ipaddress.ip_address(entry[0]).version == family]
        if len(selected) > 1:
            issue("unsupported-multiple-family-addresses", "addresses")
    networks = []
    for index, item in enumerate(array(capture["routes"], 64, "routes")):
        path = f"routes[{index}]"
        if not shape(item, "address prefixLength metric ipv6", path):
            continue
        try:
            if not isinstance(item["address"], str) or "%" in item["address"]:
                raise ValueError()
            address = ipaddress.ip_address(item["address"])
            if item["ipv6"] is not (address.version == 6) or not _integer(item["prefixLength"], 0, address.max_prefixlen):
                raise ValueError()
            network = ipaddress.ip_network((address, item["prefixLength"]), strict=True)
        except (ValueError, TypeError):
            issue("invalid-route", path)
            continue
        if network.prefixlen <= 1:
            issue("global-route", path)
        reserved = (["0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
                     # RFC 2544 benchmark range and local LAN must never be grabbed by the tunnel.
                     "198.18.0.0/15", "192.168.50.0/24"]
                    if network.version == 4 else ["::/128", "::1/128", "fe80::/10", "ff00::/8"])
        if any(network.overlaps(ipaddress.ip_network(net)) for net in reserved):
            issue("reserved-route", path)
        if remote is not None and remote.version == network.version and remote in network:
            issue("control-endpoint-overlap", path)
        if not any(ipaddress.ip_address(entry[0]).version == network.version for entry in addresses):
            issue("missing-address-family", path)
        if network.version == 4 and not any(ipaddress.ip_address(entry[0]).version == 4 and entry[2] for entry in addresses):
            issue("missing-route-gateway", path)
        if any(network == ipaddress.ip_network((entry[0], entry[1]), strict=False) for entry in addresses):
            issue("duplicate-interface-route", path)
        if type(item["metric"]) is not int or item["metric"] != -1:
            issue("unsupported-route-metric", path)
        if network in networks:
            issue("duplicate-route", path)
        networks.append(network)
    for family in (4, 6):
        if any(net.prefixlen <= 1 for net in ipaddress.collapse_addresses(n for n in networks if n.version == family)):
            issue("global-route-union", "routes")
    servers, domains = [], []
    dns_domains_fallback = False
    dns = capture["dns"]
    if dns is not None and shape(dns, "fromDhcp searchDomains servers", "dns"):
        if type(dns["fromDhcp"]) is not bool:
            issue("invalid-flag", "dns.fromDhcp")
        if array(dns["searchDomains"], 32, "dns.searchDomains"):
            issue("unsupported-search-domains", "dns.searchDomains")
        groups = array(dns["servers"], 8, "dns.servers")
        if len(groups) > 1:
            issue("unsupported-resolver-priorities", "dns.servers")
        for index, group in enumerate(groups):
            path = f"dns.servers[{index}]"
            if not shape(group, "priority addresses domains", path):
                continue
            if type(group["priority"]) is not int or group["priority"] != 0:
                issue("unsupported-resolver-priority", path)
            values = array(group["addresses"], 8, path + ".addresses")
            if not values:
                issue("missing-dns-server", path)
            for value in values:
                if not shape(value, "address port", path + ".addresses"):
                    continue
                address = _ip(value["address"])
                if address is None or type(value["port"]) is not int or value["port"] not in (0, 53):
                    issue("unsupported-dns-address", path)
                else:
                    servers.append(str(address))
            matches = array(group["domains"], 32, path + ".domains")
            if not matches and not suffixes:
                # Unscoped resolvers with no verified suffixes to scope to:
                # fail closed rather than hijack system-wide DNS.
                issue("global-dns", path)
            if not matches and suffixes:
                # School pushes unscoped resolvers (global-dns). Never apply
                # them globally: scope to the verified campus suffixes and
                # journal the explicit deviation in the plan instead.
                dns_domains_fallback = True
                matches = [s for s in suffixes]
            for domain in matches:
                if not _domain(domain):
                    issue("invalid-domain", path + ".domains")
                elif not any(domain.lower() == suffix or domain.lower().endswith("." + suffix) for suffix in suffixes):
                    issue("unverified-domain", path + ".domains")
                else:
                    domains.append(domain.lower())
        if len(set(servers)) != len(servers) or len(set(domains)) != len(domains):
            issue("duplicate-dns-record", "dns")
    if issues:
        return Validation(tuple(issues))
    # Vendor DNS host routes (dhcp-option branch only). The derivation runs on
    # re-serialized capture bytes: the validator has already pinned the exact
    # key set and value types, so the round trip is lossless. A conflicted
    # derivation fails the plan closed rather than applying an unreachable
    # resolver silently.
    dns_host_routes = ()
    if servers and capture["dns"] is not None and capture["dns"]["fromDhcp"] is True:
        raw = json.dumps(capture, sort_keys=True, separators=(",", ":")).encode()
        derivation = vendor_dns_routes.derive(raw)
        if derivation.issues:
            return Validation(tuple(Issue(code, "dns.hostRoutes") for code in derivation.issues))
        dns_host_routes = tuple((c.destination, c.gateway) for c in derivation.candidates)
    return Validation((), Plan(context, str(remote), mtu_value, tuple(addresses),
                               tuple(str(net) for net in networks), tuple(servers), tuple(domains),
                               dns_domains_fallback, dns_host_routes))


@dataclass(frozen=True, repr=False)
class InterfaceLease:
    session_id: str
    name: str
    index: int
    handle_identity: str


@dataclass(frozen=True, repr=False)
class Operation:
    kind: str
    key: str
    value: str


def _route_specs(plan: Plan) -> tuple[tuple[str, str | None, str], ...]:
    """Route intents as (network, gateway, origin). tunsetup.hpp: IPv4 uses
    the captured peer gateway without -ifscope; IPv6 uses -iface (a link
    gateway), also not RTF_IFSCOPE."""
    specs = []
    for address, prefix, _ in plan.addresses:
        network = ipaddress.ip_network((address, prefix), strict=False)
        specs.append((str(network), address if network.version == 4 else None, "interface-prefix"))
    for route in plan.routes:
        family = ipaddress.ip_network(route).version
        gateway = next((entry[2] for entry in plan.addresses if ipaddress.ip_address(entry[0]).version == 4), None) if family == 4 else None
        specs.append((route, gateway, "pushed-prefix"))
    return tuple(specs)


def _route_operation(owner: dict, route: str, gateway: str | None, origin: str) -> Operation:
    return Operation("interface-route", "route:" + route,
                     json.dumps({**owner, "network": route, "gateway": gateway, "scope": "unscoped",
                                 "gatewayKind": "ip" if gateway else "interface-link",
                                 "origin": origin, "metric": -1}, sort_keys=True, separators=(",", ":")))


def push_operations(plan: Plan, lease: InterfaceLease) -> tuple[Operation, ...]:
    """Route additions for a validated in-session push delta (unit 4). Only
    the pushed-prefix subset, origin ctrl-push; the delta capture's address
    fields exist to satisfy the validator and never produce an
    owned-interface or interface-prefix op here. Duplicate and conflict
    rejection against the live journal is the daemon's fail-closed duty."""
    if (lease.session_id != plan.context.session_id or not re.fullmatch(r"utun[0-9]{1,6}", lease.name)
            or not _integer(lease.index, 1, 2**31 - 1) or not _uuid(lease.handle_identity)):
        raise ValueError("invalid-interface-lease")
    owner = {"sessionID": lease.session_id, "interface": lease.name, "ifindex": lease.index,
             "handleIdentity": lease.handle_identity}
    return tuple(_route_operation(owner, route, gateway, "ctrl-push")
                 for route, gateway, origin in _route_specs(plan) if origin == "pushed-prefix")


def static_route_operations(plan: Plan, lease: InterfaceLease,
                            static_routes: tuple[str, ...]) -> tuple[Operation, ...]:
    """Vendor local static policy (unit 5): the stable school-internal route
    set the official client holds in its own configuration. Split tunnel by
    design — the default route stays with the system gateway. A static
    route already covered by the session plan is skipped exactly as the
    vendor merges its config with server pushes."""
    if (lease.session_id != plan.context.session_id or not re.fullmatch(r"utun[0-9]{1,6}", lease.name)
            or not _integer(lease.index, 1, 2**31 - 1) or not _uuid(lease.handle_identity)):
        raise ValueError("invalid-interface-lease")
    owner = {"sessionID": lease.session_id, "interface": lease.name, "ifindex": lease.index,
             "handleIdentity": lease.handle_identity}
    gateway = next((entry[2] for entry in plan.addresses
                    if ipaddress.ip_address(entry[0]).version == 4), None)
    result = []
    for route in static_routes:
        network = ipaddress.ip_network(route, strict=False)
        covered = any(ipaddress.ip_network((address, prefix), strict=False) == network
                      for address, prefix, _ in plan.addresses)
        covered = covered or any(ipaddress.ip_network(r, strict=False) == network for r in plan.routes)
        if covered:
            continue
        result.append(_route_operation(owner, str(network.network_address) + "/" + str(network.prefixlen),
                                       gateway, "vendor-static-route"))
    return tuple(result)


def operations(plan: Plan, lease: InterfaceLease) -> tuple[Operation, ...]:
    """Bind only to a newly created, fd-owned interface identified by the executor."""
    if (lease.session_id != plan.context.session_id or not re.fullmatch(r"utun[0-9]{1,6}", lease.name)
            or not _integer(lease.index, 1, 2**31 - 1) or not _uuid(lease.handle_identity)):
        raise ValueError("invalid-interface-lease")

    def operation(kind, key, value):
        return Operation(kind, key, json.dumps(value, sort_keys=True, separators=(",", ":")))
    owner = {"sessionID": lease.session_id, "interface": lease.name, "ifindex": lease.index,
             "handleIdentity": lease.handle_identity}
    result = [operation("owned-interface", "interface:" + lease.name,
                        {**owner, "mtu": plan.mtu, "addresses": plan.addresses})]
    for route, gateway, origin in _route_specs(plan):
        result.append(_route_operation(owner, route, gateway, origin))
    # Vendor mirror: /32 tunnel routes keep the captured resolvers reachable.
    for destination, gateway in plan.dns_host_routes:
        result.append(_route_operation(owner, destination, gateway, "vendor-dns-host-route"))
    if plan.dns_servers:
        key = "State:/Network/Service/szu-securelink-" + lease.session_id + "/DNS"
        result.append(operation("supplemental-resolver", key, {**owner, "ServerAddresses": plan.dns_servers,
                                "SupplementalMatchDomains": plan.dns_domains, "SupplementalMatchDomainsNoSearch": 1}))
    return tuple(result)


class Journal:
    """Successful-create receipts only; never infer ownership from a resource name.

    The executor must compare-and-delete against these full records at execution
    time. A snapshot comparison alone is not an atomic OS operation. Exact
    delete/recreate by another actor cannot be detected without executor evidence.
    """
    def __init__(self, plan: Plan, lease: InterfaceLease):
        self.lease = lease
        self.expected = operations(plan, lease)
        self._created = set()

    def record(self, index: int, *, outcome: str, before: Operation | None, after: Operation | None):
        if not _integer(index, 0, len(self.expected) - 1):
            raise ValueError("invalid-operation-index")
        if index in self._created:
            raise ValueError("duplicate-success-receipt")
        if outcome not in ("created", "failed", "preexisting"):
            raise ValueError("invalid-operation-outcome")
        if outcome == "created":
            if before is not None or after != self.expected[index]:
                raise ValueError("unproven-operation-ownership")
            if index != 0 and 0 not in self._created:
                raise ValueError("interface-not-owned")
            self._created.add(index)

    def cleanup(self, current: dict[str, Operation], current_lease: InterfaceLease | None):
        if current_lease != self.lease:
            return (), (Issue("interface-ownership-lost", "cleanup"),)
        removals, issues = [], []
        # Closing utun can remove dependent routes implicitly. Keep the interface
        # if an unowned expected record exists; it must not be collateral cleanup.
        drift = any(index not in self._created and item.key in current
                    for index, item in enumerate(self.expected) if index != 0)
        if drift:
            issues.append(Issue("unowned-dependent-record", "cleanup"))
        owned = {self.expected[index] for index in self._created}
        for actual in current.values():
            if actual in owned:
                continue
            try:
                value = json.loads(actual.value)
            except (ValueError, TypeError):
                continue
            if isinstance(value, dict) and value.get("interface") == self.lease.name and value.get("ifindex") == self.lease.index:
                drift = True
                issues.append(Issue("unowned-dependent-record", "cleanup"))
                break
        for index in sorted(self._created, reverse=True):
            expected = self.expected[index]
            actual = current.get(expected.key)
            if actual is None:
                continue
            if actual != expected:
                drift = True
                issues.append(Issue("record-drift", f"operations[{index}]"))
            elif index == 0 and drift:
                issues.append(Issue("interface-retained-for-drift", "operations[0]"))
            else:
                removals.append(expected)
        return tuple(removals), tuple(issues)
