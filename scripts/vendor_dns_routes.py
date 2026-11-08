"""Pure IPv4 DNS host-route candidates; never execution or DNS authority.

Vendor evidence: dns-route-contract.md items 1–3. Exact duplicate elimination,
conflict rejection and special-address rejection are independent safety policy.
The full operation planner must still validate all captured intent and ownership.
"""
from dataclasses import dataclass, field
import ipaddress
import json


@dataclass(frozen=True, repr=False)
class Candidate:
    destination: str
    gateway: str


@dataclass(frozen=True)
class Derivation:
    issues: tuple[str, ...]
    candidates: tuple[Candidate, ...] = field(default=(), repr=False)
    deduplicated: int = 0
    execution_authorized: bool = False


def _decode(raw):
    if type(raw) is not bytes or len(raw) > 65536:
        raise ValueError()
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError()
            result[k] = v
        return result
    def invalid(_):
        raise ValueError()
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def derive(raw: bytes) -> Derivation:
    """Accept bounded capture JSON bytes; all diagnostics are fixed, data-free.

    Returned candidates only supply DNS reachability /32s via the one captured
    IPv4 VPN gateway. No resolver/global DNS/default route is authorized here.
    Any failure returns no partial candidates. No files or network are accessed.
    """
    issues = []
    def reject(code):
        if code not in issues:
            issues.append(code)
    def shape(value, keys):
        if type(value) is not dict or set(value) != set(keys.split()):
            raise ValueError()
    def integer(value, low, high):
        return type(value) is int and low <= value <= high
    def array(value, maximum):
        if type(value) is not list or len(value) > maximum:
            raise ValueError()
        return value
    def strings(value):
        for item in array(value, 64):
            if type(item) is not str or len(item.encode('utf-8')) > 256 or any(ord(c)<32 or ord(c)==127 for c in item):
                raise ValueError()
    def ip(value):
        if type(value) is not str or not 1 <= len(value) <= 45 or '%' in value:
            raise ValueError()
        parsed = ipaddress.ip_address(value)
        if (parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast
            or parsed.is_link_local or parsed.is_reserved
            or (parsed.version == 4 and parsed in ipaddress.ip_network('0.0.0.0/8'))):
            raise ValueError()
        return parsed
    try:
        c = _decode(raw)
        shape(c, 'version ctrlOptionsCaptured ctrlOptionCount ctrlDuplicateKeys ctrlDuplicateDomains ctrlMappings domainOptionsCaptured domainOptions complete failure layer mtu remote addresses routes excludedRoutes routeMetricDefault redirect dns allowIPv4 allowIPv6 allowLocalDNS sessionNameDiscarded')
        if type(c['version']) is not int or c['version'] != 2:
            reject('unsupported-capture-version')
        if c['complete'] is not True or c['failure'] is not None:
            reject('incomplete-capture')
        if type(c['layer']) is not int or c['layer'] != 3:
            reject('unsupported-layer')
        for key in ('domainOptionsCaptured','sessionNameDiscarded'):
            if type(c[key]) is not bool:
                raise ValueError()
        if c['ctrlOptionsCaptured'] is not True:
            reject('uncaptured-control-policy')
        if not integer(c['ctrlOptionCount'],0,64) or not integer(c['ctrlDuplicateKeys'],0,8192) or not integer(c['ctrlDuplicateDomains'],0,64):
            raise ValueError()
        if array(c['ctrlMappings'],64) or c['ctrlOptionCount'] or c['ctrlDuplicateKeys'] or c['ctrlDuplicateDomains']:
            reject('unapplied-static-control-policy')
        strings(c['domainOptions'])
        for key in ('allowIPv4','allowIPv6','allowLocalDNS'):
            if c[key] is not None and type(c[key]) is not bool:
                raise ValueError()
        if c['allowIPv4'] is False:
            reject('ipv4-policy-disabled')
        if c['mtu'] is not None and not integer(c['mtu'], 1, 65535):
            raise ValueError()
        if not integer(c['routeMetricDefault'], -1, 65535):
            raise ValueError()
        if c['redirect'] is not None:
            shape(c['redirect'], 'ipv4 ipv6 flags')
            if any(type(c['redirect'][k]) is not bool for k in ('ipv4','ipv6')) or not integer(c['redirect']['flags'],0,0xffffffff):
                raise ValueError()
        shape(c['remote'], 'address ipv6')
        remote = ip(c['remote']['address'])
        if c['remote']['ipv6'] is not (remote.version == 6):
            raise ValueError()
        gateways, local = set(), set()
        for item in array(c['addresses'],8):
            shape(item, 'address prefixLength gateway ipv6 net30')
            address = ip(item['address'])
            if item['ipv6'] is not (address.version==6) or type(item['net30']) is not bool or not integer(item['prefixLength'],1,address.max_prefixlen):
                raise ValueError()
            local.add(address)
            if type(item['gateway']) is not str:
                raise ValueError()
            if item['gateway']:
                gateway = ip(item['gateway'])
                if gateway.version != address.version or gateway == address:
                    raise ValueError()
                if address.version == 4:
                    gateways.add(gateway)
            if address.version == 4 and item['net30']:
                reject('unsupported-net30-gateway')
        routes, exclusions = [], []
        for key, destination in [('routes', routes), ('excludedRoutes', exclusions)]:
            for item in array(c[key],64):
                shape(item, 'address prefixLength metric ipv6')
                if type(item['address']) is not str or '%' in item['address']:
                    raise ValueError()
                address = ipaddress.ip_address(item['address'])
                if item['ipv6'] is not (address.version==6) or not integer(item['prefixLength'],0,address.max_prefixlen) or not integer(item['metric'],-1,65535):
                    raise ValueError()
                destination.append((ipaddress.ip_network((address,item['prefixLength']),strict=True),item['metric']))
        shape(c['dns'],'fromDhcp searchDomains servers')
        if type(c['dns']['fromDhcp']) is not bool:
            raise ValueError()
        strings(c['dns']['searchDomains'])
        dns = []
        for server in array(c['dns']['servers'],16):
            shape(server,'priority addresses domains')
            if not integer(server['priority'],-32768,32767):
                raise ValueError()
            strings(server['domains'])
            for entry in array(server['addresses'],8):
                shape(entry,'address port')
                if not integer(entry['port'],0,65535):
                    raise ValueError()
                address = ip(entry['address'])
                if address.version != 4:
                    reject('unsupported-ipv6-dns-route')
                if entry['port'] not in (0,53):
                    reject('unsupported-dns-port')
                dns.append(address)
        # Evidence is the dhcp-option DNS builder branch, not all new DNS modes.
        if dns and c['dns']['fromDhcp'] is not True:
            reject('unsupported-dns-source')
        if dns and len(gateways) != 1:
            reject('missing-or-ambiguous-ipv4-vpn-gateway')
        if issues:
            return Derivation(tuple(issues))
        if not dns:
            return Derivation(())
        gateway = next(iter(gateways))
        if gateway == remote:
            reject('gateway-control-endpoint-conflict')
        candidates, seen, duplicates = [], set(), 0
        for address in dns:
            if address in local or address in (gateway,remote):
                reject('dns-endpoint-conflict')
            if any(address in network for network,_ in exclusions if network.version==4):
                reject('dns-excluded-route-conflict')
            exact = [(network,metric) for network,metric in routes if network.version==4 and network.prefixlen==32 and address in network]
            if exact and (c['routeMetricDefault'] != -1 or any(metric != -1 for _,metric in exact)):
                reject('dns-route-metric-conflict')
            if address in seen or exact:
                duplicates += 1
            else:
                candidates.append(Candidate(str(address)+'/32', str(gateway)))
            seen.add(address)
        return Derivation(tuple(issues), () if issues else tuple(candidates), duplicates)
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        return Derivation(('invalid-capture',))
