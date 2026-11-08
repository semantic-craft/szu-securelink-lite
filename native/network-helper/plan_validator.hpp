#pragma once
// C++ mirror of scripts/network_plan.py validate_capture. Issue codes, paths
// and accept/reject decisions must agree exactly; the differential test in
// tests/test_plan_validator.py is the authority and fails on any drift.
// This module is pure: no executor, no commands, no OS mutation.
#include <algorithm>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include "ip_math.hpp"
#include "plan_input.hpp"

namespace plan_validator {

struct Context {
    std::string session_id;
    long long duration_seconds = 0;
    long long remote_port = 0;
    std::vector<std::string> verified_dns_suffixes;
    // Vendor local static policy (unit 5): canonical IPv4 CIDRs, staged
    // root-side like the rest of the trusted bootstrap. Canonical IPv4 only,
    // bounded by the reader; the default route never appears here.
    std::vector<std::string> static_routes;
};

struct Issue {
    std::string code;
    std::string path;

    bool operator<(const Issue &other) const {
        return std::tie(code, path) < std::tie(other.code, other.path);
    }
    bool operator==(const Issue &other) const { return code == other.code && path == other.path; }
};

struct Plan {
    std::string session_id;  // from context, binds leases and resolver keys
    std::string remote;
    long long mtu = 0;
    std::vector<std::tuple<std::string, long long, std::string>> addresses;  // addr, prefix, peer
    std::vector<std::string> routes;                                         // canonical networks
    std::vector<std::string> dns_servers;
    std::vector<std::string> dns_domains;
    // vendor-dns-host-route candidates (destination/32, gateway), mirrored
    // from scripts/vendor_dns_routes.derive; empty without dhcp-option DNS.
    std::vector<std::pair<std::string, std::string>> dns_host_routes;
};

struct Validation {
    std::vector<Issue> issues;
    bool has_plan = false;
    Plan plan;
};

inline bool is_integer_in(const plan_input::Value &value, long long low, long long high) {
    return value.is_int() && value.integer >= low && value.integer <= high;
}

inline bool valid_uuid(const std::string &value) {
    // Canonical lowercase 8-4-4-4-12 hex: str(uuid.UUID(v)) == v round trip.
    if (value.size() != 36) return false;
    for (size_t i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') return false;
            continue;
        }
        const char c = value[i];
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hex) return false;
    }
    return true;
}

inline bool valid_domain(const std::string &value) {
    if (value.empty() || value.size() > 253) return false;
    size_t start = 0;
    while (true) {
        const size_t at = value.find('.', start);
        const std::string part = value.substr(start, at == std::string::npos ? std::string::npos : at - start);
        if (part.empty() || part.size() > 63) return false;
        const char first = part.front();
        const char last = part.back();
        auto alnum = [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
        };
        if (!alnum(first) || !alnum(last)) return false;
        for (char c : part) {
            if (!alnum(c) && c != '-') return false;
        }
        if (at == std::string::npos) break;
        start = at + 1;
    }
    return true;
}

inline std::string lower(const std::string &value) {
    std::string out = value;
    for (char &c : out) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return out;
}

inline Validation validate_capture(const plan_input::Value &capture, const Context &context) {
    Validation out;
    auto issue = [&](const std::string &code, const std::string &path) {
        out.issues.push_back({code, path});
    };
    auto shape = [&](const plan_input::Value *value, const std::string &keys, const std::string &path) {
        if (value == nullptr || !value->is_object()) {
            issue("unexpected-fields", path);
            return false;
        }
        std::vector<std::string> expected;
        size_t start = 0;
        while (true) {
            const size_t at = keys.find(' ', start);
            expected.push_back(keys.substr(start, at == std::string::npos ? std::string::npos : at - start));
            if (at == std::string::npos) break;
            start = at + 1;
        }
        if (value->members.size() != expected.size()) {
            issue("unexpected-fields", path);
            return false;
        }
        for (const std::string &key : expected) {
            if (value->find(key) == nullptr) {
                issue("unexpected-fields", path);
                return false;
            }
        }
        return true;
    };
    auto as_array = [&](const plan_input::Value *value, size_t maximum, const std::string &path) {
        if (value == nullptr || !value->is_array() || value->items.size() > maximum) {
            issue("invalid-count", path);
            return static_cast<const std::vector<plan_input::Value> *>(nullptr);
        }
        return &value->items;
    };
    if (!valid_uuid(context.session_id)) issue("invalid-session", "context.sessionID");
    // Audited transaction lifetime: the unit-4 observation window needs up to
    // 15 minutes; official sessions run longer, so this is our own bound.
    if (context.duration_seconds < 1 || context.duration_seconds > 900) {
        issue("invalid-duration", "context.durationSeconds");
    }
    if (context.remote_port < 1 || context.remote_port > 65535) issue("invalid-port", "context.remotePort");
    std::vector<std::string> suffixes;
    bool suffixes_ok = context.verified_dns_suffixes.size() <= 32;
    for (const std::string &suffix : context.verified_dns_suffixes) {
        if (!valid_domain(suffix) || suffix.find('.') == std::string::npos) suffixes_ok = false;
    }
    if (!suffixes_ok) issue("invalid-domain-authority", "context.verifiedDNSSuffixes");
    if (suffixes_ok) {
        // Python resets the tuple to () on any bad suffix; keep that exactly.
        for (const std::string &suffix : context.verified_dns_suffixes) suffixes.push_back(lower(suffix));
    }

    const std::string keys = "version ctrlOptionsCaptured ctrlOptionCount ctrlDuplicateKeys "
                             "ctrlDuplicateDomains ctrlMappings domainOptionsCaptured domainOptions "
                             "complete failure layer mtu remote addresses routes excludedRoutes "
                             "routeMetricDefault redirect dns allowIPv4 allowIPv6 allowLocalDNS "
                             "sessionNameDiscarded";
    if (!shape(&capture, keys, "capture")) return out;

    const plan_input::Value *field = nullptr;
    auto at = [&](const std::string &key) { return capture.find(key); };

    field = at("ctrlOptionsCaptured");
    if (field == nullptr || !field->is_bool() || !field->boolean) issue("uncaptured-control-policy", "ctrlOptionsCaptured");
    field = at("ctrlOptionCount");
    if (field == nullptr || !is_integer_in(*field, 0, 64)) issue("invalid-control-summary", "ctrlOptionCount");
    field = at("ctrlDuplicateKeys");
    if (field == nullptr || !is_integer_in(*field, 0, 8192)) issue("invalid-control-summary", "ctrlDuplicateKeys");
    field = at("ctrlDuplicateDomains");
    if (field == nullptr || !is_integer_in(*field, 0, 64)) issue("invalid-control-summary", "ctrlDuplicateDomains");

    const auto mappings = as_array(at("ctrlMappings"), 64, "ctrlMappings");
    // Python compares `capture[...] != 0`, which is true for every non-integer
    // value too; mirror that, never silently treat malformed input as zero.
    auto non_zero = [&](const std::string &key) {
        const plan_input::Value *value = at(key);
        return value != nullptr && !(value->is_int() && value->integer == 0);
    };
    const bool any_ctrl = (mappings != nullptr && !mappings->empty()) ||
                          non_zero("ctrlOptionCount") || non_zero("ctrlDuplicateKeys") ||
                          non_zero("ctrlDuplicateDomains");
    if (any_ctrl) issue("unapplied-static-control-policy", "ctrlMappings");

    field = at("domainOptionsCaptured");
    if (field == nullptr || !field->is_bool() || !field->boolean) issue("uncaptured-domain-policy", "domainOptionsCaptured");
    const auto domain_options = as_array(at("domainOptions"), 64, "domainOptions");
    if (domain_options != nullptr && !domain_options->empty()) issue("unsupported-dynamic-domain-policy", "domainOptions");

    field = at("version");
    if (field == nullptr || !field->is_int() || field->integer != 2) issue("unsupported-version", "version");
    const bool complete_ok = at("complete") != nullptr && at("complete")->is_bool() &&
                             at("complete")->boolean && at("failure") != nullptr &&
                             at("failure")->type == plan_input::Type::null;
    if (!complete_ok) issue("incomplete-capture", "complete");
    field = at("layer");
    if (field == nullptr || !field->is_int() || field->integer != 3) issue("unsupported-layer", "layer");
    field = at("mtu");
    long long mtu_value = 1400;  // school omits mtu; upstream tun default applies
    if (field != nullptr && field->is_int()) mtu_value = field->integer;
    if (field != nullptr && !(field->is_int() || field->type == plan_input::Type::null)) {
        mtu_value = 0;  // non-int non-null: fails the range check below
    }
    if (!(mtu_value >= 1280 && mtu_value <= 9000)) issue("unsupported-mtu", "mtu");
    field = at("sessionNameDiscarded");
    if (field == nullptr || !field->is_bool()) issue("invalid-flag", "sessionNameDiscarded");
    for (const std::string &key : {"allowIPv4", "allowIPv6", "allowLocalDNS"}) {
        field = at(key);
        if (field != nullptr && field->type != plan_input::Type::null &&
            !(field->is_bool() && field->boolean)) {
            issue("unsupported-block-policy", key);
        }
    }
    field = at("routeMetricDefault");
    if (field == nullptr || !field->is_int() || field->integer != -1) issue("unsupported-route-metric", "routeMetricDefault");

    const auto excluded = as_array(at("excludedRoutes"), 64, "excludedRoutes");
    if (excluded != nullptr && !excluded->empty()) issue("unsupported-excluded-routes", "excludedRoutes");

    field = at("redirect");
    if (field != nullptr && field->type != plan_input::Type::null &&
        shape(field, "ipv4 ipv6 flags", "redirect")) {
        const plan_input::Value *ipv4 = field->find("ipv4");
        const plan_input::Value *ipv6 = field->find("ipv6");
        const plan_input::Value *flags = field->find("flags");
        const bool inert = ipv4 != nullptr && ipv4->is_bool() && !ipv4->boolean &&
                           ipv6 != nullptr && ipv6->is_bool() && !ipv6->boolean &&
                           flags != nullptr && flags->is_int() &&
                           (flags->integer == 0 || flags->integer == 256);
        if (!inert) issue("unsupported-redirect", "redirect");
    }

    ip_math::Address remote{};
    bool remote_valid = false;
    field = at("remote");
    if (field != nullptr && shape(field, "address ipv6", "remote")) {
        const plan_input::Value *address_value = field->find("address");
        const plan_input::Value *ipv6_value = field->find("ipv6");
        if (address_value != nullptr && address_value->is_string()) {
            const auto parsed = ip_math::parse_address(address_value->text);
            if (parsed.has_value() && !ip_math::rejected_for_assignment(*parsed) &&
                ipv6_value != nullptr && ipv6_value->is_bool() &&
                ipv6_value->boolean == (parsed->version == 6)) {
                remote = *parsed;
                remote_valid = true;
            } else {
                issue("invalid-address", "remote");
            }
        } else {
            issue("invalid-address", "remote");
        }
    }

    std::vector<std::tuple<std::string, long long, std::string>> addresses;
    const auto address_items = as_array(at("addresses"), 8, "addresses");
    if (address_items != nullptr) {
        for (size_t index = 0; index < address_items->size(); index++) {
            const std::string path = "addresses[" + std::to_string(index) + "]";
            const plan_input::Value &item = (*address_items)[index];
            if (!shape(&item, "address prefixLength gateway ipv6 net30", path)) continue;
            const plan_input::Value *address_value = item.find("address");
            const plan_input::Value *prefix_value = item.find("prefixLength");
            const plan_input::Value *gateway_value = item.find("gateway");
            const plan_input::Value *ipv6_value = item.find("ipv6");
            const plan_input::Value *net30_value = item.find("net30");
            if (address_value == nullptr || !address_value->is_string() || prefix_value == nullptr ||
                gateway_value == nullptr || !gateway_value->is_string() || ipv6_value == nullptr ||
                net30_value == nullptr) {
                issue("invalid-interface-address", path);
                continue;
            }
            const auto address = ip_math::parse_address(address_value->text);
            ip_math::Address peer{};
            bool peer_valid = false;
            if (gateway_value->text != "") {
                const auto parsed_peer = ip_math::parse_address(gateway_value->text);
                if (parsed_peer.has_value() && !ip_math::rejected_for_assignment(*parsed_peer)) {
                    peer = *parsed_peer;
                    peer_valid = true;
                }
            }
            const bool prefix_ok = prefix_value->is_int() && address.has_value() &&
                                   prefix_value->integer >= 1 &&
                                   prefix_value->integer <= (address->version == 4 ? 32 : 128);
            bool bad = !address.has_value() || ip_math::rejected_for_assignment(*address);
            if (ipv6_value == nullptr || !ipv6_value->is_bool() || !address.has_value() ||
                ipv6_value->boolean != (address->version == 6)) {
                bad = true;
            }
            if (!prefix_ok) bad = true;
            if (gateway_value->text != "" &&
                (!peer_valid || peer.version != (address.has_value() ? address->version : 0) ||
                 (address.has_value() && ip_math::compare(ip_math::to_bytes(peer),
                                                          ip_math::to_bytes(*address)) == 0))) {
                bad = true;
            }
            if (bad) {
                issue("invalid-interface-address", path);
                continue;
            }
            if (net30_value->type != plan_input::Type::boolean || net30_value->boolean) {
                issue("unsupported-net30", path);
            }
            const auto network = ip_math::make_network(address_value->text,
                                                       static_cast<int>(prefix_value->integer), false);
            if (network.has_value() && network->prefix <= 1) issue("global-interface-prefix", path);
            bool overlap = false;
            if (remote_valid) {
                if (ip_math::compare(ip_math::to_bytes(*address), ip_math::to_bytes(remote)) == 0 ||
                    (peer_valid && ip_math::compare(ip_math::to_bytes(peer), ip_math::to_bytes(remote)) == 0)) {
                    overlap = true;
                }
                if (network.has_value() && remote.version == network->version &&
                    ip_math::network_contains(network->base, network->prefix, ip_math::to_bytes(remote))) {
                    overlap = true;
                }
            }
            if (overlap) issue("control-endpoint-overlap", path);
            const std::string canonical = ip_math::format(*address);
            bool duplicate = false;
            for (const auto &existing : addresses) {
                if (std::get<0>(existing) == canonical) duplicate = true;
            }
            if (duplicate) issue("duplicate-address", path);
            addresses.emplace_back(canonical, prefix_value->integer,
                                   peer_valid ? ip_math::format(peer) : std::string(""));
        }
    }
    if (addresses.empty()) issue("missing-interface-address", "addresses");
    for (int family : {4, 6}) {
        int count = 0;
        for (const auto &entry : addresses) {
            const auto parsed = ip_math::parse_address(std::get<0>(entry));
            if (parsed.has_value() && parsed->version == family) count++;
        }
        if (count > 1) issue("unsupported-multiple-family-addresses", "addresses");
    }

    std::vector<ip_math::Network> networks;
    const auto route_items = as_array(at("routes"), 64, "routes");
    if (route_items != nullptr) {
        for (size_t index = 0; index < route_items->size(); index++) {
            const std::string path = "routes[" + std::to_string(index) + "]";
            const plan_input::Value &item = (*route_items)[index];
            if (!shape(&item, "address prefixLength metric ipv6", path)) continue;
            const plan_input::Value *address_value = item.find("address");
            const plan_input::Value *prefix_value = item.find("prefixLength");
            const plan_input::Value *metric_value = item.find("metric");
            const plan_input::Value *ipv6_value = item.find("ipv6");
            if (address_value == nullptr || !address_value->is_string() || prefix_value == nullptr ||
                metric_value == nullptr || ipv6_value == nullptr) {
                issue("invalid-route", path);
                continue;
            }
            if (address_value->text.find('%') != std::string::npos) {
                issue("invalid-route", path);
                continue;
            }
            const auto address = ip_math::parse_address(address_value->text);
            if (!address.has_value() || !ipv6_value->is_bool() ||
                ipv6_value->boolean != (address->version == 6) || !prefix_value->is_int() ||
                prefix_value->integer < 0 ||
                prefix_value->integer > (address->version == 4 ? 32 : 128)) {
                issue("invalid-route", path);
                continue;
            }
            const auto network = ip_math::make_network(address_value->text,
                                                       static_cast<int>(prefix_value->integer), true);
            if (!network.has_value()) {
                issue("invalid-route", path);
                continue;
            }
            if (network->prefix <= 1) issue("global-route", path);
            const bool is_v4 = network->version == 4;
            const std::vector<std::string> reserved =
                is_v4 ? std::vector<std::string>{"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
                                                 "224.0.0.0/4", "240.0.0.0/4",
                                                 // RFC 2544 range and local LAN.
                                                 "198.18.0.0/15", "192.168.50.0/24"}
                      : std::vector<std::string>{"::/128", "::1/128", "fe80::/10", "ff00::/8"};
            for (const std::string &text : reserved) {
                const auto slash = text.rfind('/');
                const auto reserved_network =
                    ip_math::make_network(text.substr(0, slash),
                                          std::stoi(text.substr(slash + 1)), true);
                if (!reserved_network.has_value()) continue;
                // Python uses network.overlaps(): any intersection counts.
                const ip_math::Bytes route_start = network->base;
                const ip_math::Bytes route_end = ip_math::range_end(*network);
                const ip_math::Bytes res_start = reserved_network->base;
                const ip_math::Bytes res_end = ip_math::range_end(*reserved_network);
                const bool overlaps =
                    (ip_math::compare(route_start, res_start) <= 0 &&
                     ip_math::compare(route_end, res_start) >= 0) ||
                    (ip_math::compare(res_start, route_start) <= 0 &&
                     ip_math::compare(res_end, route_start) >= 0);
                if (overlaps) {
                    issue("reserved-route", path);
                    break;
                }
            }
            bool overlap = false;
            if (remote_valid && remote.version == network->version &&
                ip_math::network_contains(network->base, network->prefix, ip_math::to_bytes(remote))) {
                overlap = true;
            }
            if (overlap) issue("control-endpoint-overlap", path);
            bool family_present = false, v4_with_gateway = false;
            for (const auto &entry : addresses) {
                const auto parsed = ip_math::parse_address(std::get<0>(entry));
                if (parsed.has_value() && parsed->version == network->version) family_present = true;
                if (parsed.has_value() && parsed->version == 4 && !std::get<2>(entry).empty()) {
                    v4_with_gateway = true;
                }
            }
            if (!family_present) issue("missing-address-family", path);
            if (network->version == 4 && !v4_with_gateway) issue("missing-route-gateway", path);
            bool duplicate_interface = false;
            for (const auto &entry : addresses) {
                const auto entry_network =
                    ip_math::make_network(std::get<0>(entry), static_cast<int>(std::get<1>(entry)), false);
                if (entry_network.has_value() && *entry_network == *network) duplicate_interface = true;
            }
            if (duplicate_interface) issue("duplicate-interface-route", path);
            if (!metric_value->is_int() || metric_value->integer != -1) {
                issue("unsupported-route-metric", path);
            }
            bool duplicate_route = false;
            for (const ip_math::Network &existing : networks) {
                if (existing == *network) duplicate_route = true;
            }
            if (duplicate_route) issue("duplicate-route", path);
            networks.push_back(*network);
        }
    }
    for (int family : {4, 6}) {
        if (ip_math::covers_half_space(networks, family, 0) ||
            ip_math::covers_half_space(networks, family, 1)) {
            issue("global-route-union", "routes");
            break;
        }
    }

    std::vector<std::string> servers, domains;
    bool from_dhcp_true = false;
    field = at("dns");
    if (field != nullptr && field->type != plan_input::Type::null &&
        shape(field, "fromDhcp searchDomains servers", "dns")) {
        const plan_input::Value *from_dhcp = field->find("fromDhcp");
        if (from_dhcp == nullptr || !from_dhcp->is_bool()) issue("invalid-flag", "dns.fromDhcp");
        from_dhcp_true = from_dhcp != nullptr && from_dhcp->is_bool() && from_dhcp->boolean;
        const auto search_domains = as_array(field->find("searchDomains"), 32, "dns.searchDomains");
        if (search_domains != nullptr && !search_domains->empty()) {
            issue("unsupported-search-domains", "dns.searchDomains");
        }
        const auto groups = as_array(field->find("servers"), 8, "dns.servers");
        if (groups != nullptr) {
            if (groups->size() > 1) issue("unsupported-resolver-priorities", "dns.servers");
            for (size_t index = 0; index < groups->size(); index++) {
                const std::string path = "dns.servers[" + std::to_string(index) + "]";
                const plan_input::Value &group = (*groups)[index];
                if (!shape(&group, "priority addresses domains", path)) continue;
                const plan_input::Value *priority = group.find("priority");
                if (priority == nullptr || !priority->is_int() || priority->integer != 0) {
                    issue("unsupported-resolver-priority", path);
                }
                const auto values = as_array(group.find("addresses"), 8, path + ".addresses");
                // Python's `if not values:` fires for a missing list too, since
                // array() returns a falsy empty list on type failure.
                if (values == nullptr || values->empty()) issue("missing-dns-server", path);
                if (values != nullptr) {
                    for (const plan_input::Value &value : *values) {
                        if (!shape(&value, "address port", path + ".addresses")) continue;
                        const plan_input::Value *server = value.find("address");
                        const plan_input::Value *port = value.find("port");
                        if (server == nullptr || !server->is_string() || port == nullptr ||
                            !port->is_int() || (port->integer != 0 && port->integer != 53)) {
                            issue("unsupported-dns-address", path);
                            continue;
                        }
                        const auto parsed = ip_math::parse_address(server->text);
                        if (!parsed.has_value() || ip_math::rejected_for_assignment(*parsed)) {
                            issue("unsupported-dns-address", path);
                            continue;
                        }
                        servers.push_back(ip_math::format(*parsed));
                    }
                }
                const auto matches = as_array(group.find("domains"), 32, path + ".domains");
                std::vector<std::string> effective_domains;
                if (matches == nullptr || matches->empty()) {
                    if (!suffixes.empty()) {
                        // School pushes unscoped resolvers (global-dns). Scope
                        // to the verified campus suffixes; journal deviation.
                        for (const std::string &suffix : suffixes) domains.push_back(suffix);
                    } else {
                        issue("global-dns-fallback-unavailable", path);
                    }
                } else {
                    for (const auto &domain_item : *matches) {
                        if (domain_item.is_string()) effective_domains.push_back(domain_item.text);
                    }
                }
                if (matches != nullptr) {
                    for (const plan_input::Value &domain : *matches) {
                        if (!domain.is_string() || !valid_domain(domain.text)) {
                            issue("invalid-domain", path + ".domains");
                            continue;
                        }
                        const std::string lowered = lower(domain.text);
                        bool verified = false;
                        for (const std::string &suffix : suffixes) {
                            const std::string dotted = "." + suffix;
                            if (lowered == suffix ||
                                (lowered.size() > dotted.size() &&
                                 lowered.compare(lowered.size() - dotted.size(), dotted.size(),
                                                 dotted) == 0)) {
                                verified = true;
                            }
                        }
                        if (!verified) issue("unverified-domain", path + ".domains");
                        else domains.push_back(lowered);
                    }
                }
            }
            bool duplicate_server = false, duplicate_domain = false;
            for (size_t i = 0; i < servers.size(); i++) {
                for (size_t j = i + 1; j < servers.size(); j++) {
                    if (servers[i] == servers[j]) duplicate_server = true;
                }
            }
            for (size_t i = 0; i < domains.size(); i++) {
                for (size_t j = i + 1; j < domains.size(); j++) {
                    if (domains[i] == domains[j]) duplicate_domain = true;
                }
            }
            if (duplicate_server || duplicate_domain) issue("duplicate-dns-record", "dns");
        }
    }

    if (!out.issues.empty()) return out;

    // Vendor DNS host-route mirror (scripts/vendor_dns_routes.derive), run on
    // otherwise-valid plans exactly like the Python authority re-serializing
    // the capture. Rules the validator already pins are unreachable here and
    // therefore omitted: net30 (unsupported-net30), route metrics and default
    // (unsupported-route-metric), non-empty exclusions, non-zero ctrl
    // summaries, DNS ports (0/53), and gateway==remote
    // (control-endpoint-overlap). Issue membership must match Python; the
    // differential test fails on any drift.
    std::vector<std::pair<std::string, std::string>> dns_host_routes;
    if (!servers.empty() && from_dhcp_true) {
        std::vector<std::string> derivation_issues;
        const auto reject = [&](const std::string &code) {
            if (std::find(derivation_issues.begin(), derivation_issues.end(), code) ==
                derivation_issues.end()) {
                derivation_issues.push_back(code);
            }
        };
        const plan_input::Value *allow4 = at("allowIPv4");
        if (allow4 != nullptr && allow4->is_bool() && !allow4->boolean) {
            reject("ipv4-policy-disabled");
        }
        std::set<std::string> gateways;
        for (const auto &entry : addresses) {
            const bool is_v4 = std::get<0>(entry).find(':') == std::string::npos;
            if (is_v4 && !std::get<2>(entry).empty() && std::get<2>(entry) != std::get<0>(entry)) {
                gateways.insert(std::get<2>(entry));
            }
        }
        for (const std::string &server : servers) {
            if (server.find(':') != std::string::npos) reject("unsupported-ipv6-dns-route");
        }
        if (gateways.size() != 1) reject("missing-or-ambiguous-ipv4-vpn-gateway");
        if (!derivation_issues.empty()) {
            for (const std::string &code : derivation_issues) out.issues.push_back({code, "dns.hostRoutes"});
            return out;
        }
        const std::string gateway = *gateways.begin();
        const std::string remote_text = remote_valid ? ip_math::format(remote) : std::string();
        std::set<std::string> seen;
        for (const std::string &server : servers) {
            bool conflicted = server == gateway || (remote_valid && server == remote_text);
            for (const auto &entry : addresses) {
                if (server == std::get<0>(entry)) conflicted = true;
            }
            bool exact = false;
            for (const ip_math::Network &network : networks) {
                if (network.version == 4 && network.prefix == 32 &&
                    server == ip_math::format(ip_math::Address{network.version, network.base})) {
                    exact = true;
                }
            }
            if (conflicted) reject("dns-endpoint-conflict");
            if (seen.count(server) != 0 || exact) continue;  // covered or duplicate: no candidate
            seen.insert(server);
            dns_host_routes.push_back({server + "/32", gateway});
        }
        // Any issue discards all candidates, matching Python's
        // `Derivation(issues)` with no candidates.
        if (!derivation_issues.empty()) {
            for (const std::string &code : derivation_issues) out.issues.push_back({code, "dns.hostRoutes"});
            return out;
        }
    }

    out.has_plan = true;
    out.plan.session_id = context.session_id;
    out.plan.remote = remote_valid ? ip_math::format(remote) : std::string();
    out.plan.mtu = mtu_value;
    out.plan.addresses = addresses;
    for (const ip_math::Network &network : networks) {
        out.plan.routes.push_back(ip_math::format(ip_math::Address{network.version, network.base}) +
                                  "/" + std::to_string(network.prefix));
    }
    out.plan.dns_servers = servers;
    out.plan.dns_domains = domains;
    out.plan.dns_host_routes = dns_host_routes;
    return out;
}

}  // namespace plan_validator
