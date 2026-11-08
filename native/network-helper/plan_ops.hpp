#pragma once
// C++ mirror of scripts/network_plan.py operations() and Journal. The JSON
// value strings must byte-match Python json.dumps(sort_keys, separators) so
// the differential test can compare them exactly. Pure model: no executor,
// no commands, no OS mutation. tests/test_plan_ops.py is the authority.
#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

#include "plan_validator.hpp"

namespace plan_ops {

struct InterfaceLease {
    std::string session_id;
    std::string name;
    long long index = 0;
    std::string handle_identity;

    bool operator==(const InterfaceLease &other) const {
        return session_id == other.session_id && name == other.name &&
               index == other.index && handle_identity == other.handle_identity;
    }
};

struct Operation {
    std::string kind;
    std::string key;
    std::string value;

    bool operator==(const Operation &other) const {
        return kind == other.kind && key == other.key && value == other.value;
    }
    bool operator<(const Operation &other) const {
        return std::tie(kind, key, value) < std::tie(other.kind, other.key, other.value);
    }
};

inline bool lease_valid(const InterfaceLease &lease, const std::string &session_id) {
    if (lease.session_id != session_id) return false;
    if (lease.name.size() < 5 || lease.name.size() > 10) return false;
    if (lease.name.rfind("utun", 0) != 0) return false;
    for (size_t i = 4; i < lease.name.size(); i++) {
        if (lease.name[i] < '0' || lease.name[i] > '9') return false;
    }
    if (lease.index < 1 || lease.index > 2147483647LL) return false;
    return plan_validator::valid_uuid(lease.handle_identity);
}

// Minimal JSON encoder matching json.dumps(sort_keys=True, separators=(",",":"))
// for the value shapes this module produces (strings, ints, arrays, null).
inline std::string json_escape(const std::string &text) {
    std::string out;
    for (char c : text) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<uint8_t>(c) < 0x20) {
                    char buffer[8];
                    std::snprintf(buffer, sizeof(buffer), "\\u%04x", static_cast<uint8_t>(c));
                    out += buffer;
                } else {
                    out.push_back(c);
                }
        }
    }
    return out;
}

struct JsonEntry {
    std::string key;
    std::string encoded;
};

inline std::string json_object(std::vector<JsonEntry> entries) {
    std::sort(entries.begin(), entries.end(),
              [](const JsonEntry &a, const JsonEntry &b) { return a.key < b.key; });
    std::string out = "{";
    bool first = true;
    for (const JsonEntry &entry : entries) {
        if (!first) out += ",";
        first = false;
        out += "\"" + json_escape(entry.key) + "\":" + entry.encoded;
    }
    out += "}";
    return out;
}

inline std::string json_string(const std::string &text) { return "\"" + json_escape(text) + "\""; }
inline std::string json_int(long long value) { return std::to_string(value); }
inline std::string json_null() { return "null"; }

struct OwnedRecord {
    std::string session_id;
    std::string interface;
    long long ifindex = 0;
    std::string handle_identity;
};

inline std::string encode_owner(const OwnedRecord &owner) {
    return json_object({
        {"sessionID", json_string(owner.session_id)},
        {"interface", json_string(owner.interface)},
        {"ifindex", json_int(owner.ifindex)},
        {"handleIdentity", json_string(owner.handle_identity)},
    });
}

inline std::vector<plan_ops::Operation> operations(
    const plan_validator::Plan &plan, const InterfaceLease &lease) {
    if (!lease_valid(lease, plan.session_id)) {
        throw std::invalid_argument("invalid-interface-lease");
    }
    std::vector<plan_ops::Operation> result;
    const OwnedRecord owner{lease.session_id, lease.name, lease.index, lease.handle_identity};

    std::string address_array = "[";
    bool first = true;
    for (const auto &entry : plan.addresses) {
        if (!first) address_array += ",";
        first = false;
        address_array += "[" + json_string(std::get<0>(entry)) + "," +
                         json_int(std::get<1>(entry)) + "," +
                         json_string(std::get<2>(entry)) + "]";
    }
    address_array += "]";
    {
        std::vector<JsonEntry> entries = {
            {"sessionID", json_string(owner.session_id)},
            {"interface", json_string(owner.interface)},
            {"ifindex", json_int(owner.ifindex)},
            {"handleIdentity", json_string(owner.handle_identity)},
            {"mtu", json_int(plan.mtu)},
            {"addresses", address_array},
        };
        result.push_back({"owned-interface", "interface:" + lease.name, json_object(std::move(entries))});
    }

    struct RouteSpec {
        std::string network;
        std::optional<std::string> gateway;
        std::string origin;
    };
    std::vector<RouteSpec> routes;
    for (const auto &entry : plan.addresses) {
        const auto network = ip_math::make_network(std::get<0>(entry),
                                                   static_cast<int>(std::get<1>(entry)), false);
        if (!network.has_value()) continue;
        const std::string text = ip_math::format(ip_math::Address{network->version, network->base}) +
                                 "/" + std::to_string(network->prefix);
        if (network->version == 4) {
            routes.push_back({text, std::get<0>(entry), "interface-prefix"});
        } else {
            routes.push_back({text, std::nullopt, "interface-prefix"});
        }
    }
    for (const std::string &route : plan.routes) {
        std::optional<std::string> gateway;
        if (route.find(':') == std::string::npos && !route.empty()) {
            for (const auto &entry : plan.addresses) {
                const auto parsed = ip_math::parse_address(std::get<0>(entry));
                if (parsed.has_value() && parsed->version == 4) {
                    gateway = std::get<2>(entry);
                    break;
                }
            }
        }
        routes.push_back({route, gateway, "pushed-prefix"});
    }
    for (const RouteSpec &spec : routes) {
        std::vector<JsonEntry> entries = {
            {"sessionID", json_string(owner.session_id)},
            {"interface", json_string(owner.interface)},
            {"ifindex", json_int(owner.ifindex)},
            {"handleIdentity", json_string(owner.handle_identity)},
            {"network", json_string(spec.network)},
            {"scope", json_string("unscoped")},
            {"gateway", spec.gateway.has_value() ? json_string(*spec.gateway) : json_null()},
            {"gatewayKind", json_string(spec.gateway.has_value() ? "ip" : "interface-link")},
            {"origin", json_string(spec.origin)},
            {"metric", json_int(-1)},
        };
        result.push_back({"interface-route", "route:" + spec.network, json_object(std::move(entries))});
    }
    // Vendor mirror: /32 tunnel routes keep the captured resolvers reachable.
    for (const auto &candidate : plan.dns_host_routes) {
        std::vector<JsonEntry> entries = {
            {"sessionID", json_string(owner.session_id)},
            {"interface", json_string(owner.interface)},
            {"ifindex", json_int(owner.ifindex)},
            {"handleIdentity", json_string(owner.handle_identity)},
            {"network", json_string(candidate.first)},
            {"scope", json_string("unscoped")},
            {"gateway", json_string(candidate.second)},
            {"gatewayKind", json_string("ip")},
            {"origin", json_string("vendor-dns-host-route")},
            {"metric", json_int(-1)},
        };
        result.push_back({"interface-route", "route:" + candidate.first, json_object(std::move(entries))});
    }
    if (!plan.dns_servers.empty()) {
        std::string server_array = "[";
        for (size_t i = 0; i < plan.dns_servers.size(); i++) {
            if (i != 0) server_array += ",";
            server_array += json_string(plan.dns_servers[i]);
        }
        server_array += "]";
        std::string domain_array = "[";
        for (size_t i = 0; i < plan.dns_domains.size(); i++) {
            if (i != 0) domain_array += ",";
            domain_array += json_string(plan.dns_domains[i]);
        }
        domain_array += "]";
        const std::string key =
            "State:/Network/Service/szu-securelink-" + lease.session_id + "/DNS";
        std::vector<JsonEntry> entries = {
            {"sessionID", json_string(owner.session_id)},
            {"interface", json_string(owner.interface)},
            {"ifindex", json_int(owner.ifindex)},
            {"handleIdentity", json_string(owner.handle_identity)},
            {"ServerAddresses", server_array},
            {"SupplementalMatchDomains", domain_array},
            {"SupplementalMatchDomainsNoSearch", json_int(1)},
        };
        result.push_back({"supplemental-resolver", key, json_object(std::move(entries))});
    }
    return result;
}

// Route additions for a validated in-session push delta: only the
// pushed-prefix subset with origin ctrl-push, mirroring
// network_plan.py push_operations. Delta captures carry address fields only
// to satisfy the validator; no owned-interface or interface-prefix op is
// produced here. Duplicate and conflict rejection against the live journal
// is the daemon's fail-closed duty.
inline std::vector<Operation> push_operations(
    const plan_validator::Plan &plan, const InterfaceLease &lease) {
    if (!lease_valid(lease, plan.session_id)) {
        throw std::invalid_argument("invalid-interface-lease");
    }
    const OwnedRecord owner{lease.session_id, lease.name, lease.index, lease.handle_identity};
    std::vector<Operation> result;
    result.reserve(plan.routes.size());
    for (const std::string &route : plan.routes) {
        std::optional<std::string> gateway;
        if (route.find(':') == std::string::npos && !route.empty()) {
            for (const auto &entry : plan.addresses) {
                const auto parsed = ip_math::parse_address(std::get<0>(entry));
                if (parsed.has_value() && parsed->version == 4) {
                    gateway = std::get<2>(entry);
                    break;
                }
            }
        }
        std::vector<JsonEntry> entries = {
            {"sessionID", json_string(owner.session_id)},
            {"interface", json_string(owner.interface)},
            {"ifindex", json_int(owner.ifindex)},
            {"handleIdentity", json_string(owner.handle_identity)},
            {"network", json_string(route)},
            {"scope", json_string("unscoped")},
            {"gateway", gateway.has_value() ? json_string(*gateway) : json_null()},
            {"gatewayKind", json_string(gateway.has_value() ? "ip" : "interface-link")},
            {"origin", json_string("ctrl-push")},
            {"metric", json_int(-1)},
        };
        result.push_back({"interface-route", "route:" + route, json_object(std::move(entries))});
    }
    return result;
}

// Vendor local static policy (unit 5): the stable school-internal route set
// the official client holds in its own configuration (observed evidence:
// native/network-helper/vendor-static-routes.json). Split tunnel by design —
// the default route stays with the system gateway; only school-internal
// ranges ride the tunnel. A static route already covered by the session plan
// (interface prefix or a server push) is skipped exactly as the vendor merges
// its config with server pushes; origin marks the journal so the finance gate
// can tell the two sources apart.
inline std::vector<Operation> static_route_operations(
    const plan_validator::Plan &plan, const InterfaceLease &lease,
    const std::vector<std::string> &static_routes) {
    if (!lease_valid(lease, plan.session_id)) {
        throw std::invalid_argument("invalid-interface-lease");
    }
    const OwnedRecord owner{lease.session_id, lease.name, lease.index, lease.handle_identity};
    std::vector<Operation> result;
    for (const std::string &route : static_routes) {
        bool covered = false;
        for (const auto &entry : plan.addresses) {
            const auto network = ip_math::make_network(std::get<0>(entry),
                                                       static_cast<int>(std::get<1>(entry)), false);
            if (network.has_value()) {
                const std::string text = ip_math::format(ip_math::Address{network->version, network->base}) +
                                         "/" + std::to_string(network->prefix);
                if (text == route) covered = true;
            }
        }
        for (const std::string &pushed : plan.routes) {
            if (pushed == route) covered = true;
        }
        if (covered) continue;
        std::optional<std::string> gateway;
        for (const auto &entry : plan.addresses) {
            const auto parsed = ip_math::parse_address(std::get<0>(entry));
            if (parsed.has_value() && parsed->version == 4) {
                gateway = std::get<2>(entry);
                break;
            }
        }
        std::vector<JsonEntry> entries = {
            {"sessionID", json_string(owner.session_id)},
            {"interface", json_string(owner.interface)},
            {"ifindex", json_int(owner.ifindex)},
            {"handleIdentity", json_string(owner.handle_identity)},
            {"network", json_string(route)},
            {"scope", json_string("unscoped")},
            {"gateway", gateway.has_value() ? json_string(*gateway) : json_null()},
            {"gatewayKind", json_string(gateway.has_value() ? "ip" : "interface-link")},
            {"origin", json_string("vendor-static-route")},
            {"metric", json_int(-1)},
        };
        result.push_back({"interface-route", "route:" + route, json_object(std::move(entries))});
    }
    return result;
}

inline bool contains(const std::set<size_t> &set, size_t value) { return set.count(value) != 0; }

class Journal {
public:
    Journal(const std::vector<Operation> &expected, const InterfaceLease &lease)
        : expected_(expected), lease_(lease) {}

    static Journal for_plan(const plan_validator::Plan &plan, const InterfaceLease &lease) {
        return Journal(operations(plan, lease), lease);
    }

    const std::vector<Operation> &expected() const { return expected_; }

    // outcome: created | failed | preexisting. Throws std::invalid_argument on
    // any violation, mirroring ValueError in the Python model.
    void record(size_t index, const std::string &outcome, const Operation *before,
                const Operation *after) {
        if (index >= expected_.size()) throw std::invalid_argument("invalid-operation-index");
        if (contains(created_, index)) throw std::invalid_argument("duplicate-success-receipt");
        if (outcome != "created" && outcome != "failed" && outcome != "preexisting") {
            throw std::invalid_argument("invalid-operation-outcome");
        }
        if (outcome == "created") {
            if (before != nullptr || after == nullptr || !(*after == expected_[index])) {
                throw std::invalid_argument("unproven-operation-ownership");
            }
            if (index != 0 && !contains(created_, 0)) {
                throw std::invalid_argument("interface-not-owned");
            }
            created_.insert(index);
        }
    }

    // Unit-4 in-session push deltas: extend the audited journal with more
    // route ops instead of opening a second journal. Whole-interface
    // ownership, the drift model and reverse-order cleanup are preserved;
    // created receipts for appended indices follow through record().
    void append(const std::vector<Operation> &ops) {
        for (const Operation &op : ops) expected_.push_back(op);
    }

    struct CleanupResult {
        std::vector<Operation> removals;
        std::vector<plan_validator::Issue> issues;
    };

    CleanupResult cleanup(const std::map<std::string, Operation> &current,
                          const std::optional<InterfaceLease> &current_lease) const {
        CleanupResult out;
        if (!current_lease.has_value() || !(*current_lease == lease_)) {
            out.issues.push_back({"interface-ownership-lost", "cleanup"});
            return out;
        }
        bool drift = false;
        for (size_t index = 0; index < expected_.size(); index++) {
            if (index == 0 || contains(created_, index)) continue;
            if (current.count(expected_[index].key) != 0) drift = true;
        }
        if (drift) {
            // Python emits this pre-drift issue before the identity probe may
            // emit its own, so a double report on one record is expected.
            out.issues.push_back({"unowned-dependent-record", "cleanup"});
        }
        std::set<const Operation *> owned;
        for (size_t index : created_) owned.insert(&expected_[index]);
        for (const auto &entry : current) {
            bool is_owned = false;
            for (const Operation *op : owned) {
                if (*op == entry.second) is_owned = true;
            }
            if (is_owned) continue;
            // Identity probe of the payload. Canonical values produced by
            // operations() make this exact; the real executor must feed only
            // canonical serialization into cleanup, or parse the JSON fully.
            const std::string &value = entry.second.value;
            const auto interface_at = value.find("\"interface\":\"" + lease_.name + "\"");
            const auto ifindex_at = value.find("\"ifindex\":" + std::to_string(lease_.index));
            if (interface_at != std::string::npos && ifindex_at != std::string::npos) {
                drift = true;
                out.issues.push_back({"unowned-dependent-record", "cleanup"});
                break;
            }
        }
        for (auto it = created_.rbegin(); it != created_.rend(); ++it) {
            const Operation &expected = expected_[*it];
            const auto actual = current.find(expected.key);
            if (actual == current.end()) continue;
            if (!(actual->second == expected)) {
                drift = true;
                out.issues.push_back({"record-drift",
                                      "operations[" + std::to_string(*it) + "]"});
            } else if (*it == 0 && drift) {
                out.issues.push_back({"interface-retained-for-drift", "operations[0]"});
            } else {
                out.removals.push_back(expected);
            }
        }
        return out;
    }

private:
    std::vector<Operation> expected_;
    InterfaceLease lease_;
    std::set<size_t> created_;
};

}  // namespace plan_ops
