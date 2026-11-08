#pragma once
// Pure system-operation builders for the executor. Routes become fixed-argv
// /sbin/route invocations (IPv4 via the captured peer gateway, IPv6 via
// -iface link gateway, never RTF_IFSCOPE); DNS becomes the supplemental
// resolver store key with its canonical payload. NOTHING here executes or
// mutates: these are data descriptions the privileged daemon (3c) applies
// under journal ownership in 3e.
#include <optional>
#include <string>
#include <vector>

#include "plan_ops.hpp"

namespace system_ops {

struct RouteInvocation {
    bool apply = true;          // add vs delete
    std::vector<std::string> argv;
};

inline std::optional<RouteInvocation> route_invocation(const plan_ops::Operation &op,
                                                       bool apply) {
    if (op.kind != "interface-route") return std::nullopt;
    const std::string prefix = apply ? "route:" : "route:";
    if (op.key.rfind(prefix, 0) != 0) return std::nullopt;
    const std::string network = op.key.substr(prefix.size());
    // Gateway kind comes from the canonical payload produced by operations().
    const bool has_ip_gateway = op.value.find("\"gatewayKind\":\"ip\"") != std::string::npos;
    const bool is_v4 = network.find(':') == std::string::npos;
    const bool is_host = is_v4 && network.size() > 3 &&
                         network.substr(network.size() - 3) == "/32";
    const bool is_v6_host = !is_v4 && network.size() > 4 &&
                            network.substr(network.size() - 4) == "/128";
    std::vector<std::string> argv{"/sbin/route", "-n", apply ? "add" : "delete"};
    if (is_v4) {
        argv.push_back(is_host ? "-host" : "-net");
        argv.push_back(network);
        if (apply && has_ip_gateway) {
            // The peer value sits in the canonical payload's gateway field.
            const auto gateway_at = op.value.find("\"gateway\":\"");
            if (gateway_at == std::string::npos) return std::nullopt;
            const size_t start = gateway_at + std::string("\"gateway\":\"").size();
            const size_t end = op.value.find('"', start);
            if (end == std::string::npos) return std::nullopt;
            argv.push_back("-gateway");
            argv.push_back(op.value.substr(start, end - start));
        }
    } else {
        argv.push_back("-inet6");
        argv.push_back(is_v6_host ? "-host" : "-net");
        argv.push_back(network);
        if (apply && !has_ip_gateway) {
            argv.push_back("-iface");
            // interface name from the canonical payload
            const auto interface_at = op.value.find("\"interface\":\"");
            if (interface_at == std::string::npos) return std::nullopt;
            const size_t start = interface_at + std::string("\"interface\":\"").size();
            const size_t end = op.value.find('"', start);
            if (end == std::string::npos) return std::nullopt;
            argv.push_back(op.value.substr(start, end - start));
        }
    }
    return RouteInvocation{apply, argv};
}

inline std::optional<std::string> dns_store_key(const plan_ops::Operation &op) {
    if (op.kind != "supplemental-resolver") return std::nullopt;
    return op.key;  // "State:/Network/Service/szu-securelink-<session>/DNS"
}

inline std::optional<std::string> dns_payload(const plan_ops::Operation &op) {
    if (op.kind != "supplemental-resolver") return std::nullopt;
    // SCDynamicStore payload values minus the owner bookkeeping fields; the
    // daemon passes exactly this dictionary to SCDynamicStoreSetKeyValue.
    return op.value;
}

}  // namespace system_ops
