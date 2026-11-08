// Offline tests for system-op builders and the utun lifecycle fake. Prints
// nothing on success; a non-zero exit means the executor data model drifted.
#import <Foundation/Foundation.h>
#import <cstdio>
#import <string>
#import <vector>
#import "system_ops.hpp"
#import "utun_tunnel.hpp"

namespace {
int failures = 0;
void check(bool ok, const char *what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL %s\n", what);
        failures++;
    }
}
std::string join(const std::vector<std::string> &argv) {
    std::string out;
    for (const std::string &part : argv) {
        if (!out.empty()) out += " ";
        out += part;
    }
    return out;
}
plan_ops::Operation route_op(const std::string &network, const std::string &gateway,
                             bool v6) {
    const std::string gateway_value = v6 ? "null" : "\"" + gateway + "\"";
    const std::string kind_value = gateway.empty() || v6 ? "interface-link" : "ip";
    return plan_ops::Operation{
        "interface-route", "route:" + network,
        "{\"gateway\":" + gateway_value +
            ",\"gatewayKind\":\"" + kind_value +
            "\",\"handleIdentity\":\"b5c9d692-528e-44d3-966c-9f3772fbc3a9\",\"ifindex\":9,"
            "\"interface\":\"utun9\",\"metric\":-1,\"network\":\"" + network +
            "\",\"origin\":\"pushed-prefix\",\"scope\":\"unscoped\",\"sessionID\":"
            "\"f50ed258-6ef7-4f2c-9b63-c0838c89c9fa\"}"};
}
}

int main() {
    // IPv4 pushed prefix with the peer gateway, add then delete.
    const auto add = system_ops::route_invocation(
        route_op("10.30.0.0/16", "10.20.0.1", false), true);
    check(add.has_value(), "v4 add builds");
    check(join(add->argv) == "/sbin/route -n add -net 10.30.0.0/16 -gateway 10.20.0.1",
          "v4 add argv");
    const auto del = system_ops::route_invocation(
        route_op("10.30.0.0/16", "10.20.0.1", false), false);
    check(del.has_value() && join(del->argv) == "/sbin/route -n delete -net 10.30.0.0/16",
          "v4 delete argv");

    // IPv6 pushed prefix via the interface link gateway.
    const auto add6 = system_ops::route_invocation(
        route_op("fd00:0:0:2::/64", "", true), true);
    check(add6.has_value() &&
              join(add6->argv) == "/sbin/route -n add -inet6 -net fd00:0:0:2::/64 -iface utun9",
          "v6 add argv");

    // Host routes use -host.
    const auto host = system_ops::route_invocation(
        route_op("10.30.0.53/32", "10.20.0.1", false), true);
    check(host.has_value() &&
              join(host->argv) == "/sbin/route -n add -host 10.30.0.53/32 -gateway 10.20.0.1",
          "v4 host argv");

    // DNS op exposes its store key and payload; route ops expose none.
    const plan_ops::Operation dns{
        "supplemental-resolver",
        "State:/Network/Service/szu-securelink-f50ed258-6ef7-4f2c-9b63-c0838c89c9fa/DNS",
        "{\"ServerAddresses\":[\"10.30.0.53\"],\"SupplementalMatchDomains\":"
        "[\"campus.example\",\"finance.campus.example\"],\"SupplementalMatchDomainsNoSearch\":1,"
        "\"handleIdentity\":\"b5c9d692-528e-44d3-966c-9f3772fbc3a9\",\"ifindex\":9,"
        "\"interface\":\"utun9\",\"sessionID\":\"f50ed258-6ef7-4f2c-9b63-c0838c89c9fa\"}"};
    const auto key = system_ops::dns_store_key(dns);
    check(key.has_value() &&
              key->find("szu-securelink-f50ed258-6ef7-4f2c-9b63-c0838c89c9fa") != std::string::npos,
          "dns store key");
    check(system_ops::dns_payload(dns).has_value(), "dns payload");
    check(!system_ops::dns_store_key(route_op("10.30.0.0/16", "10.20.0.1", false)).has_value(),
          "route op is not a dns op");
    check(!system_ops::route_invocation(dns, true).has_value(), "dns op is not a route op");

    // utun lifecycle: every failure point converges on exactly one close and
    // never claims removal past the failing stage (mirrors probe selfTest).
    const int stages[] = {0, 1, 2, 3, 5, 6};
    for (int failure : stages) {
        utun_tunnel::Fake ops;
        ops.fail_at = failure;
        const auto result = utun_tunnel::run_lifecycle(ops);
        const bool close_expected = failure != 1;
        check(ops.closes == (close_expected ? 1 : 0), "exactly one close per path");
        if (failure == 0) {
            check(result.created && result.closed && result.removed && result.error == 0,
                  "happy path");
        } else {
            check(result.error == EACCES, "failure carries errno");
            if (failure <= 2) check(!result.created, "no creation before connect");
            if (failure == 3 || failure == 5 || failure == 6) {
                check(!result.removed, "no removal claim past the failure");
            }
            if (failure == 6) check(ops.removed_seen, "removal was attempted then failed");
        }
    }
    if (failures != 0) return 1;
    return 0;
}
