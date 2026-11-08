// Differential entry for plan_ops. Prints Python-comparable canonical text
// for operations() and for ten fixed Journal scenarios. The Python test in
// tests/test_plan_ops.py mirrors every line; any drift fails the gate.
// Pure offline tooling: nothing executes or mutates.
#import <Foundation/Foundation.h>
#import <cstdio>
#import <fstream>
#import <iostream>
#import <string>
#import <vector>
#import "plan_ops.hpp"

namespace {

// Both sides derive the baseline from the same fixture capture through the
// validator, so vendor DNS host-route candidates stay identical by
// construction instead of drifting from a hand-written copy.
plan_validator::Plan baseline_plan() {
    static const char kCapture[] =
        "{\"version\": 2, \"ctrlOptionsCaptured\": true, \"ctrlOptionCount\": 0,"
        " \"ctrlDuplicateKeys\": 0, \"ctrlDuplicateDomains\": 0, \"ctrlMappings\": [],"
        " \"domainOptionsCaptured\": true, \"domainOptions\": [], \"complete\": true,"
        " \"failure\": null, \"layer\": 3, \"mtu\": 1400,"
        " \"remote\": {\"address\": \"198.51.100.4\", \"ipv6\": false},"
        " \"addresses\": [{\"address\": \"10.20.0.2\", \"prefixLength\": 30,"
        " \"gateway\": \"10.20.0.1\", \"ipv6\": false, \"net30\": false}],"
        " \"routes\": [{\"address\": \"10.30.0.0\", \"prefixLength\": 16, \"metric\": -1,"
        " \"ipv6\": false}], \"excludedRoutes\": [], \"routeMetricDefault\": -1,"
        " \"redirect\": null, \"dns\": {\"fromDhcp\": true, \"searchDomains\": [],"
        " \"servers\": [{\"priority\": 0, \"addresses\": [{\"address\": \"10.30.0.53\","
        " \"port\": 0}], \"domains\": [\"campus.example\", \"finance.campus.example\"]}]},"
        " \"allowIPv4\": true, \"allowIPv6\": null, \"allowLocalDNS\": true,"
        " \"sessionNameDiscarded\": true}";
    const auto decoded = plan_input::parse(
        reinterpret_cast<const uint8_t *>(kCapture), std::strlen(kCapture));
    plan_validator::Context context;
    context.session_id = "f50ed258-6ef7-4f2c-9b63-c0838c89c9fa";
    context.duration_seconds = 120;
    context.remote_port = 443;
    context.verified_dns_suffixes = {"campus.example"};
    const auto result = plan_validator::validate_capture(decoded.value, context);
    if (decoded.error != plan_input::Error::none || !result.has_plan) {
        std::fputs("baseline fixture plan invalid\n", stderr);
        std::exit(71);
    }
    return result.plan;
}

plan_ops::InterfaceLease baseline_lease() {
    return {"f50ed258-6ef7-4f2c-9b63-c0838c89c9fa", "utun9", 9,
            "b5c9d692-528e-44d3-966c-9f3772fbc3a9"};
}

std::string describe(const std::vector<plan_ops::Operation> &removals,
                     const std::vector<plan_validator::Issue> &issues) {
    std::string out = "removals=";
    if (removals.empty()) out += "-";
    for (size_t i = 0; i < removals.size(); i++) {
        if (i != 0) out += ",";
        out += removals[i].key;
    }
    out += " issues=";
    if (issues.empty()) out += "-";
    for (size_t i = 0; i < issues.size(); i++) {
        if (i != 0) out += ",";
        out += issues[i].code + ":" + issues[i].path;
    }
    out += "\n";
    return out;
}

}  // namespace

int main(int argc, char **argv) {
    const std::string mode = argc > 1 ? argv[1] : "";
    const auto plan = baseline_plan();
    const auto lease = baseline_lease();
    if (mode == "operations") {
        try {
            for (const plan_ops::Operation &op : plan_ops::operations(plan, lease)) {
                std::cout << op.kind << "|" << op.key << "|" << op.value << "\n";
            }
        } catch (const std::exception &error) {
            std::cout << "ERROR " << error.what() << "\n";
        }
        return 0;
    }
    if (mode == "static-route-operations") {
        // Static set arrives as a plain JSON array of canonical CIDR strings.
        const auto static_path = argc > 2 ? argv[2] : nullptr;
        std::vector<std::string> static_routes;
        if (static_path != nullptr) {
            std::ifstream stream(static_path);
            std::string text((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
            const auto decoded = plan_input::parse(
                reinterpret_cast<const uint8_t *>(text.data()), text.size());
            if (decoded.error == plan_input::Error::none && decoded.value.is_object()) {
                const auto *routes = decoded.value.find("staticRoutes");
                if (routes != nullptr && routes->is_array()) {
                    for (const auto &item : routes->items) {
                        if (item.is_string()) static_routes.push_back(item.text);
                    }
                }
            }
        }
        try {
            for (const plan_ops::Operation &op : plan_ops::static_route_operations(plan, lease, static_routes)) {
                std::cout << op.kind << "|" << op.key << "|" << op.value << "\n";
            }
        } catch (const std::exception &error) {
            std::cout << "ERROR " << error.what() << "\n";
        }
        return 0;
    }
    if (mode == "push-operations") {
        try {
            for (const plan_ops::Operation &op : plan_ops::push_operations(plan, lease)) {
                std::cout << op.kind << "|" << op.key << "|" << op.value << "\n";
            }
        } catch (const std::exception &error) {
            std::cout << "ERROR " << error.what() << "\n";
        }
        return 0;
    }
    if (mode == "lease-mismatch") {
        plan_ops::InterfaceLease wrong = lease;
        wrong.session_id = "ffffffff-ffff-4fff-8fff-ffffffffffff";
        try {
            (void)plan_ops::operations(plan, wrong);
            std::cout << "NO-ERROR\n";
        } catch (const std::exception &error) {
            std::cout << "ERROR " << error.what() << "\n";
        }
        return 0;
    }
    if (mode == "scenarios") {
        const auto expected = plan_ops::operations(plan, lease);
        auto fresh = [&]() { return plan_ops::Journal::for_plan(plan, lease); };
        auto at = [&](size_t i) { return expected[i]; };
        // S1 all created, full cleanup
        {
            auto journal = fresh();
            for (size_t i = 0; i < expected.size(); i++) {
                const plan_ops::Operation op = at(i);
                journal.record(i, "created", nullptr, &op);
            }
            std::map<std::string, plan_ops::Operation> current;
            for (const auto &op : expected) current[op.key] = op;
            const auto result = journal.cleanup(current, lease);
            std::cout << "S1 " << describe(result.removals, result.issues);
        }
        // S2 only interface created
        {
            auto journal = fresh();
            const plan_ops::Operation op0 = at(0);
            journal.record(0, "created", nullptr, &op0);
            std::map<std::string, plan_ops::Operation> current;
            current[op0.key] = op0;
            const auto result = journal.cleanup(current, lease);
            std::cout << "S2 " << describe(result.removals, result.issues);
        }
        // S3 interface record drifted
        {
            auto journal = fresh();
            const plan_ops::Operation op0 = at(0);
            const plan_ops::Operation op1 = at(1);
            journal.record(0, "created", nullptr, &op0);
            journal.record(1, "created", nullptr, &op1);
            plan_ops::Operation drifted = op0;
            drifted.value = "{\"drift\":true}";
            std::map<std::string, plan_ops::Operation> current;
            current[drifted.key] = drifted;
            current[op1.key] = op1;
            const auto result = journal.cleanup(current, lease);
            std::cout << "S3 " << describe(result.removals, result.issues);
        }
        // S4 foreign record bound to our interface
        {
            auto journal = fresh();
            const plan_ops::Operation op0 = at(0);
            journal.record(0, "created", nullptr, &op0);
            plan_ops::Operation foreign{"interface-route", "route:198.51.100.0/24",
                                        "{\"gateway\":\"198.51.100.1\",\"handleIdentity\":\""
                                        "b5c9d692-528e-44d3-966c-9f3772fbc3a9\",\"ifindex\":9,"
                                        "\"interface\":\"utun9\",\"metric\":-1,\"network\":"
                                        "\"198.51.100.0/24\",\"origin\":\"foreign\",\"scope\":"
                                        "\"unscoped\",\"sessionID\":\"f50ed258-6ef7-4f2c-9b63-"
                                        "c0838c89c9fa\"}"};
            std::map<std::string, plan_ops::Operation> current;
            current[op0.key] = op0;
            current[foreign.key] = foreign;
            const auto result = journal.cleanup(current, lease);
            std::cout << "S4 " << describe(result.removals, result.issues);
        }
        // S5 route recorded without owning the interface
        {
            auto journal = fresh();
            std::cout << "S5 ";
            try {
                const plan_ops::Operation op1 = at(1);
                journal.record(1, "created", nullptr, &op1);
                std::cout << "NO-ERROR\n";
            } catch (const std::exception &error) {
                std::cout << "ERROR " << error.what() << "\n";
            }
        }
        // S6 duplicate success receipt
        {
            auto journal = fresh();
            const plan_ops::Operation op0 = at(0);
            journal.record(0, "created", nullptr, &op0);
            std::cout << "S6 ";
            try {
                journal.record(0, "created", nullptr, &op0);
                std::cout << "NO-ERROR\n";
            } catch (const std::exception &error) {
                std::cout << "ERROR " << error.what() << "\n";
            }
        }
        // S7 cleanup under a replaced lease
        {
            auto journal = fresh();
            plan_ops::InterfaceLease replaced = lease;
            replaced.name = "utun10";
            std::map<std::string, plan_ops::Operation> current;
            for (const auto &op : expected) current[op.key] = op;
            const auto result = journal.cleanup(current, replaced);
            std::cout << "S7 " << describe(result.removals, result.issues);
        }
        // S8 invalid outcome
        {
            auto journal = fresh();
            std::cout << "S8 ";
            try {
                const plan_ops::Operation op2 = at(2);
                journal.record(2, "bogus", &op2, nullptr);
                std::cout << "NO-ERROR\n";
            } catch (const std::exception &error) {
                std::cout << "ERROR " << error.what() << "\n";
            }
        }
        // S9 preexisting never grants ownership; a later created claim is rejected
        {
            auto journal = fresh();
            const plan_ops::Operation op1 = at(1);
            journal.record(1, "preexisting", &op1, nullptr);
            std::cout << "S9 ";
            try {
                journal.record(1, "created", nullptr, &op1);
                std::cout << "NO-ERROR\n";
            } catch (const std::exception &error) {
                std::cout << "ERROR " << error.what() << "\n";
            }
            const auto result = journal.cleanup({}, lease);
            std::cout << "S9b " << describe(result.removals, result.issues);
        }
        // S10 uncreated-but-present expected record retains the interface
        {
            auto journal = fresh();
            const plan_ops::Operation op0 = at(0);
            const plan_ops::Operation op2 = at(2);
            journal.record(0, "created", nullptr, &op0);
            std::map<std::string, plan_ops::Operation> current;
            current[op0.key] = op0;
            current[op2.key] = op2;
            const auto result = journal.cleanup(current, lease);
            std::cout << "S10 " << describe(result.removals, result.issues);
        }
        return 0;
    }
    std::fputs("usage: plan-ops operations|push-operations|scenarios|lease-mismatch\n", stderr);
    return 2;
}
