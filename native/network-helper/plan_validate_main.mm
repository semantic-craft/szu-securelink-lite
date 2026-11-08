// Differential-test entry point for the C++ plan validator. Reads a context
// JSON file and a capture JSON file, prints issues as "code\tpath" lines in
// traversal order, "PLAN" followed by field lines when valid, or
// "DECODE\t<reason>" when the input never parsed. Pure offline tooling.
#import <Foundation/Foundation.h>
#import <cstdio>
#import <fstream>
#import <iostream>
#import <sstream>
#import <string>
#import <vector>
#import "plan_validator.hpp"

namespace {

bool read_file(const std::string &path, std::string &out) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return false;
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    out = buffer.str();
    return true;
}

plan_validator::Context parse_context(const plan_input::Value &value, bool &ok) {
    plan_validator::Context context;
    ok = value.is_object();
    if (!ok) return context;
    const auto *session = value.find("sessionID");
    const auto *duration = value.find("durationSeconds");
    const auto *port = value.find("remotePort");
    const auto *suffixes = value.find("verifiedDNSSuffixes");
    ok = session != nullptr && session->is_string() && duration != nullptr && duration->is_int() &&
         port != nullptr && port->is_int() && suffixes != nullptr && suffixes->is_array();
    if (!ok) return context;
    context.session_id = session->text;
    context.duration_seconds = duration->integer;
    context.remote_port = port->integer;
    for (const auto &item : suffixes->items) {
        if (!item.is_string()) {
            ok = false;
            return context;
        }
        context.verified_dns_suffixes.push_back(item.text);
    }
    return context;
}

}  // namespace

int main(int argc, char **argv) {
    if (argc != 3) {
        std::fputs("usage: plan-validate <context.json> <capture.json>\n", stderr);
        return 2;
    }
    std::string context_bytes, capture_bytes;
    if (!read_file(argv[1], context_bytes) || !read_file(argv[2], capture_bytes)) {
        std::fputs("cannot read input files\n", stderr);
        return 2;
    }
    const auto context_parsed = plan_input::parse(
        reinterpret_cast<const uint8_t *>(context_bytes.data()), context_bytes.size());
    const auto capture_parsed = plan_input::parse(
        reinterpret_cast<const uint8_t *>(capture_bytes.data()), capture_bytes.size());
    if (context_parsed.error != plan_input::Error::none ||
        capture_parsed.error != plan_input::Error::none) {
        const auto error = context_parsed.error != plan_input::Error::none
                               ? context_parsed.error
                               : capture_parsed.error;
        const char *name = error == plan_input::Error::duplicate_field ? "duplicate-field"
                           : error == plan_input::Error::invalid_number ? "invalid-number"
                                                                        : "invalid-capture-json";
        std::cout << "DECODE\t" << name << "\n";
        return 0;
    }
    bool context_ok = false;
    const auto context = parse_context(context_parsed.value, context_ok);
    if (!context_ok) {
        std::cout << "DECODE\tinvalid-capture-json\n";
        return 0;
    }
    const auto result = plan_validator::validate_capture(capture_parsed.value, context);
    if (result.has_plan) {
        std::cout << "PLAN\n";
        std::cout << "remote\t" << result.plan.remote << "\n";
        std::cout << "mtu\t" << result.plan.mtu << "\n";
        for (const auto &entry : result.plan.addresses) {
            std::cout << "address\t" << std::get<0>(entry) << "," << std::get<1>(entry) << ","
                      << std::get<2>(entry) << "\n";
        }
        for (const std::string &route : result.plan.routes) std::cout << "route\t" << route << "\n";
        for (const std::string &server : result.plan.dns_servers) {
            std::cout << "server\t" << server << "\n";
        }
        for (const std::string &domain : result.plan.dns_domains) {
            std::cout << "domain\t" << domain << "\n";
        }
        for (const auto &candidate : result.plan.dns_host_routes) {
            std::cout << "hostroute\t" << candidate.first << "," << candidate.second << "\n";
        }
        return 0;
    }
    for (const plan_validator::Issue &single : result.issues) {
        std::cout << single.code << "\t" << single.path << "\n";
    }
    return 0;
}
