// Tunnel-capable privileged executor daemon. Launchd socket-activates one
// instance per engine connection. Per connection: verify the engine's code
// identity, run the audited transaction over the real hooks (utun lifecycle,
// journaled route invocations, supplemental DNS), send exactly one utun fd,
// and converge cleanup on every exit path. Root never executes a user-owned
// binary; identities come from staged root-owned files.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <launch.h>
#import <sys/stat.h>
#import <cstdio>
#import <cstdlib>
#import <cstring>
#import <fstream>
#import <string>
#import "real_hooks.hpp"
#import "tunnel_transaction.hpp"

namespace {

// Unit-5 audit evidence: publish the session journal exactly once, in the
// shape network_plan.py mirrors, so the finance gate can compare snapshots
// against what was actually created and removed. 0644: root-owned but
// user-readable; nothing secret (routes, resolver addresses, lease UUIDs).
void write_journal(const char *path, const tunnel_transaction::TransactionResult &result) {
    auto quote = [](const std::string &text) {
        std::string escaped = "\"";
        for (char c : text) {
            if (c == '"' || c == '\\') escaped += '\\';
            if (static_cast<unsigned char>(c) < 0x20) escaped += ' ';
            else escaped += c;
        }
        escaped += '"';
        return escaped;
    };
    std::string out = "{\"lease\":";
    if (result.lease_valid) {
        out += "{\"sessionID\":" + quote(result.lease.session_id) +
               ",\"interface\":" + quote(result.lease.name) +
               ",\"ifindex\":" + std::to_string(result.lease.index) +
               ",\"handleIdentity\":" + quote(result.lease.handle_identity) + "}";
    } else {
        out += "null";
    }
    out += ",\"created\":[";
    for (std::size_t i = 0; i < result.created_ops.size(); ++i) {
        const auto &op = result.created_ops[i];
        out += (i ? "," : "") + std::string("{\"kind\":") + quote(op.kind) +
               ",\"key\":" + quote(op.key) + ",\"value\":" + op.value + "}";
    }
    out += "],\"cleanup\":{\"removals\":[";
    for (std::size_t i = 0; i < result.removed.size(); ++i)
        out += (i ? "," : "") + quote(result.removed[i]);
    out += "],\"issues\":[";
    for (std::size_t i = 0; i < result.issues.size(); ++i)
        out += (i ? "," : "") + quote(result.issues[i]);
    out += "]}}";
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) return;
    stream << out << "\n";
    stream.close();
    (void)::chmod(path, 0644);
}

}  // namespace

namespace {

using tunnel_transaction::Approval;
using tunnel_transaction::CodeExpectation;

std::optional<std::string> arg_value(int argc, char **argv, const std::string &name) {
    for (int i = 1; i + 1 < argc; i++) {
        if (name == argv[i]) return std::string(argv[i + 1]);
    }
    return std::nullopt;
}

// Unit-5 static route policy: staged root-side JSON
// {"staticRoutes": ["a.b.c.d/p", ...]}. Bounded, canonical IPv4, fail-closed:
// a malformed trusted file refuses to start the daemon.
std::optional<std::vector<std::string>> static_routes_from_file(const std::string &path) {
    const auto text = real_hooks::read_file_string(path);
    if (!text.has_value()) return std::nullopt;
    const auto decoded = plan_input::parse(
        reinterpret_cast<const uint8_t *>(text->data()), text->size());
    if (decoded.error != plan_input::Error::none || !decoded.value.is_object()) return std::nullopt;
    const auto *routes = decoded.value.find("staticRoutes");
    if (routes == nullptr || !routes->is_array() || routes->items.size() > 200) return std::nullopt;
    std::vector<std::string> out;
    for (const auto &item : routes->items) {
        if (!item.is_string()) return std::nullopt;
        const std::string &route = item.text;
        const auto slash = route.find('/');
        if (slash == std::string::npos || slash == 0 || slash + 1 >= route.size()) return std::nullopt;
        const std::string address = route.substr(0, slash);
        const std::string prefix = route.substr(slash + 1);
        if (prefix.size() > 2 || prefix.find_first_not_of("0123456789") != std::string::npos) return std::nullopt;
        const long long value = std::atoll(prefix.c_str());
        if (value < 1 || value > 32) return std::nullopt;
        for (char c : address) {
            if (c != '.' && (c < '0' || c > '9')) return std::nullopt;
        }
        if (address.find("..") != std::string::npos || address.front() == '.' || address.back() == '.') {
            return std::nullopt;
        }
        // Reserved range guard: RFC 2544 (198.18.0.0/15) and local LAN
        // (192.168.50.0/24) are structurally excluded from the
        // tunnel, belt and braces with the capture validator's reserved set.
        unsigned address_value = 0, octets = 1, number = 0;
        for (char c : address) {
            if (c == '.') { address_value = (address_value << 8) | number; number = 0; octets++; continue; }
            number = number * 10 + static_cast<unsigned>(c - '0');
        }
        address_value = (address_value << 8) | number;
        if (octets != 4) return std::nullopt;
        auto in_range = [&](unsigned base_ip, unsigned prefix_len) {
            const unsigned range_host_bits = 32 - prefix_len;
            const unsigned range_mask = range_host_bits ? (1U << range_host_bits) - 1U : 0U;
            return (address_value & ~range_mask) == base_ip;
        };
        if (in_range((198u << 24) | (18u << 16), 15) || in_range((192u << 24) | (168u << 16) | (50u << 8), 24)) {
            std::fprintf(stderr, "executor: static route %s excluded (reserved range)\n", route.c_str());
            continue;
        }
        out.push_back(route);
    }
    if (out.empty()) return std::nullopt;
    return out;
}

std::optional<plan_validator::Context> context_from_file(const std::string &path) {
    const auto text = real_hooks::read_file_string(path);
    if (!text.has_value()) return std::nullopt;
    const auto decoded = plan_input::parse(
        reinterpret_cast<const uint8_t *>(text->data()), text->size());
    if (decoded.error != plan_input::Error::none || !decoded.value.is_object()) {
        return std::nullopt;
    }
    plan_validator::Context context;
    const auto session = decoded.value.find("sessionID");
    const auto duration = decoded.value.find("durationSeconds");
    const auto port = decoded.value.find("remotePort");
    const auto suffixes = decoded.value.find("verifiedDNSSuffixes");
    if (!session || !session->is_string() || !duration || !duration->is_int() ||
        !port || !port->is_int() || !suffixes || !suffixes->is_array()) {
        return std::nullopt;
    }
    context.session_id = session->text;
    context.duration_seconds = duration->integer;
    context.remote_port = port->integer;
    for (const auto &item : suffixes->items) {
        if (!item.is_string()) return std::nullopt;
        context.verified_dns_suffixes.push_back(item.text);
    }
    return context;
}

std::optional<std::string> read_trimmed(const std::string &path) {
    const auto text = real_hooks::read_file_string(path);
    if (!text.has_value()) return std::nullopt;
    size_t end = text->size();
    while (end > 0 && (text->at(end - 1) == '\n' || text->at(end - 1) == ' ' ||
                       text->at(end - 1) == '\r')) {
        end--;
    }
    return text->substr(0, end);
}

}  // namespace

int main(int argc, char **argv) {
    setvbuf(stderr, nullptr, _IONBF, 0);  // launchd redirects stderr to a file
    ::signal(SIGPIPE, SIG_IGN);  // engine may drop first; marker write reports EPIPE
    const auto allowed_uid_text = arg_value(argc, argv, "--allowed-uid");
    const auto cdhash_file = arg_value(argc, argv, "--engine-cdhash-file");
    const auto context_file = arg_value(argc, argv, "--context-file");
    const auto identity_file = arg_value(argc, argv, "--identity-file");
    if (!allowed_uid_text.has_value() || !context_file.has_value() || !identity_file.has_value()) {
        std::fputs("usage: executor --allowed-uid <uid> --context-file <json> "
                   "[--engine-cdhash-file <hexfile>] --identity-file <uuidfile>\n",
                   stderr);
        return 64;
    }
    const long long uid = std::strtoll(allowed_uid_text->c_str(), nullptr, 10);
    if (uid < 0 || uid > 1000000) {
        std::fputs("implausible uid\n", stderr);
        return 64;
    }
    const auto static_file = arg_value(argc, argv, "--static-routes-file");
    auto context = context_from_file(*context_file);
    if (!context.has_value()) {
        std::fputs("invalid staged context\n", stderr);
        return 65;
    }
    if (static_file.has_value()) {
        const auto static_routes = static_routes_from_file(*static_file);
        if (!static_routes.has_value()) {
            std::fputs("invalid staged static routes\n", stderr);
            return 65;
        }
        context->static_routes = *static_routes;
        std::fprintf(stderr, "executor: %zu staged static routes\n", static_routes->size());
    }
    CodeExpectation engine;
    engine.uid = static_cast<uid_t>(uid);
    engine.identifier = "local.szu.securelink.executor-engine";
    if (cdhash_file.has_value()) {
        const auto hex = read_trimmed(*cdhash_file);
        // CDHash is SHA-1: exactly 40 lowercase hex characters.
        if (!hex.has_value() || hex->size() != 40) {
            std::fputs("invalid staged engine cdhash\n", stderr);
            return 65;
        }
        engine.cdhash_hex = *hex;
    }
    const auto identity = read_trimmed(*identity_file);
    if (!identity.has_value() || !plan_validator::valid_uuid(*identity)) {
        std::fputs("invalid staged lease identity\n", stderr);
        return 65;
    }

    int listen_fd = -1;
    const auto standalone_path = arg_value(argc, argv, "--socket-path");
    if (standalone_path.has_value()) {
        // Standalone (non-launchd) mode for offline integration tests: same
        // policy, a self-created unix socket, no privileges required.
        ::unlink(standalone_path->c_str());
        listen_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        std::strncpy(address.sun_path, standalone_path->c_str(),
                     sizeof(address.sun_path) - 1);
        if (::bind(listen_fd, reinterpret_cast<const sockaddr *>(&address),
                   sizeof(address)) != 0 ||
            ::listen(listen_fd, 4) != 0) {
            std::fputs("standalone bind failed\n", stderr);
            return 71;
        }
    } else {
        int *sockets = nullptr;
        size_t count = 0;
        if (launch_activate_socket("Listeners", &sockets, &count) != 0 || count == 0 || !sockets) {
            std::fputs("no launchd socket\n", stderr);
            return 71;
        }
        listen_fd = sockets[0];
    }

    while (true) {
        const int connection = ::accept(listen_fd, nullptr, nullptr);
        if (connection < 0) {
            if (errno == EINTR) continue;
            break;
        }
        // Ready marker: credential lookups on the engine side identify launchd
        // until this accept completes. One byte, transport level, not a frame.
        const uint8_t ready = 0x52;
        (void)::write(connection, &ready, 1);
        real_hooks::DaemonNet net;
        net.engine_expectation = engine;
        (void)listen_fd;
        real_hooks::DaemonExecutor executor;
        executor.set_lease_identity(*identity);
        tunnel_transaction::Hooks<real_hooks::DaemonNet, real_hooks::DaemonExecutor> hooks{&net, &executor};
        tunnel_transaction::Approval approval;
        approval.context = *context;
        approval.peer = engine;
        approval.duration_ms = static_cast<uint64_t>(context->duration_seconds) * 1000;
        const auto result =
            tunnel_transaction::run_transaction(connection, approval, hooks);
        std::fprintf(stderr,
                     "executor session: phase=%s applied=%zu removed=%zu issues=%zu\n",
                     result.phase.c_str(), result.applied.size(), result.removed.size(),
                     result.issues.size());
        if (result.engine_authenticated) {
            write_journal("/var/log/szu-executor-journal.json", result);
        }
        for (const auto &single : result.issues) {
            std::fprintf(stderr, "executor issue: %s\n", single.c_str());
        }
        ::close(connection);
        if (!result.engine_authenticated && !standalone_path.has_value()) {
            continue;
        }
        // One session per instance: exit so launchd respawns cleanly on the
        // next connection (KeepAlive=false, socket stays with launchd).
        return 0;
    }
    return 0;
}
