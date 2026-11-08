// Merged data-session engine: one binary, one audited identity. In
// --probe-transaction mode it is the bounded transaction client, unchanged in
// behavior. In --data-session mode the OpenVPN3 session and the executor
// transaction run in this process: the handshake probe captures the server
// network plan, tun_builder_establish submits it through the executor
// transaction, the delivered utun fd becomes the session TUN, and an
// in-tunnel ping is recorded in the receipt. The ping target is a fixed
// numeric address argument; nothing here browses or submits business data.
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>
#import <sys/socket.h>
#import <sys/un.h>
#import <sys/wait.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <poll.h>
#import <spawn.h>
#import <sys/resource.h>
#import <unistd.h>
#import <algorithm>
#import <array>
#import <atomic>
#import <cctype>
#import <chrono>
#import <cerrno>
#import <csignal>
#import <cstdio>
#import <cstring>
#import <mutex>
#import <string>
#import <thread>
#import "probe.hpp"
#import "probe_input.hpp"
#import "engine_transaction.hpp"
#import "plan_input.hpp"
#import "real_hooks.hpp"

extern char **environ;

namespace {

constexpr const char *kVersion = "data-engine-1";

std::atomic<bool> g_stop_requested{false};

extern "C" void handle_stop_signal(int) {
    g_stop_requested.store(true);
}

struct PingOutcome {
    bool ran = false;
    int exit_status = -1;
    long transmitted = -1;
    long received = -1;
};

struct DigOutcome {
    bool ran = false;
    int exit_status = -1;
    std::string status;     // e.g. NOERROR, SERVFAIL; empty when not run
    long answers = -1;
    std::vector<std::string> addresses;
};

// Extracts IPv4 A-record targets from the ";; ANSWER SECTION:" of dig output.
bool parse_dig_a_records(const std::string &output, std::vector<std::string> *addresses) {
    if (!addresses) return false;
    addresses->clear();
    const std::string marker = ";; ANSWER SECTION:";
    const auto section_at = output.find(marker);
    if (section_at == std::string::npos) return true;
    std::size_t pos = output.find('\n', section_at);
    if (pos == std::string::npos) return true;
    pos++;
    while (pos < output.size()) {
        const auto next_nl = output.find('\n', pos);
        std::string line = output.substr(pos, next_nl == std::string::npos ? std::string::npos : next_nl - pos);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || (line.size() >= 2 && line[0] == ';' && line[1] == ';')) break;
        if (line[0] != ';') {
            std::vector<std::string> tokens;
            std::size_t i = 0;
            while (i < line.size()) {
                while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) i++;
                if (i >= line.size()) break;
                std::size_t j = i;
                while (j < line.size() && line[j] != ' ' && line[j] != '\t') j++;
                tokens.push_back(line.substr(i, j - i));
                i = j;
            }
            if (tokens.size() >= 5 && tokens[tokens.size() - 2] == "A" && tokens[tokens.size() - 3] == "IN") {
                const std::string &candidate = tokens.back();
                in_addr addr{};
                if (candidate.size() <= 15 && ::inet_pton(AF_INET, candidate.c_str(), &addr) == 1) {
                    if (std::find(addresses->begin(), addresses->end(), candidate) == addresses->end() &&
                        addresses->size() < 32) {
                        addresses->push_back(candidate);
                    }
                }
            }
        }
        if (next_nl == std::string::npos) break;
        pos = next_nl + 1;
    }
    return true;
}

// Returns true if ip is in a reserved range (loopback, link-local, multicast,
// RFC 2544 198.18.0.0/15, local LAN 192.168.50.0/24) or already covered
// by the staged campus aggregate subnets (172.31.0.0/16, 192.168.240.0/20,
// 210.39.0.0/16, 10.10.27.0/24, 1.1.96.1/32).
bool is_covered_or_reserved_ipv4(const std::string &ip) {
    in_addr parsed{};
    if (::inet_pton(AF_INET, ip.c_str(), &parsed) != 1) return true;
    const uint32_t host = ntohl(parsed.s_addr);
    auto in_cidr = [&](uint32_t a, uint32_t b, uint32_t c, uint32_t d, int prefix) {
        const uint32_t base = (a << 24) | (b << 16) | (c << 8) | d;
        const uint32_t mask = prefix == 0 ? 0U : (~0U << (32 - prefix));
        return (host & mask) == (base & mask);
    };
    if (in_cidr(0, 0, 0, 0, 8) || in_cidr(127, 0, 0, 0, 8) ||
        in_cidr(169, 254, 0, 0, 16) || in_cidr(198, 18, 0, 0, 15) ||
        in_cidr(192, 168, 50, 0, 24) || in_cidr(224, 0, 0, 0, 4) ||
        in_cidr(240, 0, 0, 0, 4)) {
        return true;
    }
    if (in_cidr(172, 31, 0, 0, 16) || in_cidr(192, 168, 240, 0, 20) ||
        in_cidr(210, 39, 0, 0, 16) || in_cidr(10, 10, 27, 0, 24) ||
        in_cidr(1, 1, 96, 1, 32)) {
        return true;
    }
    return false;
}

// Parses the header line "flags: ...; status: NOERROR; ..." plus the
// ";; ANSWER SECTION"-preceding ";; ANSWER: N" counter.
bool parse_dig_summary(const std::string &output, std::string *status, long *answers) {
    const std::string status_marker = "status: ";
    const auto status_at = output.find(status_marker);
    if (status_at == std::string::npos) return false;
    // Real dig separates the status from ", id: N" with a comma.
    std::size_t end = output.size();
    for (const char stop : {',', ';', '\n'}) {
        const auto at = output.find(stop, status_at + status_marker.size());
        if (at != std::string::npos && at < end) end = at;
    }
    if (end >= output.size()) return false;
    *status = output.substr(status_at + status_marker.size(), end - status_at - status_marker.size());
    while (!status->empty() && (status->back() == ' ' || status->back() == '\r')) status->pop_back();
    if (status->empty() || status->size() > 32) return false;
    for (char c : *status) {
        if (!(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '-' && c != '_') return false;
    }
    const std::string answer_marker = "ANSWER: ";
    const auto answer_at = output.find(answer_marker);
    if (answer_at == std::string::npos) return false;
    std::size_t start = answer_at + answer_marker.size();
    std::size_t digits_end = start;
    while (digits_end < output.size() && isdigit(static_cast<unsigned char>(output[digits_end]))) digits_end++;
    if (digits_end == start) return false;
    try {
        *answers = std::stol(output.substr(start, digits_end - start));
    } catch (...) { return false; }
    return *answers >= 0;
}

// Valid label/label-set check mirroring the plan authority's domain rule.
bool valid_query_name(const std::string &value) {
    if (value.empty() || value.size() > 253) return false;
    size_t start = 0;
    while (true) {
        const size_t at = value.find('.', start);
        const std::string part = value.substr(start, at == std::string::npos ? std::string::npos : at - start);
        if (part.empty() || part.size() > 63) return false;
        const char first = part.front(), last = part.back();
        auto alnum = [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
        };
        if (!alnum(first) || !alnum(last)) return false;
        for (char c : part) {
            if (!alnum(c) && c != '-') return false;
        }
        if (at == std::string::npos) return true;
        start = at + 1;
    }
}

bool parse_resolve_domains_csv(const std::string &csv, std::vector<std::string> *domains) {
    if (!domains) return false;
    domains->clear();
    if (csv.empty() || csv.size() > 2048) return false;
    std::size_t start = 0;
    while (true) {
        const std::size_t comma = csv.find(',', start);
        const std::string item = csv.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
        if (!valid_query_name(item)) return false;
        if (std::find(domains->begin(), domains->end(), item) == domains->end()) {
            if (domains->size() >= 32) return false;
            domains->push_back(item);
        }
        if (comma == std::string::npos) return true;
        start = comma + 1;
    }
}

DigOutcome run_dig(const std::string &server, const std::string &name) {
    DigOutcome outcome;
    if (server.empty() || name.empty()) return outcome;
    const std::string at_server = "@" + server;
    std::vector<std::string> argv_strings = {"/usr/bin/dig", at_server, name, "+time=5", "+tries=1"};
    std::vector<char *> argv;
    for (auto &item : argv_strings) argv.push_back(item.data());
    argv.push_back(nullptr);
    int stdout_pipe[2];
    if (::pipe(stdout_pipe) != 0) return outcome;
    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) { ::close(stdout_pipe[0]); ::close(stdout_pipe[1]); return outcome; }
    posix_spawn_file_actions_adddup2(&actions, stdout_pipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, stdout_pipe[0]);
    posix_spawn_file_actions_addclose(&actions, stdout_pipe[1]);
    pid_t child = -1;
    const int spawned = ::posix_spawn(&child, argv_strings[0].data(), &actions, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    ::close(stdout_pipe[1]);
    if (spawned != 0) { ::close(stdout_pipe[0]); return outcome; }
    std::string output;
    char buffer[4096];
    const auto read_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    for (;;) {
        pollfd wanted = {stdout_pipe[0], POLLIN, 0};
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            read_deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) break;
        if (::poll(&wanted, 1, static_cast<int>(std::min<long long>(remaining, 500))) <= 0) continue;
        const ssize_t got = ::read(stdout_pipe[0], buffer, sizeof(buffer));
        if (got <= 0) break;
        output.append(buffer, static_cast<std::size_t>(got));
        if (output.size() > 64 * 1024) break;
    }
    ::close(stdout_pipe[0]);
    int status = 0;
    const auto kill_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (::waitpid(child, &status, WNOHANG) <= 0) {
        if (std::chrono::steady_clock::now() >= kill_deadline) {
            ::kill(child, SIGKILL);
            (void)::waitpid(child, &status, 0);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    outcome.ran = true;
    if (WIFEXITED(status)) outcome.exit_status = WEXITSTATUS(status);
    (void)parse_dig_summary(output, &outcome.status, &outcome.answers);
    (void)parse_dig_a_records(output, &outcome.addresses);
    return outcome;
}

// Parses the fixed "N packets transmitted, M packets received" summary line.
bool parse_ping_summary(const std::string &output, long *transmitted, long *received) {
    const std::string sent_marker = " packets transmitted, ";
    const std::string recv_marker = " packets received";
    const auto sent = output.find(sent_marker);
    if (sent == std::string::npos) return false;
    const auto received_at = output.find(recv_marker, sent + sent_marker.size());
    if (received_at == std::string::npos) return false;
    std::size_t start = sent;
    while (start > 0 && isdigit(static_cast<unsigned char>(output[start - 1]))) start--;
    std::size_t mid = received_at;
    while (mid > sent + sent_marker.size() && isdigit(static_cast<unsigned char>(output[mid - 1]))) mid--;
    try {
        *transmitted = std::stol(output.substr(start, sent - start));
        *received = std::stol(output.substr(mid, received_at - mid));
    } catch (...) { return false; }
    return *transmitted >= 0 && *received >= 0 && *received <= *transmitted;
}

PingOutcome run_ping(const std::string &peer, int count) {
    PingOutcome outcome;
    if (peer.empty() || count < 1 || count > 10) return outcome;
    const int overall_seconds = std::min(30, count + 4);
    const std::string count_text = std::to_string(count);
    const std::string timeout_text = std::to_string(overall_seconds);
    // Fixed argv: bound count, one-second spacing, whole-run timeout. The
    // target is validated as a numeric IPv4 address by the caller.
    std::vector<std::string> argv_strings = {"/sbin/ping", "-c", count_text, "-i", "1", "-t", timeout_text, peer};
    std::vector<char *> argv;
    for (auto &item : argv_strings) argv.push_back(item.data());
    argv.push_back(nullptr);
    int stdout_pipe[2];
    if (::pipe(stdout_pipe) != 0) return outcome;
    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) { ::close(stdout_pipe[0]); ::close(stdout_pipe[1]); return outcome; }
    posix_spawn_file_actions_adddup2(&actions, stdout_pipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, stdout_pipe[0]);
    posix_spawn_file_actions_addclose(&actions, stdout_pipe[1]);
    pid_t child = -1;
    const int spawned = ::posix_spawn(&child, argv_strings[0].data(), &actions, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    ::close(stdout_pipe[1]);
    if (spawned != 0) { ::close(stdout_pipe[0]); return outcome; }
    std::string output;
    char buffer[4096];
    const auto read_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(overall_seconds + 10);
    for (;;) {
        pollfd wanted = {stdout_pipe[0], POLLIN, 0};
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            read_deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) break;
        if (::poll(&wanted, 1, static_cast<int>(std::min<long long>(remaining, 500))) <= 0) continue;
        const ssize_t got = ::read(stdout_pipe[0], buffer, sizeof(buffer));
        if (got <= 0) break;
        output.append(buffer, static_cast<std::size_t>(got));
        if (output.size() > 64 * 1024) break;
    }
    ::close(stdout_pipe[0]);
    int status = 0;
    const auto kill_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (::waitpid(child, &status, WNOHANG) <= 0) {
        if (std::chrono::steady_clock::now() >= kill_deadline) {
            ::kill(child, SIGKILL);
            (void)::waitpid(child, &status, 0);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    outcome.ran = true;
    if (WIFEXITED(status)) outcome.exit_status = WEXITSTATUS(status);
    (void)parse_ping_summary(output, &outcome.transmitted, &outcome.received);
    return outcome;
}

int receipt(const char *reason, int code, const HandshakeProbe *probe = nullptr,
            const engine_transaction::EngineResult &transaction = {},
            const PingOutcome &ping = {}, bool disconnectSent = false,
            uint64_t heartbeats = 0, long long holdMs = 0, bool connectCalled = false,
            const DigOutcome &dig = {}, const std::string &digServer = "",
            const std::string &digName = "", int ctrlPushes = 0, int ctrlUpdatesSent = 0,
            int ctrlUpdatesFailed = 0, const std::vector<std::string> &ctrlRoutes = {}) {
    std::string planJSON = "null";
    if (probe && probe->capturePlan && probe->plan.requested()) {
        planJSON = probe->plan.json();
        if (planJSON.size() > 48 * 1024) { planJSON = "null"; reason = "plan-limit"; code = 3; }
    }
    std::printf("{\"mode\":\"bounded-data-session\",\"engine\":\"%s\",\"reason\":\"%s\",", kVersion, reason);
    std::printf("\"phase\":\"%s\",\"interface\":\"%s\",\"fdAccepted\":%s,", transaction.phase.c_str(),
                transaction.tunnel_interface.c_str(), transaction.fd_accepted ? "true" : "false");
    std::printf("\"connectCalled\":%s,\"socketObserved\":%s,\"tunnelSetupRequested\":%s,\"tunnelStarted\":%s,",
                connectCalled ? "true" : "false", probe && probe->socketObserved ? "true" : "false",
                probe && probe->tunnelSetupRequested ? "true" : "false",
                transaction.fd_accepted ? "true" : "false");
    std::printf("\"connectedInDataMode\":%s,\"pingRan\":%s,\"pingExitStatus\":%d,\"pingTransmitted\":%ld,\"pingReceived\":%ld,",
                probe && probe->connectedInDataMode.load() ? "true" : "false",
                ping.ran ? "true" : "false", ping.exit_status, ping.transmitted, ping.received);
    // dig fields are validated tokens (status charset, numeric server,
    // domain-shaped name); safe to emit unescaped.
    std::printf("\"digRan\":%s,\"digExitStatus\":%d,\"digStatus\":\"%s\",\"digAnswers\":%ld,\"digServer\":\"%s\",\"digName\":\"%s\",",
                dig.ran ? "true" : "false", dig.exit_status, dig.status.c_str(), dig.answers,
                digServer.c_str(), digName.c_str());
    // Ctrl push evidence: numeric addresses with prefix lengths only.
    std::printf("\"ctrlPushesObserved\":%d,\"ctrlUpdatesSent\":%d,\"ctrlUpdatesFailed\":%d,\"ctrlRoutesPushed\":[",
                ctrlPushes, ctrlUpdatesSent, ctrlUpdatesFailed);
    for (std::size_t index = 0; index < ctrlRoutes.size() && index < 64; ++index)
        std::printf("%s\"%s\"", index ? "," : "", ctrlRoutes[index].c_str());
    std::printf("],");
    std::printf("\"planCaptureRequested\":%s,\"planComplete\":%s,\"plan\":%s,",
                probe && probe->capturePlan ? "true" : "false",
                probe && probe->capturePlan && probe->plan.isComplete() && planJSON != "null" ? "true" : "false",
                planJSON.c_str());
    std::printf("\"holdMs\":%lld,\"heartbeatsSent\":%llu,\"disconnectSent\":%s,", holdMs,
                static_cast<unsigned long long>(heartbeats), disconnectSent ? "true" : "false");
    std::printf("\"deadlineReached\":%s,\"unexpectedConnected\":%s,\"eventsDropped\":%s,\"events\":[",
                probe && probe->deadlineReached ? "true" : "false",
                probe && probe->unexpectedConnected ? "true" : "false",
                probe && probe->eventsDropped ? "true" : "false");
    if (probe) for (std::size_t index = 0; index < probe->events.size(); ++index)
        std::printf("%s\"%s\"", index ? "," : "", probe->events[index]);
    std::puts("]}");
    return code;
}

class EngineNet {
public:
    bool authenticate(int fd, const tunnel_transaction::CodeExpectation &expected) {
        // With launchd socket activation the credential lookup identifies
        // launchd until the daemon accepts; retry under a short deadline.
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < deadline) {
            if (authenticate_once(fd, expected)) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        return authenticate_once(fd, expected);
    }
    bool authenticate_once(int fd, const tunnel_transaction::CodeExpectation &expected) {
        xucred credential{};
        socklen_t size = sizeof(credential);
        if (::getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, &credential, &size) != 0 ||
            credential.cr_uid != expected.uid) return false;
        audit_token_t token{};
        size = sizeof(token);
        if (::getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size) != 0) return false;
        CFDataRef audit = CFDataCreate(nullptr, reinterpret_cast<const UInt8 *>(&token), sizeof(token));
        if (!audit) return false;
        const void *key = kSecGuestAttributeAudit;
        const void *value = audit;
        CFDictionaryRef attributes = CFDictionaryCreate(nullptr, &key, &value, 1,
                                                        &kCFTypeDictionaryKeyCallBacks,
                                                        &kCFTypeDictionaryValueCallBacks);
        SecCodeRef code = nullptr;
        const OSStatus status = attributes
            ? SecCodeCopyGuestWithAttributes(nullptr, attributes, kSecCSDefaultFlags, &code)
            : errSecAllocate;
        if (attributes) CFRelease(attributes);
        CFRelease(audit);
        if (status != errSecSuccess || !code) return false;
        SecStaticCodeRef static_code = nullptr;
        CFDictionaryRef information = nullptr;
        bool valid = SecCodeCopyStaticCode(code, kSecCSDefaultFlags, &static_code) == errSecSuccess &&
                     SecCodeCopySigningInformation(static_code, kSecCSSigningInformation,
                                                   &information) == errSecSuccess;
        if (valid) {
            const auto identifier = static_cast<CFStringRef>(
                CFDictionaryGetValue(information, kSecCodeInfoIdentifier));
            valid = identifier && CFStringCompare(
                identifier, CFSTR("local.szu.securelink.executor"), kCFCompareCaseInsensitive) == kCFCompareEqualTo;
        }
        if (information) CFRelease(information);
        if (static_code) CFRelease(static_code);
        CFRelease(code);
        return valid;
    }
    static bool send(int fd, const network_helper::Bytes &bytes) {
        return real_hooks::write_all_fd(fd, bytes);
    }
    static bool wait_readable(int fd, int timeout_ms) {
        pollfd wanted = {fd, POLLIN, 0};
        return ::poll(&wanted, 1, timeout_ms) > 0;
    }
    static network_helper::Received receive_fd(int fd) {
        return network_helper::receive_chunk(fd, true);
    }
    static bool utun_name(int fd, std::string *out) {
        char buffer[IFNAMSIZ]{};
        socklen_t size = sizeof(buffer);
        if (::getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, buffer, &size) != 0) return false;
        *out = buffer;
        return true;
    }
    static uint64_t now_ms() { return real_hooks::steady_ms(); }
};

std::optional<std::string> arg_value(int argc, char **argv, const std::string &name) {
    for (int i = 1; i + 1 < argc; i++) {
        if (name == argv[i]) return std::string(argv[i + 1]);
    }
    return std::nullopt;
}

// Connects to the executor socket and consumes the daemon's one-byte ready
// marker so credential lookups resolve against the daemon process.
int connect_executor(const std::string &socket_path, std::string *error) {
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { if (error) *error = "socket"; return -1; }
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (socket_path.empty() || socket_path.size() >= sizeof(address.sun_path)) {
        if (error) *error = "socket-path";
        ::close(fd);
        return -1;
    }
    std::strncpy(address.sun_path, socket_path.c_str(), sizeof(address.sun_path) - 1);
    if (::connect(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
        if (error) *error = std::string("connect:") + std::strerror(errno);
        ::close(fd);
        return -1;
    }
    pollfd wanted = {fd, POLLIN, 0};
    if (::poll(&wanted, 1, 5000) <= 0) {
        if (error) *error = "no ready marker";
        ::close(fd);
        return -1;
    }
    uint8_t marker = 0;
    const ssize_t got = ::read(fd, &marker, 1);
    if (got != 1 || marker != 0x52) {
        if (error) *error = "bad ready marker";
        ::close(fd);
        return -1;
    }
    return fd;
}

int probeTransaction(int argc, char **argv) {
    ::signal(SIGPIPE, SIG_IGN);  // daemon may close first; writes report EPIPE
    const auto socket_path = arg_value(argc, argv, "--socket");
    const auto plan_path = arg_value(argc, argv, "--plan");
    const auto context_path = arg_value(argc, argv, "--context");
    const auto identity_path = arg_value(argc, argv, "--identity");
    const auto update_path = arg_value(argc, argv, "--update-plan");
    long long hold_seconds = 0, update_delay = 0;
    for (int i = 1; i + 1 < argc; i++) {
        if (std::string(argv[i]) == "--hold-seconds") hold_seconds = std::atoll(argv[i + 1]);
        if (std::string(argv[i]) == "--update-delay-seconds") update_delay = std::atoll(argv[i + 1]);
    }
    if (!socket_path.has_value() || !plan_path.has_value() || !context_path.has_value() ||
        !identity_path.has_value()) {
        std::fputs("usage: engine --probe-transaction --socket <path> --plan <json> "
                   "--context <json> --identity <uuidfile> [--update-plan <json> "
                   "--update-delay-seconds N]\n", stderr);
        return 64;
    }
    const auto plan = real_hooks::read_file_string(*plan_path);
    const auto identity = real_hooks::read_file_string(*identity_path);
    if (!plan.has_value() || !identity.has_value()) {
        std::fputs("cannot read staged plan or identity\n", stderr);
        return 65;
    }
    const int fd = connect_executor(*socket_path, nullptr);
    if (fd < 0) {
        std::fprintf(stderr, "engine connect failed\n");
        return 1;
    }
    engine_transaction::EngineApproval approval;
    approval.binding.session.fill(0xB7);
    approval.binding.challenge.fill(0x4C);
    CC_SHA256(plan->data(), static_cast<CC_LONG>(plan->size()),
              approval.binding.plan_digest.data());
    approval.peer.uid = 0;
    approval.plan = *plan;
    approval.duration_ms = 900000;
    approval.hold_ms = static_cast<uint64_t>(hold_seconds) * 1000;

    engine_transaction::EngineHooks<EngineNet> hooks{EngineNet{}};
    std::fprintf(stderr, "engine: entering transaction\n");
    int updates_sent = 0;
    std::string phase;
    std::string interface_name;
    if (!update_path.has_value()) {
        const auto result = engine_transaction::run_engine(fd, approval, hooks);
        phase = result.phase;
        interface_name = result.tunnel_interface;
        std::fprintf(stderr, "engine: transaction returned phase=%s\n", result.phase.c_str());
    } else {
        // Unit-4 machinery probe: hold with the pump, submit one update delta
        // mid-hold, then disconnect so the daemon converges cleanup.
        const auto update_bytes = real_hooks::read_file_string(*update_path);
        if (!update_bytes.has_value() || update_delay < 1 || update_delay >= hold_seconds) {
            std::fputs("cannot read update plan or bad delay\n", stderr);
            ::close(fd);
            return 65;
        }
        uint64_t sequence = 0;
        const auto handshake = engine_transaction::engine_handshake(fd, approval, hooks, sequence);
        phase = handshake.phase;
        interface_name = handshake.tunnel_interface;
        if (!handshake.fd_accepted) {
            std::fprintf(stderr, "engine: handshake phase=%s\n", handshake.phase.c_str());
            ::close(fd);
            std::printf("{\"phase\":\"%s\",\"interface\":\"%s\",\"fdAccepted\":false,\"updatesSent\":0}\n",
                        phase.c_str(), interface_name.c_str());
            return 1;
        }
        engine_transaction::EnginePump pump;
        pump.fd = fd;
        pump.binding = approval.binding;
        pump.sequence = sequence;
        pump.start(hooks.net, 1000);
        std::this_thread::sleep_for(std::chrono::seconds(update_delay));
        const bool sent = pump.send_update(hooks.net, *update_bytes);
        updates_sent = sent ? 1 : 0;
        std::fprintf(stderr, "engine: update sent=%d\n", sent ? 1 : 0);
        std::this_thread::sleep_for(std::chrono::seconds(
            std::max<long long>(1, hold_seconds - update_delay)));
        pump.stop();
        if (!pump.disconnect(hooks.net)) phase = "cleanup";
    }
    std::printf("{\"phase\":\"%s\",\"interface\":\"%s\",\"fdAccepted\":%s,\"updatesSent\":%d}\n",
                phase.c_str(), interface_name.c_str(),
                phase == "active" && !interface_name.empty() ? "true" : "false", updates_sent);
    ::close(fd);
    return phase == "active" && !interface_name.empty() ? 0 : 1;
}

int selfTest() {
    // The probe/parser semantics are pinned by the handshake binary; this
    // suite covers what the merged engine adds: plan byte compatibility with
    // the daemon-side parser, ping summary parsing, and the shared input
    // contract. No sockets, no network, no privileges.
    HandshakeProbe probe(false, false, false, true);
    if (!probe.tun_builder_new() || !probe.capture_domain_options(openvpn::OptionList{})
        || !probe.tun_builder_set_layer(3)
        || !probe.tun_builder_set_remote_address("192.0.2.1", false)
        || !probe.tun_builder_add_address("192.0.2.2", 30, "192.0.2.1", false, false)
        || !probe.tun_builder_add_route("192.0.2.128", 25, -1, false)
        || !probe.tun_builder_set_mtu(1400)) return 3;
    (void)probe.tun_builder_establish();
    if (!probe.plan.isComplete()) return 3;
    // The exact bytes this engine submits must parse on the daemon side.
    const std::string planBytes = probe.plan.json();
    const auto decoded = plan_input::parse(
        reinterpret_cast<const uint8_t *>(planBytes.data()), planBytes.size());
    if (decoded.error != plan_input::Error::none || !decoded.value.is_object()) return 3;
    long transmitted = -1, received = -1;
    if (!parse_ping_summary("3 packets transmitted, 3 packets received, 0.0% packet loss",
                            &transmitted, &received) || transmitted != 3 || received != 3) return 3;
    transmitted = -1; received = -1;
    if (!parse_ping_summary("10 packets transmitted, 7 packets received, 30.0% packet loss",
                            &transmitted, &received) || transmitted != 10 || received != 7) return 3;
    transmitted = -1; received = -1;
    if (parse_ping_summary("ping: cannot resolve", &transmitted, &received)) return 3;
    if (transmitted != -1 || received != -1) return 3;
    // Shared stdin contract: accept the exact probe shape, reject strangers.
    probe_input::Parsed parsed;
    const std::string good = R"({"config":"client\n","username":"u","password":"p",)"
                             R"("peerInfo":{"UV_CODE":"t"},"vendorConfusion":true})";
    if (!probe_input::parse(good, parsed) || !parsed.vendorConfusion
        || parsed.peerInfo.size() != 1 || parsed.profile.empty()) return 3;
    probe_input::Parsed rejected;
    if (probe_input::parse(R"({"config":"c","username":"u","password":"p","SECRET":"x"})", rejected)) return 3;
    // dig summary parsing: fixed tokens only, strict charset on status.
    std::string dig_status;
    long dig_answers = -1;
    const std::string dig_output =
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345\n"
        ";; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n\n"
        ";; ANSWER SECTION:\nszu.edu.cn. 300 IN CNAME www1.szu.edu.cn.\nwww1.szu.edu.cn. 300 IN A 192.0.2.10\n";
    if (!parse_dig_summary(dig_output, &dig_status, &dig_answers) || dig_status != "NOERROR" ||
        dig_answers != 2) return 3;
    std::vector<std::string> dig_addrs;
    if (!parse_dig_a_records(dig_output, &dig_addrs) || dig_addrs.size() != 1 ||
        dig_addrs[0] != "192.0.2.10") return 3;
    dig_status.clear(); dig_answers = -1;
    if (parse_dig_summary(";; communications error: connection timed out", &dig_status, &dig_answers)) return 3;
    if (!dig_status.empty() || dig_answers != -1) return 3;
    dig_status.clear(); dig_answers = -1;
    if (!parse_dig_summary(";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1\n"
                           ";; flags:; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0\n",
                           &dig_status, &dig_answers) || dig_status != "SERVFAIL" || dig_answers != 0) return 3;
    // Query-name validation mirrors the plan authority's domain rule.
    if (!valid_query_name("szu.edu.cn") || !valid_query_name("a-b.example") ||
        valid_query_name("") || valid_query_name(".example") || valid_query_name("a..b") ||
        valid_query_name("-example") || valid_query_name("exa mple") ||
        valid_query_name(std::string(254, 'a'))) return 3;
    std::vector<std::string> csv_domains;
    if (!parse_resolve_domains_csv("www1.szu.edu.cn,authserver.szu.edu.cn,ehall.szu.edu.cn,cwpt.szu.edu.cn", &csv_domains) ||
        csv_domains.size() != 4 || csv_domains[3] != "cwpt.szu.edu.cn") return 3;
    if (parse_resolve_domains_csv("", &csv_domains) ||
        parse_resolve_domains_csv("bad domain,szu.edu.cn", &csv_domains)) return 3;
    if (!is_covered_or_reserved_ipv4("198.18.0.10") ||
        !is_covered_or_reserved_ipv4("172.31.132.60") ||
        !is_covered_or_reserved_ipv4("210.39.3.155") ||
        !is_covered_or_reserved_ipv4("192.168.247.6") ||
        is_covered_or_reserved_ipv4("172.22.10.5")) return 3;
    // Unit-4 push parsing: narrow route directives only, everything else
    // fails closed.
    std::vector<securelink::ctrl::PushRouteIntent> pushed;
    // Directives are comma separated, arguments inside a directive are space
    // separated (same grammar as the vendor ctrl rows).
    if (!parse_push_update_routes("route 10.10.27.0 255.255.255.0", pushed) ||
        pushed.size() != 1 || pushed[0].address != "10.10.27.0" || pushed[0].prefix != 24) return 3;
    pushed.clear();
    if (!parse_push_update_routes("route 10.10.27.0 255.255.255.0,route 192.0.2.7 255.255.255.255", pushed) ||
        pushed.size() != 2 || pushed[1].prefix != 32) return 3;
    pushed.clear();
    for (const std::string &bad : std::vector<std::string>{
             "route 10.10.27.0 255.255.255.0 10.10.27.1",   // gateway form
             "dhcp-option DNS 192.0.2.53",                   // non-route directive
             "route 10.10.27.1 255.255.255.0",               // host bits set
             "route 10.10.27.0 3.255.255.255",               // non-contiguous mask
             "route 10.10.27.0 255.255.255.0,route 10.10.27.0 255.255.255.0",  // duplicate
             "route,10.10.27.0,255.255.255.0",               // comma args are separate directives
             "",
             "PUSH_REPLY route 10.10.27.0 255.255.255.0",
         }) {
        pushed.clear();
        if (parse_push_update_routes(bad, pushed)) return 3;
    }
    std::printf("{\"mode\":\"data-engine-self-test\",\"passed\":true}\n");
    return 0;
}

}  // namespace

int main(int argc, char **argv) {
    if (argc == 2 && std::strcmp(argv[1], "--self-test") == 0) return selfTest();
    const pid_t owner = getppid();
    const pid_t group = owner > 1 ? getpgid(owner) : -1;
    if (group <= 0 || setpgid(0, group) != 0) return receipt("invalid-input", 3);
    alarm(1200); // finance observation holds need up to twenty minutes of wall clock
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1190);
    const rlimit noCore = {0, 0}; setrlimit(RLIMIT_CORE, &noCore);
    @autoreleasepool {
        if (argc >= 2 && std::strcmp(argv[1], "--probe-transaction") == 0) return probeTransaction(argc, argv);
        if (argc < 2 || std::strcmp(argv[1], "--data-session") != 0) return receipt("invalid-input", 3);
        // --data-session --socket P --hold-ms N --ping-peer A.B.C.D [--ping-count N]
        const auto socket_path = arg_value(argc, argv, "--socket");
        const auto peer_arg = arg_value(argc, argv, "--ping-peer");
        long long hold_ms = 0;
        for (int i = 1; i + 1 < argc; i++) {
            if (std::string(argv[i]) == "--hold-ms") hold_ms = std::atoll(argv[i + 1]);
        }
        int ping_count = 3;
        for (int i = 1; i + 1 < argc; i++) {
            if (std::string(argv[i]) == "--ping-count") ping_count = std::atoi(argv[i + 1]);
        }
        if (!socket_path.has_value() || socket_path->empty() || socket_path->size() > 100 ||
            hold_ms <= 0 || hold_ms > 560000 || ping_count < 1 || ping_count > 10 ||
            !peer_arg.has_value()) return receipt("invalid-input", 3);
        in_addr peer_address{};
        if (::inet_pton(AF_INET, peer_arg->c_str(), &peer_address) != 1) return receipt("invalid-input", 3);
        // Optional in-tunnel DNS probe: both flags together or neither.
        const auto dig_server = arg_value(argc, argv, "--dig-server");
        const auto dig_name = arg_value(argc, argv, "--dig-name");
        const bool dig_configured = dig_server.has_value() || dig_name.has_value();
        if (dig_configured) {
            if (!dig_server.has_value() || !dig_name.has_value()) return receipt("invalid-input", 3);
            in_addr dig_address{};
            if (dig_server->empty() || dig_server->size() > 15 ||
                ::inet_pton(AF_INET, dig_server->c_str(), &dig_address) != 1 ||
                !valid_query_name(*dig_name)) return receipt("invalid-input", 3);
        }
        const auto resolve_domains_arg = arg_value(argc, argv, "--resolve-domains");
        std::vector<std::string> resolve_domains;
        if (resolve_domains_arg.has_value()) {
            if (!parse_resolve_domains_csv(*resolve_domains_arg, &resolve_domains)) {
                return receipt("invalid-input", 3);
            }
        }
        ::signal(SIGTERM, handle_stop_signal);
        ::signal(SIGINT, handle_stop_signal);

        std::string input;
        std::array<char, 8192> buffer{};
        for (;;) {
            const auto count = ::read(STDIN_FILENO, buffer.data(), buffer.size());
            if (count < 0) return receipt("invalid-input", 3);
            if (!count) break;
            if (input.size() + static_cast<std::size_t>(count) > 2 * 1024 * 1024) return receipt("invalid-input", 3);
            input.append(buffer.data(), static_cast<std::size_t>(count));
        }
        probe_input::Parsed parsed;
        if (!probe_input::parse(input, parsed)) return receipt("invalid-input", 3);
        std::vector<openvpn::ClientAPI::KeyValue> peerInfo;
        for (auto &entry : parsed.peerInfo) peerInfo.emplace_back(entry.first, std::move(entry.second));

        EngineNet hooksNet;
        std::atomic<bool> sessionOver{false};
        engine_transaction::EnginePump pump;
        std::atomic<int> transactionSocket{-1};
        engine_transaction::EngineResult transaction;
        std::atomic<bool> disconnectSent{false};
        std::atomic<uint64_t> heartbeatsSent{0};
        PingOutcome ping;
        DigOutcome dig;
        std::thread watcher;
        std::atomic<bool> connectCalled{false};
        // Ctrl push evidence, written from the OpenVPN3 client thread.
        std::mutex ctrl_mutex;
        std::atomic<int> ctrlPushesObserved{0}, ctrlUpdatesSent{0}, ctrlUpdatesFailed{0};
        std::vector<std::string> ctrlRoutesPushed;

        auto probeBox = std::make_unique<HandshakeProbe>(parsed.vendorConfusion, parsed.activeShapingNotExercised,
                                                         parsed.gmsslRenegotiationNotExercised, true);
        auto &probe = *probeBox;
        probe.pushUpdateHandler = [&](const std::vector<securelink::ctrl::PushRouteIntent> &routes) {
            // Runs on the OpenVPN3 client thread. Before the executor
            // transaction there is no lease to apply a push to: fail the
            // session closed exactly as the handshake probe does.
            if (transactionSocket.load() < 0) { probe.rejectControlPolicy(); return; }
            std::vector<std::pair<std::string, int>> pushed;
            for (const auto &r : routes) pushed.push_back({r.address, static_cast<int>(r.prefix)});
            const MemoryTunPlan deltaPlan = probe.plan.delta_with_routes(pushed);
            const bool sent = deltaPlan.isComplete() && pump.send_update(hooksNet, deltaPlan.json());
            {
                const std::lock_guard<std::mutex> lock(ctrl_mutex);
                ctrlPushesObserved++;
                for (const auto &r : pushed)
                    ctrlRoutesPushed.push_back(r.first + "/" + std::to_string(r.second));
                if (sent) ctrlUpdatesSent++; else ctrlUpdatesFailed++;
            }
            std::fprintf(stderr, "engine: push update %zu routes sent=%d\n",
                         pushed.size(), sent ? 1 : 0);
        };
        probe.establishHook = [&]() -> int {
            const std::string planBytes = probe.plan.json();
            std::string error;
            const int fd = connect_executor(*socket_path, &error);
            if (fd < 0) {
                std::fprintf(stderr, "engine: executor connect failed: %s\n", error.c_str());
                transaction.phase = "connect-failed";
                return -1;
            }
            transactionSocket = fd;
            engine_transaction::EngineApproval approval;
            approval.binding.session.fill(0xB7);
            approval.binding.challenge.fill(0x4C);
            CC_SHA256(planBytes.data(), static_cast<CC_LONG>(planBytes.size()),
                      approval.binding.plan_digest.data());
            approval.peer.uid = 0;
            approval.plan = planBytes;
            approval.duration_ms = 120000;
            uint64_t sequence = 0;
            engine_transaction::EngineHooks<EngineNet> hooks{EngineNet{}};
            const auto handshake = engine_transaction::engine_handshake(fd, approval, hooks, sequence);
            transaction.phase = handshake.phase;
            transaction.fd_accepted = handshake.fd_accepted;
            transaction.tunnel_interface = handshake.tunnel_interface;
            if (!handshake.fd_accepted) {
                std::fprintf(stderr, "engine: transaction phase=%s\n", handshake.phase.c_str());
                ::close(fd);
                transactionSocket = -1;
                return -1;
            }
            pump.fd = fd;
            pump.binding = approval.binding;
            pump.sequence = sequence;
            pump.start(hooksNet, 1000);  // well inside the daemon silence ceiling
            const std::string vip = probe.plan.primaryIPv4Address();
            if (!vip.empty()) {
                std::fprintf(stderr, "engine: active on %s vip=%s\n", handshake.tunnel_interface.c_str(), vip.c_str());
            } else {
                std::fprintf(stderr, "engine: active on %s\n", handshake.tunnel_interface.c_str());
            }
            std::fflush(stderr);
            return handshake.tunnel_fd;  // ownership passes to the OpenVPN3 session
        };
        auto finishSession = [&]() {
            sessionOver = true;
            pump.stop();
            heartbeatsSent = pump.heartbeats_sent;
            if (transactionSocket.load() >= 0) {
                // The engine always sends disconnect after an accepted fd so
                // the daemon converges journal cleanup.
                disconnectSent = pump.disconnect(hooksNet);
                ::close(transactionSocket.load());
                transactionSocket = -1;
            }
        };

        try {
            openvpn::ClientAPI::Config config;
            config.peerInfo = std::move(peerInfo);
            config.content = std::move(parsed.profile);
            config.connTimeout = 25;
            config.retryOnAuthFailed = false;
            config.tunPersist = false;
            config.googleDnsFallback = false;
            config.disableClientCert = parsed.vendorConfusion;
            const auto evaluation = probe.eval_config(config);
            if (evaluation.error) return receipt("profile-rejected", 2, &probe, transaction);
            openvpn::ClientAPI::ProvideCreds credentials;
            credentials.username = std::move(parsed.username);
            credentials.password = std::move(parsed.password);
            if (probe.provide_creds(credentials).error) return receipt("credentials-rejected", 2, &probe, transaction);
            if (std::chrono::steady_clock::now() >= deadline) {
                probe.deadlineReached = true;
                return receipt("deadline", 2, &probe, transaction);
            }
            // In-tunnel ping watcher: wait for CONNECTED, run a bounded ping
            // through the tunnel, and stop early once the session is over.
            watcher = std::thread([&]() {
                const auto wait_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(90);
                while (!sessionOver.load() && !g_stop_requested.load() && !probe.connectedInDataMode.load() &&
                       std::chrono::steady_clock::now() < wait_deadline)
                    std::this_thread::sleep_for(std::chrono::milliseconds(25));
                if (g_stop_requested.load()) {
                    probe.stop();
                    return;
                }
                if (!sessionOver.load() && probe.connectedInDataMode.load()) {
                    ping = run_ping(*peer_arg, ping_count);
                    if (dig_configured) dig = run_dig(*dig_server, *dig_name);
                    if (!resolve_domains.empty() && !sessionOver.load() && !g_stop_requested.load()) {
                        const std::string dns_target = dig_configured ? *dig_server : probe.plan.primaryDNSServerIPv4();
                        if (!dns_target.empty()) {
                            std::vector<securelink::ctrl::PushRouteIntent> dynamic_routes;
                            for (const auto &domain : resolve_domains) {
                                if (sessionOver.load() || g_stop_requested.load()) break;
                                const DigOutcome resolved = run_dig(dns_target, domain);
                                for (const auto &ip : resolved.addresses) {
                                    if (is_covered_or_reserved_ipv4(ip) ||
                                        ip == probe.plan.remoteAddress() ||
                                        ip == dns_target ||
                                        probe.plan.hasRoute(ip, 32)) {
                                        continue;
                                    }
                                    bool already = false;
                                    for (const auto &existing : dynamic_routes) {
                                        if (existing.address == ip) { already = true; break; }
                                    }
                                    if (!already && dynamic_routes.size() < 16) {
                                        dynamic_routes.push_back(securelink::ctrl::PushRouteIntent{ip, 32});
                                    }
                                }
                            }
                            if (!dynamic_routes.empty() && !sessionOver.load() && !g_stop_requested.load()) {
                                probe.pushUpdateHandler(dynamic_routes);
                            }
                        }
                    }
                }
                while (!sessionOver.load()) {
                    if (g_stop_requested.load()) {
                        probe.stop();
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
            });
            {
                StopDeadline timer(deadline, [&] { probe.deadlineReached = true; probe.stop(); });
                StopDeadline holdTimer(std::chrono::steady_clock::now() + std::chrono::milliseconds(hold_ms),
                                       [&] { probe.stop(); }); // hold ends the session
                connectCalled = true;
                const auto status = probe.connect();
                (void)status; // status/message may include secrets; never render them
            }
            finishSession();
        } catch (...) {
            finishSession();
            if (watcher.joinable()) watcher.join();
            const std::lock_guard<std::mutex> lock(ctrl_mutex);
            return receipt("internal-error", 3, &probe, transaction, ping,
                           disconnectSent.load(), heartbeatsSent.load(), hold_ms, connectCalled.load(),
                           dig, dig_configured ? *dig_server : "", dig_configured ? *dig_name : "",
                           ctrlPushesObserved.load(), ctrlUpdatesSent.load(), ctrlUpdatesFailed.load(),
                           ctrlRoutesPushed);
        }
        if (watcher.joinable()) watcher.join();
        const char *reason = probe.controlPolicyRejected ? "control-policy-rejected" :
                             !transaction.fd_accepted ? (probe.plan.isComplete() ? "transaction-failed" : "capture-incomplete") :
                             probe.unexpectedConnected ? "unexpected-connected" :
                             (probe.connectedInDataMode.load() && ping.ran && ping.received > 0) ? "data-session-verified" :
                             probe.connectedInDataMode.load() ? "data-session-ended" :
                             probe.deadlineReached ? "deadline" : "connection-ended";
        const int code = std::strcmp(reason, "data-session-verified") == 0 ? 0 :
                         std::strcmp(reason, "data-session-ended") == 0 ? 1 :
                         std::strcmp(reason, "unexpected-connected") == 0 ? 1 :
                         std::strcmp(reason, "connection-ended") == 0 ? 1 : 2;
        const std::lock_guard<std::mutex> lock(ctrl_mutex);
        return receipt(reason, code, &probe, transaction, ping,
                       disconnectSent.load(), heartbeatsSent.load(), hold_ms, connectCalled.load(),
                       dig, dig_configured ? *dig_server : "", dig_configured ? *dig_name : "",
                       ctrlPushesObserved.load(), ctrlUpdatesSent.load(), ctrlUpdatesFailed.load(),
                       ctrlRoutesPushed);
    }
}
