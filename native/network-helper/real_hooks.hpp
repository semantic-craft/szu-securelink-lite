#pragma once
// Real daemon/engine hooks for the tunnel transaction: launchd socket, peer
// identity via audit-token code lookup, utun lifecycle, journaled route
// invocations through /sbin/route, and supplemental DNS through the system
// dynamic store. 3e pins identities by uid + code identifier plus an optional
// staged cdhash; full exact-token pinning both ways is Slice F work and is
// documented as such in the run receipt.
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <SystemConfiguration/SCDynamicStore.h>
#include <bsm/libbsm.h>
#include <sys/ucred.h>
#include <spawn.h>
#include <sys/wait.h>
#include <memory>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <chrono>
#include <csignal>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include "engine_transaction.hpp"
#include "ipc.hpp"
#include "system_ops.hpp"
#include "tunnel_transaction.hpp"
#include "utun_tunnel.hpp"

extern char **environ;

namespace real_hooks {

inline uint64_t steady_ms() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

inline bool wait_readable(int fd, int timeout_ms) {
    pollfd wanted = {fd, POLLIN, 0};
    return ::poll(&wanted, 1, timeout_ms) > 0;
}

inline bool write_all_fd(int fd, const network_helper::Bytes &bytes) {
    size_t done = 0;
    while (done < bytes.size()) {
        const ssize_t n = ::write(fd, bytes.data() + done, bytes.size() - done);
        if (n <= 0) return false;
        done += static_cast<size_t>(n);
    }
    return true;
}

inline std::optional<std::string> read_file_string(const std::string &path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return std::nullopt;
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    return buffer.str();
}

// Spawn a fixed argv list, wait, and return the exit code. No shell anywhere.
inline std::string join_argv(const std::vector<std::string> &argv) {
    std::string out;
    for (const std::string &part : argv) {
        if (!out.empty()) out += " ";
        out += part;
    }
    return out;
}

inline int spawn_and_wait(const std::vector<std::string> &argv, int timeout_ms = 5000) {
    std::vector<char *> mutable_argv;
    mutable_argv.reserve(argv.size() + 1);
    for (const std::string &arg : argv) mutable_argv.push_back(const_cast<char *>(arg.c_str()));
    mutable_argv.push_back(nullptr);
    posix_spawnattr_t attributes = nullptr;
    posix_spawn_file_actions_t actions = nullptr;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    pid_t child = -1;
    const int spawn_error =
        posix_spawn(&child, argv[0].c_str(), &actions, &attributes, mutable_argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    if (spawn_error != 0) return -1;
    // Fail closed on hangs: a system command that does not finish within the
    // deadline is killed and reported as failure, never left dangling.
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    int status = 0;
    while (true) {
        const pid_t done = waitpid(child, &status, WNOHANG);
        if (done == child) break;
        if (done < 0 && errno != EINTR) return -1;
        if (std::chrono::steady_clock::now() >= deadline) {
            ::kill(child, SIGKILL);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
            std::fprintf(stderr, "spawn: timeout killed argv=%s\n",
                         join_argv(argv).c_str());
            return -2;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// The engine and daemon learn each other's code identity from the audit
// token; a staged cdhash pins the exact binary when provided (hex, 64).
using CodeExpectation = tunnel_transaction::CodeExpectation;


inline bool code_identity_matches(int fd, const tunnel_transaction::CodeExpectation &expected) {
    xucred credential{};
    socklen_t size = sizeof(credential);
    if (::getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, &credential, &size) != 0 ||
        size != sizeof(credential) || credential.cr_version != XUCRED_VERSION ||
        credential.cr_uid != expected.uid) {
        std::fprintf(stderr, "ident: uid stage failed uid=%u want=%u\n",
                     credential.cr_uid, expected.uid);
        return false;
    }
    std::fprintf(stderr, "ident: uid ok\n");
    audit_token_t token{};
    size = sizeof(token);
    if (::getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size) != 0 ||
        size != sizeof(token)) {
        std::fprintf(stderr, "ident: token stage failed\n");
        return false;
    }
    if (audit_token_to_euid(token) != expected.uid) {
        std::fprintf(stderr, "ident: token euid mismatch\n");
        return false;
    }
    CFDataRef audit = CFDataCreate(nullptr, reinterpret_cast<const UInt8 *>(&token),
                                   sizeof(token));
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
    if (status != errSecSuccess || !code) {
        std::fprintf(stderr, "ident: code lookup failed status=%d\n", (int)status);
        return false;
    }
    SecStaticCodeRef static_code = nullptr;
    CFDictionaryRef information = nullptr;
    bool valid = SecCodeCheckValidity(code, kSecCSStrictValidate, nullptr) == errSecSuccess &&
                 SecCodeCopyStaticCode(code, kSecCSDefaultFlags, &static_code) == errSecSuccess &&
                 SecCodeCopySigningInformation(static_code, kSecCSSigningInformation,
                                               &information) == errSecSuccess;
    if (valid) {
        const auto identifier = static_cast<CFStringRef>(
            CFDictionaryGetValue(information, kSecCodeInfoIdentifier));
        char seen[256] = {0};
        if (identifier) CFStringGetCString(identifier, seen, 256, kCFStringEncodingUTF8);
        std::fprintf(stderr, "ident: engine identifier seen=%s\n", seen);
        valid = identifier && CFGetTypeID(identifier) == CFStringGetTypeID() &&
                CFStringCompare(identifier, CFSTR("local.szu.securelink.executor-engine"),
                                kCFCompareCaseInsensitive) == kCFCompareEqualTo;
    }
    if (valid && !expected.cdhash_hex.empty()) {
        std::fprintf(stderr, "ident: staged cdhash=%s\n", expected.cdhash_hex.c_str());
    }
    if (valid && !expected.cdhash_hex.empty()) {
        const auto hash = static_cast<CFDataRef>(
            CFDictionaryGetValue(information, kSecCodeInfoUnique));
        valid = hash && CFGetTypeID(hash) == CFDataGetTypeID() &&
                CFDataGetLength(hash) == 20;
        if (valid) {
            std::string hex;
            static const char *kDigits = "0123456789abcdef";
            const UInt8 *bytes = CFDataGetBytePtr(hash);
            for (int i = 0; i < 20; i++) {
                hex.push_back(kDigits[bytes[i] >> 4]);
                hex.push_back(kDigits[bytes[i] & 0x0F]);
            }
            valid = hex == expected.cdhash_hex;
        }
    }
    if (information) CFRelease(information);
    if (static_code) CFRelease(static_code);
    CFRelease(code);
    return valid;
}

class DaemonNet {
public:
    CodeExpectation engine_expectation;
    std::vector<uint8_t> pending;  // per-connection frame accumulator

    bool authenticate(int fd, const tunnel_transaction::CodeExpectation &expected) {
        return code_identity_matches(fd, expected);
    }
    static uint64_t now_ms() { return steady_ms(); }
    bool wait_readable(int fd, int timeout_ms) {
        // Frames already sitting in the accumulator are "readable" even though
        // the kernel socket buffer may be empty after a coalesced read.
        if (!pending.empty()) return true;
        return real_hooks::wait_readable(fd, timeout_ms);
    }
    // The audited parser rejects coalesced frames, so this hook accumulates
    // raw bytes and yields exactly one complete frame per call. EOF, invalid
    // chunks and truncation propagate fail-closed flags unchanged.
    network_helper::Received receive(int fd, bool) {
        while (true) {
            const uint8_t *base = pending.data();
            if (pending.size() >= 4) {
                uint32_t length = 0;
                for (int i = 0; i < 4; i++) length = (length << 8) | base[i];
                if (length >= 92 && length <= 65536 && pending.size() >= length + 4) {
                    network_helper::Received frame;
                    frame.bytes.assign(pending.begin(), pending.begin() + length + 4);
                    frame.valid = true;
                    pending.erase(pending.begin(), pending.begin() + length + 4);
                    return frame;
                }
            }
            auto chunk = network_helper::receive_chunk(fd, false);
            if (chunk.must_exit || chunk.eof) {
                chunk.valid = false;
                chunk.bytes.clear();
                pending.clear();
                return chunk;
            }
            if (!chunk.valid) {
                // No data right now (EAGAIN): keep the accumulator, let the
                // caller's slice timeout and silence judgment drive retries.
                if (wait_readable(fd, 200)) continue;
                network_helper::Received quiet;
                quiet.valid = false;
                quiet.bytes.clear();
                return quiet;
            }
            pending.insert(pending.end(), chunk.bytes.begin(), chunk.bytes.end());
        }
    }
    static bool send_fd_marker(int fd, int tunnel_fd) {
        return network_helper::send_fd_marker(fd, tunnel_fd);
    }
};

class DaemonExecutor {
public:
    bool fail_open = false;

    int tunnel_open() {
        if (fail_open) return -1;
        utun_.reset(new utun_tunnel::System());
        const int fd = utun_->open();
        if (fd < 0) {
            utun_.reset();
            return -1;
        }
        if (!utun_->connect(fd) || !utun_->read_name(fd)) {
            const int saved = errno;
            (void)utun_->close(fd);
            utun_.reset();
            errno = saved;
            return -1;
        }
        tunnel_fd_ = fd;
        return fd;
    }
    std::string tunnel_name() { return utun_ ? utun_->name : std::string(); }
    long long tunnel_ifindex() {
        return utun_ ? static_cast<long long>(::if_nametoindex(utun_->name.c_str())) : 0;
    }
    std::string tunnel_identity() { return lease_identity_; }
    void set_lease_identity(const std::string &value) { lease_identity_ = value; }
    bool close_tunnel(int fd) {
        if (utun_ && !utun_->name.empty()) {
            (void)spawn_and_wait("/sbin/ifconfig", {"/sbin/ifconfig", utun_->name, "down"});
        }
        const bool closed = utun_ && utun_->close(fd);
        if (closed) {
            const bool gone = utun_->removed();
            removed_confirmed_ = gone;
        }
        utun_.reset();
        tunnel_fd_ = -1;
        return closed;
    }
    bool tunnel_removed() const { return removed_confirmed_; }

    bool apply_op(const plan_ops::Operation &op) {
        std::fprintf(stderr, "apply: begin kind=%s key=%s\n", op.kind.c_str(),
                     op.key.c_str());
        if (op.kind == "interface-route") {
            // Bind to our interface: the plan gateway address may also belong
            // to the official tunnel's interface, and an unbound gateway
            // route would silently ride THAT interface.
            const auto invocation = system_ops::route_invocation(op, true);
            if (!invocation.has_value()) return false;
            std::vector<std::string> argv = invocation->argv;
            // The gateway address may exist on BOTH interfaces (ours and the
            // official tunnel's), so bind the route to our interface with
            // -iface and route via the p2p peer. Never leave it unbound.
            for (size_t i = 0; i + 1 < argv.size(); i++) {
                if (argv[i] == "-gateway") {
                    argv[static_cast<size_t>(i) + 1] = tunnel_name();
                    argv[static_cast<size_t>(i)] = "-iface";
                    break;
                }
            }
            const int exit_code = spawn_and_wait(argv);
            std::fprintf(stderr, "apply: route spawn exit=%d argv=%s\n", exit_code,
                         join_argv(argv).c_str());
            return exit_code == 0;
        }
        if (op.kind == "supplemental-resolver") {
            return dns_set(op);
        }
        if (op.kind == "owned-interface") {
            std::fprintf(stderr, "apply: owned-interface configuring %s\n",
                         tunnel_name().c_str());
            // Configure the plan address and peer on our interface so the
            // routes via that address actually resolve to OUR tunnel.
            const auto decoded = plan_input::parse(
                reinterpret_cast<const uint8_t *>(op.value.data()), op.value.size());
            if (decoded.error != plan_input::Error::none || !decoded.value.is_object()) return false;
            const auto addresses = decoded.value.find("addresses");
            if (!addresses || !addresses->is_array() || addresses->items.empty()) return false;
            for (const auto &item : addresses->items) {
                // Canonical payload encodes each address as [addr, prefix, peer].
                if (!item.is_array() || item.items.size() < 2) return false;
                if (!item.items[0].is_string()) return false;
                std::vector<std::string> argv{"/sbin/ifconfig", tunnel_name(), "inet",
                                              item.items[0].text};
                if (item.items.size() >= 3 && item.items[2].is_string() &&
                    !item.items[2].text.empty()) {
                    argv.push_back(item.items[2].text);
                }
                argv.push_back("up");
                const int exit_code = spawn_and_wait(argv);
                std::fprintf(stderr, "apply: ifconfig exit=%d argv=%s\n", exit_code,
                             join_argv(argv).c_str());
                if (exit_code != 0) return false;
            }
            const auto mtu = decoded.value.find("mtu");
            if (mtu && mtu->is_int()) {
                (void)spawn_and_wait({"/sbin/ifconfig", tunnel_name(), "mtu",
                                      std::to_string(mtu->integer)});
            }
            return true;
        }
        return false;
    }
    bool remove_op(const plan_ops::Operation &op) {
        std::fprintf(stderr, "remove: begin kind=%s\n", op.kind.c_str());
        if (op.kind == "interface-route") {
            const auto invocation = system_ops::route_invocation(op, false);
            if (!invocation.has_value()) return false;
            std::vector<std::string> argv = invocation->argv;
            argv.push_back("-iface");
            argv.push_back(tunnel_name());
            return spawn_and_wait(argv) == 0;
        }
        if (op.kind == "supplemental-resolver") {
            const auto key = system_ops::dns_store_key(op);
            if (!key.has_value()) return false;
            return dns_remove(*key);
        }
        return op.kind == "owned-interface";  // closed with the fd
    }

private:
    std::unique_ptr<utun_tunnel::System> utun_;
    int tunnel_fd_ = -1;
    bool removed_confirmed_ = false;
    std::string lease_identity_;

    static bool dns_set(const plan_ops::Operation &op) {
        std::fprintf(stderr, "apply: dns_set begin\n");
        const auto key = system_ops::dns_store_key(op);
        const auto payload = system_ops::dns_payload(op);
        if (!key.has_value() || !payload.has_value()) return false;
        const auto decoded = plan_input::parse(
            reinterpret_cast<const uint8_t *>(payload->data()), payload->size());
        if (decoded.error != plan_input::Error::none || !decoded.value.is_object()) return false;
        CFStringRef store_key =
            CFStringCreateWithCString(nullptr, key->c_str(), kCFStringEncodingUTF8);
        const auto values = decoded.value.find("ServerAddresses");
        const auto domains = decoded.value.find("SupplementalMatchDomains");
        if (!store_key || !values || !values->is_array() || !domains || !domains->is_array()) {
            if (store_key) CFRelease(store_key);
            return false;
        }
        CFMutableArrayRef servers = CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks);
        CFMutableArrayRef match_domains = CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks);
        for (const auto &item : values->items) {
            CFStringRef text = CFStringCreateWithCString(nullptr, item.text.c_str(),
                                                         kCFStringEncodingUTF8);
            CFArrayAppendValue(servers, text);
            CFRelease(text);
        }
        for (const auto &item : domains->items) {
            CFStringRef text = CFStringCreateWithCString(nullptr, item.text.c_str(),
                                                         kCFStringEncodingUTF8);
            CFArrayAppendValue(match_domains, text);
            CFRelease(text);
        }
        const int no_search = 1;
        CFNumberRef no_search_number = CFNumberCreate(nullptr, kCFNumberIntType, &no_search);
        const void *keys[] = {CFSTR("ServerAddresses"), CFSTR("SupplementalMatchDomains"),
                              CFSTR("SupplementalMatchDomainsNoSearch")};
        const void *vals[] = {servers, match_domains, no_search_number};
        CFDictionaryRef payload_cf = CFDictionaryCreate(nullptr, keys, vals, 3,
                                                        &kCFTypeDictionaryKeyCallBacks,
                                                        &kCFTypeDictionaryValueCallBacks);
        SCDynamicStoreRef store = SCDynamicStoreCreate(nullptr, CFSTR("szu-securelink-executor"),
                                                       nullptr, nullptr);
        std::fprintf(stderr, "apply: dns store=%d\n", store ? 1 : 0);
        const bool ok = store && SCDynamicStoreSetValue(store, store_key, payload_cf);
        std::fprintf(stderr, "apply: dns set ok=%d\n", ok ? 1 : 0);
        if (payload_cf) CFRelease(payload_cf);
        if (no_search_number) CFRelease(no_search_number);
        if (match_domains) CFRelease(match_domains);
        if (servers) CFRelease(servers);
        if (store_key) CFRelease(store_key);
        if (store) CFRelease(store);
        return ok;
    }

    static bool dns_remove(const std::string &key) {
        CFStringRef store_key = CFStringCreateWithCString(nullptr, key.c_str(),
                                                          kCFStringEncodingUTF8);
        SCDynamicStoreRef store = SCDynamicStoreCreate(nullptr, CFSTR("szu-securelink-executor"),
                                                       nullptr, nullptr);
        const bool ok = store && SCDynamicStoreRemoveValue(store, store_key);
        if (store_key) CFRelease(store_key);
        if (store) CFRelease(store);
        return ok;
    }
};

}  // namespace real_hooks
