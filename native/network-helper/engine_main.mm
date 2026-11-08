// Engine CLI for the bounded tunnel-executor probe. Connects to the executor
// daemon socket, submits the staged plan through the audited transaction,
// verifies the returned descriptor is a utun control socket, acknowledges,
// then disconnects so the daemon converges journal cleanup. Prints a JSON
// receipt. Synthetic plan only: this never touches campus resources.
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>
#import <sys/socket.h>
#import <sys/un.h>
#import <poll.h>
#import <thread>
#import <chrono>
#import <cerrno>
#import <cstdio>
#import <cstring>
#import <string>
#import "engine_transaction.hpp"
#import "real_hooks.hpp"

namespace {

std::optional<std::string> arg_value(int argc, char **argv, const std::string &name) {
    for (int i = 1; i + 1 < argc; i++) {
        if (name == argv[i]) return std::string(argv[i + 1]);
    }
    return std::nullopt;
}

std::optional<std::string> read_file_string(const std::string &path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return std::nullopt;
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    return buffer.str();
}

class EngineNet {
public:
    std::string identifier = "local.szu.securelink.executor";

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
            credential.cr_uid != expected.uid) {
            std::fprintf(stderr, "DBG uid fail: uid=%u\n", credential.cr_uid);
            return false;
        }
        audit_token_t token{};
        size = sizeof(token);
        if (::getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size) != 0) {
            std::fprintf(stderr, "DBG token fail\n");
            return false;
        }
        CFDataRef audit = CFDataCreate(nullptr, reinterpret_cast<const UInt8 *>(&token),
                                       sizeof(token));
        if (!audit) return false;
        const void *key = kSecGuestAttributeAudit;
        const void *value = audit;
        CFDictionaryRef attributes = CFDictionaryCreate(
            nullptr, &key, &value, 1, &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);
        SecCodeRef code = nullptr;
        const OSStatus status = attributes
            ? SecCodeCopyGuestWithAttributes(nullptr, attributes, kSecCSDefaultFlags, &code)
            : errSecAllocate;
        if (attributes) CFRelease(attributes);
        CFRelease(audit);
        if (status != errSecSuccess || !code) {
            std::fprintf(stderr, "DBG code lookup fail status=%d\n", (int)status);
            return false;
        }
        SecStaticCodeRef static_code = nullptr;
        CFDictionaryRef information = nullptr;
        bool valid = SecCodeCopyStaticCode(code, kSecCSDefaultFlags, &static_code) == errSecSuccess &&
                     SecCodeCopySigningInformation(static_code, kSecCSSigningInformation,
                                                   &information) == errSecSuccess;
        if (valid) {
            const auto identifier = static_cast<CFStringRef>(
                CFDictionaryGetValue(information, kSecCodeInfoIdentifier));
            char buffer[256] = {0};
            if (identifier) CFStringGetCString(identifier, buffer, 256, kCFStringEncodingUTF8);
            std::fprintf(stderr, "DBG identifier=%s\n", buffer);
            valid = identifier && CFStringCompare(
                identifier, CFSTR("local.szu.securelink.executor"),
                kCFCompareCaseInsensitive) == kCFCompareEqualTo;
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
        auto received = network_helper::receive_chunk(fd, true);
        std::fprintf(stderr, "DBG recv_fd valid=%d eof=%d must_exit=%d bytes=%zu fd=%d\n",
                     received.valid ? 1 : 0, received.eof ? 1 : 0,
                     received.must_exit ? 1 : 0, received.bytes.size(), received.fd);
        return received;
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

}  // namespace

int main(int argc, char **argv) {
    ::signal(SIGPIPE, SIG_IGN);  // daemon may close first; writes report EPIPE
    const auto socket_path = arg_value(argc, argv, "--socket");
    const auto plan_path = arg_value(argc, argv, "--plan");
    const auto context_path = arg_value(argc, argv, "--context");
    const auto identity_path = arg_value(argc, argv, "--identity");
    long long hold_seconds = 0;
    for (int i = 1; i + 1 < argc; i++) {
        if (std::string(argv[i]) == "--hold-seconds") hold_seconds = std::atoll(argv[i + 1]);
    }
    if (!socket_path.has_value() || !plan_path.has_value() || !context_path.has_value() ||
        !identity_path.has_value()) {
        std::fputs("usage: engine --socket <path> --plan <json> --context <json> "
                   "--identity <uuidfile>\n", stderr);
        return 64;
    }
    const auto plan = read_file_string(*plan_path);
    const auto identity = real_hooks::read_file_string(*identity_path);
    if (!plan.has_value() || !identity.has_value()) {
        std::fputs("cannot read staged plan or identity\n", stderr);
        return 65;
    }
    std::string trimmed = *identity;
    while (!trimmed.empty() && (trimmed.back() == '\n' || trimmed.back() == '\r')) trimmed.pop_back();

    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        std::fprintf(stderr, "engine socket error\n");
        return 1;
    }
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::strncpy(address.sun_path, socket_path->c_str(), sizeof(address.sun_path) - 1);
    if (::connect(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
        std::fprintf(stderr, "engine connect failed: %s\n", std::strerror(errno));
        return 1;
    }

    engine_transaction::EngineApproval approval;
    approval.binding.session.fill(0xB7);
    approval.binding.challenge.fill(0x4C);
    CC_SHA256(plan->data(), static_cast<CC_LONG>(plan->size()),
              approval.binding.plan_digest.data());
    approval.peer.uid = 0;
    approval.plan = *plan;
    approval.duration_ms = 120000;
    approval.hold_ms = static_cast<uint64_t>(hold_seconds) * 1000;

    // Wait for the daemon's one-byte ready marker so credential lookups
    // resolve against the daemon process, not launchd.
    pollfd wanted = {fd, POLLIN, 0};
    if (::poll(&wanted, 1, 5000) <= 0) {
        std::fprintf(stderr, "engine: no ready marker\n");
        return 1;
    }
    uint8_t marker = 0;
    const ssize_t got = ::read(fd, &marker, 1);
    if (got != 1 || marker != 0x52) {
        std::fprintf(stderr, "engine: bad ready marker got=%zd val=%02x errno=%d\n",
                     got, got == 1 ? marker : 0, errno);
        return 1;
    }

    engine_transaction::EngineHooks<EngineNet> hooks{EngineNet{}};
    hooks.debug_sends = true;
    std::fprintf(stderr, "engine: entering transaction\n");
    const auto result = engine_transaction::run_engine(fd, approval, hooks);
    std::fprintf(stderr, "engine: transaction returned phase=%s\n", result.phase.c_str());
    std::printf("{\"phase\":\"%s\",\"interface\":\"%s\",\"fdAccepted\":%s}\n",
                result.phase.c_str(), result.tunnel_interface.c_str(),
                result.fd_accepted ? "true" : "false");
    ::close(fd);
    (void)trimmed;
    return result.phase == "active" && result.fd_accepted ? 0 : 1;
}
