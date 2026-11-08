#include <client/ovpncli.hpp>
#include <array>
#include <cstdio>
#include <string>
#include <sys/resource.h>
#include <unistd.h>

namespace {
int receipt(bool accepted, const char *reason, int code) {
    std::printf("{\"accepted\":%s,\"mode\":\"offline-config-evaluation\",\"networkOpened\":false,\"tunnelStarted\":false,\"reason\":\"%s\"}\n", accepted ? "true" : "false", reason);
    return code;
}
}
int main(int argc, char **) {
    // Foundation gives children their own group. Join the owner's group so its
    // bounded supervisor can reap the whole trial before restoring networking.
    const pid_t owner = getppid();
    const pid_t group = owner > 1 ? getpgid(owner) : -1;
    if (group <= 0 || setpgid(0, group) != 0) return receipt(false, "invalid-input", 3);
    // Bounded stdin-only lifetime, including a caller that never closes its pipe.
    alarm(10);
    const rlimit noCore = {0, 0};
    setrlimit(RLIMIT_CORE, &noCore);
    if (argc != 1) return receipt(false, "invalid-input", 3);
    try {
        constexpr std::size_t maximum = 2 * 1024 * 1024;
        std::string input;
        std::array<char, 8192> buffer{};
        for (;;) {
            const auto count = ::read(STDIN_FILENO, buffer.data(), buffer.size());
            if (count < 0) return receipt(false, "invalid-input", 3);
            if (!count) break;
            if (input.size() + static_cast<std::size_t>(count) > maximum) return receipt(false, "invalid-input", 3);
            input.append(buffer.data(), static_cast<std::size_t>(count));
        }
        if (input.empty() || input.find('\0') != std::string::npos) return receipt(false, "invalid-input", 3);
        openvpn::ClientAPI::Config config;
        config.content = std::move(input);
        openvpn::ClientAPI::OpenVPNClientHelper helper;
        // No merge_config (file reads), no OpenVPNClient, no connect, no credentials.
        const auto result = helper.eval_config(config);
        const char *reason = !result.error ? "accepted" : "rejected";
        if (result.error && result.message.find("remote option not specified") != std::string::npos)
            reason = "missing-remote";
        return receipt(!result.error, reason, result.error ? 2 : 0);
    } catch (...) {
        // Never print exception text or EvalConfig.message.
        return receipt(false, "internal-error", 3);
    }
}
