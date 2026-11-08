#pragma once
// Pure status-daemon logic shared by daemon.mm and the offline test. The
// daemon only answers one fixed read-only request and never mutates anything.
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace status_daemon {
inline constexpr uint32_t kRequestFrameLength = 1;
inline constexpr uint8_t kOpStatus = 0x01;
inline constexpr const char *kHelperLabel = "local.szu.securelink.helper";
inline constexpr const char *kVendorLabels[] = {
    "com.securelink.client",
    "com.wangsu.edlp.service",
    "com.wangsu.securebox.service",
};
inline constexpr size_t kVendorLabelCount = 3;
inline constexpr size_t kSha256HexLength = 64;

// launchctl exits 0 only for a found, loadable service. Every other exit code
// is reported verbatim so downstream gates never receive a guessed verdict.
inline const char *state_name(int launchctl_exit) {
    return launchctl_exit == 0 ? "loaded" : "exit";
}

inline bool is_hex_sha256(const std::string &hex) {
    if (hex.size() != kSha256HexLength) return false;
    for (char c : hex) {
        bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok) return false;
    }
    return true;
}

// The request is exactly one status byte. Anything else is refused.
inline bool parse_request(const uint8_t *frame, size_t length) {
    return length == 1 && frame[0] == kOpStatus;
}

struct LabelVerdict {
    std::string label;
    int launchctl_exit = -1;
};

// All embedded values are constants or validated hex, so plain assembly is
// injection-free: no launchctl output ever enters the response.
inline std::string build_response(const std::string &sha256_hex, unsigned allowed_uid,
                                  const std::vector<LabelVerdict> &verdicts,
                                  long long epoch_seconds) {
    std::string out = "{\"schemaVersion\":1,\"helper\":{\"label\":\"";
    out += kHelperLabel;
    out += "\",\"sha256\":\"";
    out += is_hex_sha256(sha256_hex) ? sha256_hex : std::string(kSha256HexLength, '0');
    out += "\",\"allowedUid\":";
    out += std::to_string(allowed_uid);
    out += "},\"services\":{";
    bool first = true;
    for (const LabelVerdict &v : verdicts) {
        if (!first) out += ",";
        first = false;
        out += "\"";
        out += v.label;
        out += "\":{\"state\":\"";
        out += state_name(v.launchctl_exit);
        out += "\",\"exitCode\":";
        out += std::to_string(v.launchctl_exit);
        out += "}";
    }
    out += "},\"epoch\":";
    out += std::to_string(epoch_seconds);
    out += "}";
    return out;
}
}
