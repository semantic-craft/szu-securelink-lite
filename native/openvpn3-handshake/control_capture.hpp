#pragma once
#include "../ctrl-policy/receiver.hpp"
#include <functional>
#include <string>
#include <vector>

namespace securelink::ctrl {
// Same shape as effects.hpp HostRouteIntent, declared here because the
// build overlay rewrites only the receiver include path.
struct PushRouteIntent { std::string address; unsigned prefix = 32; int metric = 0; };
}  // namespace securelink::ctrl

// Narrow unit-4 contract for in-session route pushes. The only accepted
// PUSH_UPDATE body is a CSV of `route,<network>,<netmask>` directives with
// dotted-quad IPv4, a contiguous mask and canonical network bits; anything
// else (gateways, options, compressed framing, extra directives) fails the
// session closed exactly as before. The real server push shape is UNOBSERVED
// on our sessions; this parser is extended only after that capture.
inline bool parse_push_update_routes(const std::string &csv,
                                     std::vector<securelink::ctrl::PushRouteIntent> &out) {
    openvpn::OptionList::Limits limits("push update limit", 65536, 8, 16, 65536, 256);
    // CSV grammar (matches the vendor ctrl rows): each comma token is one
    // directive, arguments inside it are space separated.
    auto parsed = openvpn::OptionList::parse_from_csv_static(csv, &limits);
    if (parsed.empty() || parsed.size() > 32) return false;
    auto parse_dotted = [](const std::string &text, unsigned &value) {
        unsigned number = 0, components = 1;
        for (const char c : text) {
            if (c == '.') {
                if (++components > 4) return false;
                value = (value << 8) | number;
                number = 0;
                continue;
            }
            number = number * 10 + static_cast<unsigned>(c - '0');
        }
        if (components != 4) return false;
        value = (value << 8) | number;
        return true;
    };
    for (const auto &option : parsed) {
        // Upstream separates directives by commas and directive arguments by
        // spaces; accept both spellings, flattened to exactly three tokens.
        std::vector<std::string> tokens;
        for (std::size_t index = 0; index < option.size(); ++index) {
            const std::string item = option.get(index, 256);
            std::size_t offset = 0;
            while (offset < item.size()) {
                while (offset < item.size() && item[offset] == ' ') ++offset;
                if (offset >= item.size()) break;
                const auto end = item.find(' ', offset);
                const auto stop = end == std::string::npos ? item.size() : end;
                tokens.push_back(item.substr(offset, stop - offset));
                offset = stop;
            }
        }
        if (tokens.size() != 3 || tokens[0] != "route") return false;
        const std::string network = tokens[1];
        const std::string mask = tokens[2];
        if (!securelink::ctrl::ipv4(network) || !securelink::ctrl::ipv4(mask)) return false;
        unsigned address_value = 0, mask_value = 0;
        if (!parse_dotted(network, address_value) || !parse_dotted(mask, mask_value)) return false;
        unsigned ones = 0;
        bool contiguous = true;
        for (int bit = 31; bit >= 0; --bit) {
            const unsigned set = (mask_value >> bit) & 1U;
            if (set) {
                if (!contiguous) return false;
                ++ones;
            } else {
                contiguous = false;
            }
        }
        if (ones < 2 || ones > 32) return false;
        const unsigned host_bits = 32 - ones;
        const unsigned host_mask = host_bits ? (1U << host_bits) - 1U : 0U;
        if (address_value & host_mask) return false;  // host bits set: not canonical
        for (const auto &existing : out) {
            if (existing.address == network) return false;  // duplicate in one push
        }
        out.push_back({network, static_cast<unsigned>(ones), 0});
    }
    return !out.empty();
}

// Instance-owned extension at the helper's pre-dispatch control boundary.
// No global callback, thread-local state, raw-message logs or receipt storage.
class SzuControlCapture {
public:
    virtual ~SzuControlCapture() = default;
    // true: continue standard dispatch with message (possibly normalized).
    // false: message consumed, or fail-closed stop has been requested.
    virtual bool normalize_control(std::string &message) = 0;
};

template<class TransportConfig>
class SzuControlTransportConfig : public TransportConfig, public SzuControlCapture {
    securelink::ctrl::Receiver receiver;
    const std::function<void()> reject;
    const std::function<void(const std::vector<securelink::ctrl::PushRouteIntent> &)> pushUpdate;
    bool rejected = false;
    bool fail() {
        if (!rejected) { rejected = true; reject(); }
        return false;
    }
protected:
    void reset_control_connection() { receiver = {}; rejected = false; }
public:
    explicit SzuControlTransportConfig(std::function<void()> onReject,
        std::function<void(const std::vector<securelink::ctrl::PushRouteIntent> &)> onPushUpdate = nullptr)
        : reject(std::move(onReject)), pushUpdate(std::move(onPushUpdate)) {}
    bool normalize_control(std::string &message) override {
        if (rejected) return false;
        // Unit 4: a standard route push is consumed here and applied through
        // the audited transaction chain; without a handler this still fails
        // closed exactly as before.
        if (message.compare(0, 12, "PUSH_UPDATE,") == 0) {
            if (!pushUpdate) return fail();
            std::vector<securelink::ctrl::PushRouteIntent> routes;
            try {
                if (!parse_push_update_routes(message.substr(12), routes)) return fail();
            } catch (...) { return fail(); }
            pushUpdate(routes);
            return false;  // consumed: our data plane owns route application
        }
        if (message.compare(0, 11, "PUSH_UPDATE") == 0) return fail();
        try {
            auto result = receiver.receive(message);
            using securelink::ctrl::Kind;
            switch (result.kind) {
            case Kind::Ignored:
            case Kind::AuthRefresh: return true;
            case Kind::Partial: return false;
            case Kind::InitialSnapshot:
                message = std::move(result.normalizedInitialMessage);
                return true;
            case Kind::ReloadSnapshot:
                // Parsing is covered; applying reload to a live data plane is
                // not. Never turn the full snapshot into upstream PUSH_UPDATE.
                return fail();
            }
        } catch (...) { return fail(); }
        return fail();
    }
};
// ClientProto owns a strong factory reference and invokes this only from its
// connect() io_context thread. The probe outlives connect(); its deadline thread
// only calls thread-safe stop(), never this receiver or the rejection callback.
// The wrapping factory resets control state when creating a new transport, so
// a reused factory does not confuse reconnect's initial push with auth refresh.
