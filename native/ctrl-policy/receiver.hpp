#pragma once
#include "parser.hpp"
#include <cstdint>
#include <openvpn/common/base64.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/unicode.hpp>
#include <lz4.h>

namespace securelink::ctrl {
inline constexpr std::size_t receiveByteLimit = 1024 * 1024;
inline constexpr std::size_t receiveFragmentLimit = 32;
enum class ReceiveFailure { Framing, Sequence, Limit, Encoding, Compression, CSV, Policy };
struct ReceiveError : std::runtime_error {
    ReceiveFailure failure;
    explicit ReceiveError(ReceiveFailure reason)
        : std::runtime_error("unsupported control message"), failure(reason) {}
};
enum class Kind { Ignored, Partial, InitialSnapshot, ReloadSnapshot, AuthRefresh };
struct Reception {
    Kind kind = Kind::Ignored;
    Snapshot snapshot;
    // Private engine handoff ONLY, never a diagnostic/receipt field. May contain
    // auth-token. Full reload deliberately has no standard PUSH_UPDATE mapping.
    std::string normalizedInitialMessage;
};
class Receiver {
    struct Pending {
        std::string payload;
        std::size_t bytes = 0, fragments = 0;
        bool compressed = false;
    };
    Pending initial_, reload_;
    Snapshot active_;
    std::size_t generation_ = 0;
    static bool starts(const std::string &s, const std::string &prefix) {
        return s.compare(0, prefix.size(), prefix) == 0;
    }
    static bool ends(const std::string &s, const std::string &suffix) {
        return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
    }
    static std::string decompress(const std::string &encoded) {
        try {
            openvpn::Base64 codec;
            if (encoded.empty() || encoded.size() % 4) throw ReceiveError(ReceiveFailure::Encoding);
            const auto data = codec.decode(encoded);
            // Round-trip also rejects noncanonical padding, ignored trailing bits
            // and a padding token in the middle of an otherwise decodable string.
            if (codec.encode(data) != encoded || data.size() < 5)
                throw ReceiveError(ReceiveFailure::Encoding);
            std::uint32_t capacity = 0;
            for (unsigned i = 0; i < 4; ++i)
                capacity = (capacity << 8) | static_cast<unsigned char>(data[i]);
            if (!capacity || capacity > receiveByteLimit) throw ReceiveError(ReceiveFailure::Limit);
            std::string result(capacity, '\0');
            const auto actual = LZ4_decompress_safe(data.data() + 4, result.data(),
                static_cast<int>(data.size() - 4), static_cast<int>(capacity));
            if (actual < 0 || static_cast<unsigned>(actual) > capacity)
                throw ReceiveError(ReceiveFailure::Compression);
            result.resize(static_cast<std::size_t>(actual));
            if (!result.empty() && result.back() == '\0') result.pop_back();
            return result;
        } catch (const ReceiveError &) { throw; }
        catch (...) { throw ReceiveError(ReceiveFailure::Encoding); }
    }
    static Snapshot readPolicy(const std::string &csv, bool policy) {
        if (!openvpn::Unicode::is_valid_utf8(csv, openvpn::Unicode::UTF8_NO_CTRL))
            throw ReceiveError(ReceiveFailure::Encoding);
        // Upstream UTF8_NO_CTRL covers ASCII controls; also reject Unicode C1.
        for (std::size_t i = 1; i < csv.size(); ++i)
            if (static_cast<unsigned char>(csv[i - 1]) == 0xc2
                && static_cast<unsigned char>(csv[i]) >= 0x80
                && static_cast<unsigned char>(csv[i]) <= 0x9f)
                throw ReceiveError(ReceiveFailure::Encoding);
        try {
            openvpn::OptionList::Limits limits("control input limit", receiveByteLimit * 4,
                32, 16, receiveByteLimit, 256);
            auto parsed = openvpn::OptionList::parse_from_csv_static(csv, &limits);
            Options rows;
            for (const auto &option : parsed) {
                if (option.empty()) continue;
                if (option.get(0, 256) == "push-continuation") throw ReceiveError(ReceiveFailure::Sequence);
                if (policy && option.get(0, 256) == "ctrl") {
                    Option row;
                    for (std::size_t i = 0; i < option.size(); ++i) row.push_back(option.get(i, receiveByteLimit));
                    rows.push_back(std::move(row));
                }
            }
            return parse(rows);
        } catch (const ReceiveError &) { throw; }
        catch (const Invalid &) { throw ReceiveError(ReceiveFailure::Policy); }
        catch (...) { throw ReceiveError(ReceiveFailure::CSV); }
    }
public:
    const Snapshot &snapshot() const { return active_; }
    std::size_t generation() const { return generation_; }
    bool initialized() const { return generation_ != 0; }
    Reception receive(const std::string &message) {
        const bool reload = starts(message, "PUSH_RELOAD_ALL");
        const bool initial = starts(message, "PUSH_REPLY");
        if (!reload && !initial) return {};
        Pending &stored = reload ? reload_ : initial_;
        try {
            if (message.size() > receiveByteLimit) throw ReceiveError(ReceiveFailure::Limit);
            const std::string prefix = reload ? "PUSH_RELOAD_ALL" : "PUSH_REPLY";
            const bool compressed = starts(message, prefix + "_LZ4,");
            const auto framing = prefix + (compressed ? "_LZ4," : ",");
            if (!starts(message, framing)) throw ReceiveError(ReceiveFailure::Framing);
            if (reload && !initialized()) throw ReceiveError(ReceiveFailure::Sequence);
            auto payload = message.substr(framing.size());
            if (initial && initialized()) {
                if (compressed) throw ReceiveError(ReceiveFailure::Sequence);
                readPolicy(payload, false);
                return {Kind::AuthRefresh, active_, {}};
            }
            unsigned continuation = 0;
            for (unsigned n : {1U, 2U}) {
                const auto suffix = ",push-continuation " + std::to_string(n);
                if (ends(payload, suffix)) {
                    payload.resize(payload.size() - suffix.size());
                    continuation = n;
                    break;
                }
            }
            Pending next = stored;
            if ((next.fragments && (compressed != next.compressed || continuation == 0))
                || (!next.fragments && continuation == 1)) throw ReceiveError(ReceiveFailure::Sequence);
            if (next.fragments >= receiveFragmentLimit || message.size() > receiveByteLimit - next.bytes)
                throw ReceiveError(ReceiveFailure::Limit);
            next.bytes += message.size();
            ++next.fragments;
            next.compressed = compressed;
            next.payload += payload;
            if (continuation == 2) {
                if (!compressed) next.payload += ',';
                stored = std::move(next);
                return {Kind::Partial, active_, {}};
            }
            auto csv = compressed ? decompress(next.payload) : std::move(next.payload);
            auto candidate = readPolicy(csv, true);
            Reception result{reload ? Kind::ReloadSnapshot : Kind::InitialSnapshot,
                candidate, reload ? std::string{} : "PUSH_REPLY," + csv};
            // Construct all potentially throwing result fields before commit.
            active_ = std::move(candidate);
            ++generation_;
            stored = {};
            return result;
        } catch (const ReceiveError &) { stored = {}; throw; }
        catch (...) { stored = {}; throw ReceiveError(ReceiveFailure::CSV); }
    }
};
} // namespace securelink::ctrl
