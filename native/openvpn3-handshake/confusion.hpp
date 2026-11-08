#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace securelink::confusion {

using Bytes = std::vector<std::uint8_t>;
inline constexpr std::size_t maxPayload = 65533;
inline constexpr std::size_t maxWireFrame = 65537;
inline constexpr std::size_t maxFeedInput = maxWireFrame;
inline constexpr std::size_t maxFeedOutput = 2 * maxWireFrame;

// Diagnostics intentionally contain no packet bytes or authentication material.
class CodecError : public std::runtime_error {
public:
    CodecError() : std::runtime_error("invalid or oversized confusion frame") {}
};

inline std::size_t readLength(const std::uint8_t* bytes) noexcept {
    return (static_cast<std::size_t>(bytes[0]) << 8) | bytes[1];
}

inline void appendLength(Bytes& output, std::size_t length) {
    output.push_back(static_cast<std::uint8_t>(length >> 8));
    output.push_back(static_cast<std::uint8_t>(length));
}

// Exactly one standard BE16-length frame. Empty payload is representable here;
// acceptance by the upper OpenVPN protocol is a separate decision.
inline Bytes encodeStandardFrame(const std::uint8_t* input, std::size_t size) {
    if (!input || size < 2 || size > maxPayload + 2)
        throw CodecError();
    const auto length = readLength(input);
    if (length != size - 2 || length > maxPayload)
        throw CodecError();
    Bytes output;
    output.reserve(size + 2);
    appendLength(output, length + 2);
    output.push_back(0);
    output.push_back(0);
    output.insert(output.end(), input + 2, input + size);
    return output;
}

class StreamDecoder {
public:
    // Returns zero or more complete standard frames concatenated in wire order.
    // A call either succeeds entirely or throws and clears pending state. The
    // caller must stop the transport on error; reset permits a fresh connection.
    Bytes feed(const std::uint8_t* input, std::size_t size) {
        try {
            if (size > maxFeedInput || (!input && size != 0))
                throw CodecError();
            Bytes output;
            std::size_t position = 0;
            while (position < size) {
                const auto target = expected_ == 0 ? 2 : expected_;
                const auto amount = std::min(target - pending_.size(), size - position);
                pending_.insert(pending_.end(), input + position, input + position + amount);
                position += amount;
                if (expected_ == 0 && pending_.size() == 2) {
                    const auto length = readLength(pending_.data());
                    if (length < 2)
                        throw CodecError();
                    expected_ = length + 2;
                }
                if (expected_ != 0 && pending_.size() == expected_) {
                    const auto standardSize = expected_ - 2;
                    if (standardSize > maxFeedOutput - output.size())
                        throw CodecError();
                    appendLength(output, expected_ - 4);
                    // Reserved bytes are intentionally not validated: the
                    // recovered vendor decoder merely discards them.
                    output.insert(output.end(), pending_.begin() + 4, pending_.end());
                    reset();
                }
            }
            return output;
        } catch (...) {
            reset();
            throw;
        }
    }

    void reset() noexcept {
        pending_.clear();
        expected_ = 0;
    }

    std::size_t pendingBytes() const noexcept { return pending_.size(); }

private:
    Bytes pending_;
    std::size_t expected_ = 0;
};

} // namespace securelink::confusion
