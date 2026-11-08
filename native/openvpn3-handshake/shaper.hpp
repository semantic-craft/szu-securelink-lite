#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <optional>
#include <stdexcept>
#include <vector>

namespace securelink::shaper {

// Pure scheduling model for the recovered TUN-read window algorithm. This is
// not a socket limiter. Caller owns packet storage and must suspend the read
// slot while its packet is queued. All methods run on one serialized executor.
using Tick = std::uint64_t; // injected 1/1024-second clock
struct Packet {
    std::uint64_t id;
    std::size_t bytes; // includes utun header when present
    bool countExempt = false;
};
enum class Action { Send, Queued, DropReplayExcess, DropCapacity, DropStopped,
                    DropCancelled, DropInvalidPacket };
struct Result { Packet packet; Action action; };

inline std::uint64_t effectiveLimit(std::int32_t value) noexcept {
    return value == 0 ? 0 : static_cast<std::uint64_t>(
        std::min<std::int32_t>(std::max<std::int32_t>(value, 100), 0x50000000));
}

// Mirrors the observed fixed-offset probe predicate, not a general ICMP rule.
inline bool isCountExempt(const std::uint8_t* data, std::size_t size,
                          bool utunHeader) noexcept {
    const std::size_t offset = utunHeader ? 4 : 0;
    if (!data || size < offset + 46) return false;
    const auto* ip = data + offset;
    constexpr std::uint8_t marker[] = {'S','e','c','u','r','e','l','i','n','k'};
    return ip[9] == 1 && ip[2] == 0 && ip[3] == 46
        && (ip[20] == 0 || ip[20] == 8)
        && std::equal(std::begin(marker), std::end(marker), ip + 36);
}

class WindowQueue {
public:
    // Caps are deliberately caller-selected resource policy, not recovered
    // vendor defaults. Tokens only: caller must apply equivalent payload caps.
    WindowQueue(std::int32_t configuredLimit, Tick start,
                std::size_t packetCap, std::size_t byteCap)
        : limit_(effectiveLimit(configuredLimit)), start_(start),
          packetCap_(packetCap), byteCap_(byteCap) {
        if (packetCap == 0 || packetCap > 4096 || byteCap == 0
            || byteCap > 64 * 1024 * 1024)
            throw std::invalid_argument("invalid shaper queue bounds");
    }

    Result submit(Packet packet, Tick now) {
        if (stopped_) return {packet, Action::DropStopped};
        if (packet.bytes == 0 || packet.bytes > 65539)
            return {packet, Action::DropInvalidPacket};
        if (limit_ == 0) return {packet, Action::Send};
        if (!overLimit(packet)) return send(packet);
        const auto elapsed = now > start_ ? now - start_ : 0;
        if (!due_ && elapsed >= 1025) {
            start_ = now;
            counted_ = 0;
            return send(packet);
        }
        if (queue_.size() >= packetCap_ || packet.bytes > byteCap_ - queuedBytes_)
            return {packet, Action::DropCapacity};
        queue_.push_back(packet);
        queuedBytes_ += packet.bytes;
        if (!due_) {
            const auto ms = elapsed - (3 * elapsed) / 128;
            const auto delayMS = ms <= 998 ? 1000 - ms : 1;
            const auto delay = delayMS + (3 * delayMS) / 128;
            due_ = now > std::numeric_limits<Tick>::max() - delay
                ? std::numeric_limits<Tick>::max() : now + delay;
        }
        return {packet, Action::Queued};
    }

    // Caller supplies successful timer completion. Early calls do nothing.
    // No requeue on replay excess: release or drop every queued token in FIFO.
    std::vector<Result> poll(Tick now) {
        std::vector<Result> result;
        if (stopped_ || !due_ || now < *due_) return result;
        result.reserve(queue_.size());
        start_ = now;
        counted_ = 0;
        due_.reset();
        while (!queue_.empty()) {
            const auto packet = queue_.front();
            result.push_back(overLimit(packet)
                ? Result{packet, Action::DropReplayExcess} : send(packet));
            queue_.pop_front();
        }
        queuedBytes_ = 0;
        return result;
    }

    // Chosen fail-closed cancellation policy: drop pending ownership tokens,
    // stop accepting packets, and require explicit restart after cleanup.
    std::vector<Result> cancel() {
        std::vector<Result> result;
        result.reserve(queue_.size());
        for (const auto& packet : queue_) result.push_back({packet, Action::DropCancelled});
        queue_.clear();
        queuedBytes_ = 0;
        counted_ = 0;
        due_.reset();
        stopped_ = true;
        return result;
    }

    void restart(Tick now) {
        if (!queue_.empty()) throw std::logic_error("cancel shaper before restart");
        start_ = now;
        counted_ = 0;
        due_.reset();
        stopped_ = false;
    }
    std::optional<Tick> deadline() const noexcept { return due_; }
    std::size_t queuedPackets() const noexcept { return queue_.size(); }
    std::size_t queuedBytes() const noexcept { return queuedBytes_; }
    std::uint64_t countedBytes() const noexcept { return counted_; }

private:
    bool overLimit(const Packet& packet) const noexcept {
        return limit_ != 0 && counted_ != 0
            && (counted_ > limit_ || packet.bytes > limit_ - counted_);
    }
    Result send(Packet packet) noexcept {
        if (!packet.countExempt) counted_ += packet.bytes;
        return {packet, Action::Send};
    }
    std::uint64_t limit_;
    Tick start_;
    std::size_t packetCap_, byteCap_;
    std::deque<Packet> queue_;
    std::size_t queuedBytes_ = 0;
    std::uint64_t counted_ = 0;
    std::optional<Tick> due_;
    bool stopped_ = false;
};

} // namespace securelink::shaper
