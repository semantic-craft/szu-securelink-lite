#pragma once
#include "parser.hpp"
#include <array>
#include <cstdint>
#include <set>

namespace securelink::ctrl {
// Pure intent and packet classification, never an OS route installer. Other
// vendor policy sources must be evaluated separately on NotCovered; this class
// cannot authorize an entire session or silently replace the full FastTable.
enum class PacketDecision { DestinationAllowed, NotCovered, InvalidIPv4, UnsupportedFamily };
struct HostRouteIntent { std::string address; unsigned prefix = 32; int metric = 0; };
class Effects {
    std::set<std::array<std::uint8_t, 4>> destinations_;
    static std::array<std::uint8_t, 4> bytes(const std::string &address) {
        std::array<std::uint8_t, 4> result{};
        unsigned part = 0, number = 0;
        for (char c : address) {
            if (c == '.') { result[part++] = static_cast<std::uint8_t>(number); number = 0; }
            else number = number * 10 + static_cast<unsigned>(c - '0');
        }
        result[part] = static_cast<std::uint8_t>(number);
        return result;
    }
public:
    // Parse/build first, then replace together. Bad policy never erases old state.
    void replace(const Options &options) {
        auto next = parse(options);
        std::set<std::array<std::uint8_t, 4>> destinations;
        for (const auto &mapping : next.mappings)
            for (const auto &address : mapping.addresses) destinations.insert(bytes(address));
        destinations_ = std::move(destinations);
    }
    std::vector<HostRouteIntent> initialRoutes() const {
        std::vector<HostRouteIntent> routes;
        for (const auto &ip : destinations_) {
            std::string address;
            for (unsigned i = 0; i < 4; ++i) {
                if (i) address += '.';
                address += std::to_string(ip[i]);
            }
            routes.push_back({std::move(address), 32, 0});
        }
        return routes;
    }
    // Input is a complete IP datagram without the Darwin utun family prefix.
    // any/any needs no port read, including fragments. Validate header bounds
    // rather than copying the vendor's fixed-offset transport-port read.
    PacketDecision classify(const std::uint8_t *packet, std::size_t size) const {
        if (!packet || !size) return PacketDecision::InvalidIPv4;
        if ((packet[0] >> 4) != 4) return PacketDecision::UnsupportedFamily;
        if (size < 20) return PacketDecision::InvalidIPv4;
        const auto header = static_cast<std::size_t>(packet[0] & 15) * 4;
        const auto total = (static_cast<std::size_t>(packet[2]) << 8) | packet[3];
        if (header < 20 || header > size || total != size || total < header)
            return PacketDecision::InvalidIPv4;
        std::array<std::uint8_t, 4> destination{packet[16], packet[17], packet[18], packet[19]};
        return destinations_.count(destination) ? PacketDecision::DestinationAllowed : PacketDecision::NotCovered;
    }
};
} // namespace securelink::ctrl
