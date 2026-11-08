#include "effects.hpp"
#include <cassert>
#include <iostream>
using namespace securelink::ctrl;
int main() {
    Effects effects;
    effects.replace({{"ctrl", "domain:a.example", "sourceIp:192.0.2.1;192.0.2.2"},
                     {"ctrl", "domain:b.example", "sourceIp:192.0.2.2"}});
    auto routes = effects.initialRoutes();
    assert(routes.size() == 2 && routes[0].address == "192.0.2.1");
    assert(routes[0].prefix == 32 && routes[0].metric == 0);
    std::array<std::uint8_t, 24> packet{};
    packet[0] = 0x45; packet[3] = 24; packet[9] = 6;
    packet[16] = 192; packet[18] = 2; packet[19] = 1;
    assert(effects.classify(packet.data(), packet.size()) == PacketDecision::DestinationAllowed);
    // any/any allows every protocol/port, including non-initial fragments.
    packet[9] = 1; packet[6] = 0x20; packet[7] = 1;
    assert(effects.classify(packet.data(), packet.size()) == PacketDecision::DestinationAllowed);
    packet[19] = 3;
    packet[12] = 192; packet[14] = 2; packet[15] = 1;
    assert(effects.classify(packet.data(), packet.size()) == PacketDecision::NotCovered);
    packet[19] = 2;
    effects.replace({{"ctrl", "domain:b.example", "sourceIp:192.0.2.2"}});
    assert(effects.initialRoutes().size() == 1); // shared destination remains
    try { effects.replace({{"ctrl", "sourceIp:invalid-secret"}}); assert(false); } catch (const Invalid &) {}
    assert(effects.classify(packet.data(), packet.size()) == PacketDecision::DestinationAllowed);
    for (std::size_t size = 0; size < packet.size(); ++size)
        assert(effects.classify(packet.data(), size) == PacketDecision::InvalidIPv4);
    packet[0] = 0x4f;
    assert(effects.classify(packet.data(), packet.size()) == PacketDecision::InvalidIPv4);
    packet[0] = 0x46; // valid IPv4 options, no fixed-offset port dependency
    assert(effects.classify(packet.data(), packet.size()) == PacketDecision::DestinationAllowed);
    packet[0] = 0x60;
    assert(effects.classify(packet.data(), packet.size()) == PacketDecision::UnsupportedFamily);
    packet[0] = 0x45;
    effects.replace({});
    assert(effects.initialRoutes().empty());
    assert(effects.classify(packet.data(), packet.size()) == PacketDecision::NotCovered);
    std::cout << "ctrl effects: passed\n";
}
