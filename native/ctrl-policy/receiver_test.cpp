#define OPENVPN_LOG_NTNL(...) do {} while (false)
#include "receiver.hpp"
#include <cassert>
#include <iostream>
using namespace securelink::ctrl;
static const std::string first = "ctrl domain:one.example sourceIp:192.0.2.1";
static const std::string second = "ctrl domain:two.example sourceIp:192.0.2.2";
static std::string packed(const std::string &csv, unsigned capacity = 0) {
    if (!capacity) capacity = static_cast<unsigned>(csv.size() + 8);
    std::string wire(4, '\0');
    for (int i = 0; i < 4; ++i) wire[i] = static_cast<char>(capacity >> (24 - i * 8));
    std::string block(LZ4_compressBound(static_cast<int>(csv.size())), '\0');
    auto count = LZ4_compress_default(csv.data(), block.data(), static_cast<int>(csv.size()), static_cast<int>(block.size()));
    assert(count > 0);
    wire.append(block.data(), count);
    return openvpn::Base64().encode(wire);
}
static void rejects(Receiver &r, const std::string &message) {
    const auto old = r.generation();
    const auto size = r.snapshot().mappings.size();
    try { r.receive(message); assert(false); }
    catch (const ReceiveError &error) { assert(std::string(error.what()) == "unsupported control message"); }
    assert(r.generation() == old && r.snapshot().mappings.size() == size);
}
int main() {
    Receiver r;
    assert(r.receive("INFO,synthetic-secret").kind == Kind::Ignored);
    rejects(r, "PUSH_RELOAD_ALL," + first);
    rejects(r, "PUSH_REPLY" + first);
    rejects(r, "PUSH_REPLY," + first + ",push-continuation 1");
    assert(r.receive("PUSH_REPLY," + first + ",push-continuation 2").kind == Kind::Partial);
    rejects(r, "PUSH_RELOAD_ALL," + second); // must not clear initial assembly
    auto initial = r.receive("PUSH_REPLY," + second + ",push-continuation 1");
    assert(initial.kind == Kind::InitialSnapshot && initial.snapshot.mappings.size() == 2);
    assert(initial.normalizedInitialMessage == "PUSH_REPLY," + first + "," + second);
    for (unsigned i = 0; i != 3; ++i) {
        auto refresh = r.receive("PUSH_REPLY,auth-token synthetic-secret," + second);
        assert(refresh.kind == Kind::AuthRefresh && refresh.normalizedInitialMessage.empty());
        assert(r.generation() == 1 && r.snapshot().mappings.size() == 2);
    }
    rejects(r, "PUSH_RELOAD_ALL,auth-token synthetic-secret,ctrl domain:bad sourceIp:invalid-secret");
    rejects(r, "PUSH_RELOAD_ALL,ctrl \"unterminated synthetic-secret");
    rejects(r, "PUSH_RELOAD_ALL_LZ4,invalid-secret");
    rejects(r, "PUSH_RELOAD_ALL_LZ4," + packed(second, receiveByteLimit + 1));
    rejects(r, "PUSH_RELOAD_ALL_LZ4," + packed(second, 1));
    rejects(r, "PUSH_RELOAD_ALL," + std::string("\xff", 1));
    rejects(r, "PUSH_RELOAD_ALL," + second + "\n");
    rejects(r, "PUSH_RELOAD_ALL,auth-token synthetic-secret\xc2\x85");
    rejects(r, "PUSH_RELOAD_ALL," + std::string(receiveByteLimit, 'a'));
    const auto encoded = packed(second + std::string(1, '\0'));
    assert(r.receive("PUSH_RELOAD_ALL_LZ4," + encoded.substr(0, 11) + ",push-continuation 2").kind == Kind::Partial);
    assert(r.receive("PUSH_REPLY,auth-token synthetic-secret").kind == Kind::AuthRefresh);
    auto loaded = r.receive("PUSH_RELOAD_ALL_LZ4," + encoded.substr(11) + ",push-continuation 1");
    assert(loaded.kind == Kind::ReloadSnapshot && loaded.normalizedInitialMessage.empty());
    assert(r.generation() == 2 && r.snapshot().mappings[0].domain == "two.example");
    rejects(r, "PUSH_RELOAD_ALL_LZ4," + packed(second + std::string(2, '\0')));
    r.receive("PUSH_RELOAD_ALL,");
    assert(r.generation() == 3 && r.snapshot().mappings.empty());
    r.receive("PUSH_RELOAD_ALL,ctrl \"domain:quoted.example sourceIp:192.0.2.9\"");
    assert(r.snapshot().mappings[0].domain == "quoted.example");
    r.receive("PUSH_RELOAD_ALL," + first + ",push-continuation 2");
    rejects(r, "PUSH_RELOAD_ALL_LZ4," + encoded + ",push-continuation 1");
    r.receive("PUSH_RELOAD_ALL," + second);
    for (unsigned n = 0; n < receiveFragmentLimit; ++n)
        r.receive("PUSH_RELOAD_ALL,route 192.0.2.1,push-continuation 2");
    rejects(r, "PUSH_RELOAD_ALL,,push-continuation 1");
    r.receive("PUSH_RELOAD_ALL," + first);
    for (unsigned n = 0; n < 3; ++n)
        r.receive("PUSH_RELOAD_ALL," + std::string(receiveByteLimit / 4, 'x') + ",push-continuation 2");
    rejects(r, "PUSH_RELOAD_ALL," + std::string(receiveByteLimit / 4, 'x') + ",push-continuation 1");
    Receiver exactly32;
    for (unsigned n = 0; n < receiveFragmentLimit - 1; ++n)
        exactly32.receive("PUSH_REPLY,route 192.0.2.1,push-continuation 2");
    assert(exactly32.receive("PUSH_REPLY," + first + ",push-continuation 1").kind == Kind::InitialSnapshot);
    assert(exactly32.snapshot().mappings.size() == 1);
    Receiver compressedInitial;
    auto decoded = compressedInitial.receive("PUSH_REPLY_LZ4," + packed(first));
    assert(decoded.normalizedInitialMessage == "PUSH_REPLY," + first);
    // Capacity is an upper bound; zero-length valid CSV still means empty full snapshot.
    compressedInitial.receive("PUSH_RELOAD_ALL_LZ4," + packed("", 1));
    assert(compressedInitial.snapshot().mappings.empty());
    rejects(compressedInitial, "PUSH_RELOAD_ALL_LZ4,AAAAAf8=");
    assert(compressedInitial.generation() == 2);
    std::cout << "ctrl receiver: passed\n";
}
