#pragma once
#include "confusion.hpp"
#include <openvpn/transport/mutate.hpp>

// LinkCommon calls pre_send after BE16 framing and post_recv before stream
// deframing. The decoder therefore owns fragmentation state for one connection.
class ConfusionStream final : public openvpn::TransportMutateStream {
    securelink::confusion::StreamDecoder decoder;
    static void replace(openvpn::BufferAllocated &buffer, const securelink::confusion::Bytes &bytes) {
        openvpn::BufferAllocated output(bytes.size(), 0);
        if (!bytes.empty()) output.write(bytes.data(), bytes.size());
        buffer.swap(output);
    }
public:
    void pre_send(openvpn::BufferAllocated &buffer) override {
        replace(buffer, securelink::confusion::encodeStandardFrame(buffer.c_data(), buffer.size()));
    }
    void post_recv(openvpn::BufferAllocated &buffer) override {
        replace(buffer, decoder.feed(buffer.c_data(), buffer.size()));
    }
};
