#include "confusion.hpp"
#include <iostream>

using namespace securelink::confusion;

static void require(bool value) {
    if (!value) throw std::runtime_error("test failed");
}

template<class F> static void rejects(F action) {
    bool rejected = false;
    try { action(); } catch (const CodecError&) { rejected = true; }
    require(rejected);
}

static Bytes encode(const Bytes& frame) {
    return encodeStandardFrame(frame.data(), frame.size());
}
static Bytes feed(StreamDecoder& decoder, const Bytes& data) {
    return decoder.feed(data.data(), data.size());
}
static void append(Bytes& result, const Bytes& part) {
    result.insert(result.end(), part.begin(), part.end());
}

int main() {
    try {
        const Bytes standard{0, 3, 0x40, 1, 2};
        const Bytes wire{0, 5, 0, 0, 0x40, 1, 2};
        require(encode(standard) == wire);
        for (std::size_t split = 0; split <= wire.size(); ++split) {
            StreamDecoder d;
            auto result = d.feed(wire.data(), split);
            append(result, d.feed(wire.data() + split, wire.size() - split));
            require(result == standard && d.pendingBytes() == 0);
        }
        StreamDecoder d;
        Bytes result;
        for (const auto byte : wire) append(result, d.feed(&byte, 1));
        require(result == standard);
        Bytes multiple = wire;
        append(multiple, wire);
        auto doubled = standard;
        append(doubled, standard);
        require(feed(d, multiple) == doubled);
        auto reserved = wire;
        reserved[2] = 0xaa; reserved[3] = 0xbb;
        require(feed(d, reserved) == standard);
        require(encode(Bytes{0, 0}) == Bytes({0, 2, 0, 0}));
        require(feed(d, Bytes{0, 2, 0xaa, 0xbb}) == Bytes({0, 0}));

        Bytes largest{0xff, 0xfd};
        largest.resize(maxPayload + 2, 0x5a);
        const auto largestWire = encode(largest);
        require(largestWire.size() == maxWireFrame);
        require(largestWire[0] == 0xff && largestWire[1] == 0xff);
        require(feed(d, largestWire) == largest);
        // Maximum residual plus a full input chunk can produce multiple frames.
        require(d.feed(largestWire.data(), largestWire.size() - 1).empty());
        require(d.pendingBytes() == maxWireFrame - 1);
        Bytes chunk{largestWire.back()};
        append(chunk, wire);
        auto expected = largest;
        append(expected, standard);
        require(feed(d, chunk) == expected);
        // Large frame byte-by-byte, not just the short vector.
        result.clear();
        for (const auto byte : largestWire) append(result, d.feed(&byte, 1));
        require(result == largest);

        rejects([&] { feed(d, Bytes{0, 0}); });
        rejects([&] { feed(d, Bytes{0, 1, 0}); });
        rejects([&] { encode(Bytes{0, 3, 1}); });
        rejects([&] { encode(Bytes{0, 0, 1}); });
        rejects([&] { encode(Bytes{}); });
        rejects([&] { encode(Bytes{0}); });
        rejects([&] { encodeStandardFrame(nullptr, 2); });
        auto tooLarge = largest;
        tooLarge.push_back(0); tooLarge[1] = 0xfe;
        rejects([&] { encode(tooLarge); });
        require(d.feed(wire.data(), 1).empty());
        rejects([&] { d.feed(nullptr, 1); });
        require(d.pendingBytes() == 0);
        require(feed(d, wire) == standard);
        require(d.feed(wire.data(), 1).empty());
        Bytes overInput(maxFeedInput + 1, 0);
        rejects([&] { feed(d, overInput); });
        require(d.pendingBytes() == 0 && feed(d, wire) == standard);
        auto badTail = wire;
        append(badTail, Bytes{0, 1});
        rejects([&] { feed(d, badTail); });
        require(d.pendingBytes() == 0 && feed(d, wire) == standard);
        require(d.feed(wire.data(), 3).empty());
        d.reset();
        require(d.pendingBytes() == 0 && feed(d, wire) == standard);
        require(d.feed(nullptr, 0).empty());
        StreamDecoder other;
        require(other.feed(wire.data(), 1).empty());
        require(feed(d, wire) == standard && other.pendingBytes() == 1);
        std::cout << "confusion codec: passed\n";
        return 0;
    } catch (...) {
        std::cerr << "confusion codec: failed\n";
        return 1;
    }
}
