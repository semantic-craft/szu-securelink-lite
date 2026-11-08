#pragma once
// Minimal IPv4/IPv6 address and prefix math matching CPython 3.15 ipaddress
// behavior for this project's checks: strict dotted-quad without leading
// zeros, RFC-style IPv6 with one "::" and an optional embedded IPv4 tail,
// the reserved/classification lists copied from CPython 3.15, network
// masking with host-bits validation, and canonical formatting. The
// differential test against the Python validator is the authority; these
// helpers only exist to make the C++ side able to agree with it.
#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ip_math {

struct Address {
    int version = 0;                  // 4 or 6
    std::array<uint8_t, 16> bytes{};  // v4 uses the first four bytes
};

using Bytes = std::array<uint8_t, 16>;

inline Bytes to_bytes(const Address &a) {
    Bytes out{};
    for (int i = 0; i < (a.version == 4 ? 4 : 16); i++) out[i] = a.bytes[i];
    return out;
}

inline int compare(const Bytes &a, const Bytes &b) {
    for (int i = 0; i < 16; i++) {
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    }
    return 0;
}

inline Bytes mask(const Bytes &value, int prefix) {
    Bytes out{};
    for (int i = 0; i < 16; i++) {
        const int remaining = prefix - i * 8;
        if (remaining >= 8) out[i] = value[i];
        else if (remaining <= 0) out[i] = 0;
        else out[i] = static_cast<uint8_t>(value[i] & (0xFFu << (8 - remaining)));
    }
    return out;
}

inline void increment(Bytes &value) {
    for (int i = 15; i >= 0; i--) {
        if (++value[i] != 0) return;
    }
}

inline bool network_contains(const Bytes &network, int prefix, const Bytes &value) {
    return compare(mask(network, prefix), mask(value, prefix)) == 0;
}

struct Network {
    Bytes base{};
    int version = 0;
    int prefix = 0;

    bool operator==(const Network &other) const {
        return version == other.version && prefix == other.prefix && base == other.base;
    }
};

inline bool network_less(const Network &a, const Network &b) {
    if (a.version != b.version) return a.version < b.version;
    const int c = compare(a.base, b.base);
    if (c != 0) return c < 0;
    return a.prefix < b.prefix;
}

// CPython 3.15 constants, verbatim semantics.
inline bool reserved_v4(const Address &a) {
    return a.bytes[0] >= 240;
}

inline bool reserved_v6(const Address &a) {
    const uint8_t hi = a.bytes[0];
    const uint8_t second = a.bytes[1];
    if (hi <= 0x01) return true;                // ::/8, 100::/8
    if (hi >= 0x02 && hi <= 0x03) return true;  // 200::/7
    if (hi >= 0x04 && hi <= 0x07) return true;  // 400::/6
    if (hi >= 0x08 && hi <= 0x0F) return true;  // 800::/5
    if (hi >= 0x10 && hi <= 0x1F) return true;  // 1000::/4
    if (hi >= 0x40 && hi <= 0x5F) return true;  // 4000::/3
    if (hi >= 0x60 && hi <= 0x7F) return true;  // 6000::/3 tail (6000::/3 ends 7FFF)
    if (hi >= 0x80 && hi <= 0x9F) return true;  // 8000::/3
    if (hi >= 0xA0 && hi <= 0xBF) return true;  // A000::/3
    if (hi >= 0xC0 && hi <= 0xDF) return true;  // C000::/3
    if (hi >= 0xE0 && hi <= 0xEF) return true;  // E000::/4
    if (hi >= 0xF0 && hi <= 0xF7) return true;  // F000::/5
    if (hi >= 0xF8 && hi <= 0xFB) return true;  // F800::/6
    if (hi == 0xFE && second <= 0x7F) return true;  // FE00::/9
    return false;
}

struct Classification {
    bool unspecified = false;
    bool loopback = false;
    bool multicast = false;
    bool link_local = false;
    bool reserved = false;
};

inline Classification classify(const Address &a) {
    Classification out;
    if (a.version == 4) {
        const bool z0 = a.bytes[0] == 0;
        out.unspecified = z0 && a.bytes[1] == 0 && a.bytes[2] == 0 && a.bytes[3] == 0;
        out.loopback = a.bytes[0] == 127;
        out.multicast = a.bytes[0] >= 224 && a.bytes[0] <= 239;
        out.link_local = a.bytes[0] == 169 && a.bytes[1] == 254;
        out.reserved = reserved_v4(a);
    } else {
        Bytes zero{};
        const Bytes v = to_bytes(a);
        Bytes loop{};
        loop[15] = 1;
        out.unspecified = v == zero;
        out.loopback = v == loop;
        out.multicast = v[0] == 0xFF;
        out.link_local = v[0] == 0xFE && (v[1] & 0xC0) == 0x80;
        out.reserved = reserved_v6(a);
    }
    return out;
}

inline bool rejected_for_assignment(const Address &a) {
    const Classification c = classify(a);
    // network_plan._ip additionally rejects every IPv4 inside 0.0.0.0/8.
    const bool v4_zero_octet = a.version == 4 && a.bytes[0] == 0;
    return c.unspecified || c.loopback || c.multicast || c.link_local || c.reserved || v4_zero_octet;
}

inline std::optional<Address> parse_ipv4(const std::string &text) {
    Address out;
    out.version = 4;
    int parts[4];
    int part = 0;
    long long value = -1;
    size_t digits = 0;
    for (size_t i = 0; i <= text.size(); i++) {
        const char c = i < text.size() ? text[i] : '.';
        if (c == '.') {
            if (value < 0 || value > 255) return std::nullopt;
            if (part == 4) return std::nullopt;
            parts[part++] = static_cast<int>(value);
            value = -1;
            digits = 0;
            continue;
        }
        if (c < '0' || c > '9') return std::nullopt;
        if (value < 0) {
            // A leading zero is only valid as the lone digit "0".
            if (c == '0' && i + 1 < text.size() && text[i + 1] >= '0' && text[i + 1] <= '9') {
                return std::nullopt;
            }
            digits = 1;
            value = c - '0';
            continue;
        }
        if (++digits > 3) return std::nullopt;
        value = value * 10 + (c - '0');
        if (value > 255) return std::nullopt;
    }
    if (part != 4) return std::nullopt;
    for (int i = 0; i < 4; i++) out.bytes[i] = static_cast<uint8_t>(parts[i]);
    return out;
}

inline bool hex_digit(char c, uint32_t &out) {
    if (c >= '0' && c <= '9') { out = static_cast<uint32_t>(c - '0'); return true; }
    if (c >= 'a' && c <= 'f') { out = static_cast<uint32_t>(c - 'a' + 10); return true; }
    if (c >= 'A' && c <= 'F') { out = static_cast<uint32_t>(c - 'A' + 10); return true; }
    return false;
}

inline std::optional<Address> parse_ipv6(const std::string &text) {
    Address out;
    out.version = 6;
    Bytes groups{};
    const size_t double_pos = text.find("::");
    if (text.find("::", double_pos == std::string::npos ? 0 : double_pos + 1) != std::string::npos) {
        return std::nullopt;  // more than one "::"
    }
    const bool compressed = double_pos != std::string::npos;
    const std::string head = compressed ? text.substr(0, double_pos) : text;
    const std::string tail = compressed ? text.substr(double_pos + 2) : "";
    std::vector<std::string> head_segments, tail_segments;
    auto split = [](const std::string &input) {
        std::vector<std::string> parts;
        if (input.empty()) return parts;
        size_t start = 0;
        while (true) {
            const size_t at = input.find(':', start);
            if (at == std::string::npos) {
                parts.push_back(input.substr(start));
                break;
            }
            parts.push_back(input.substr(start, at - start));
            start = at + 1;
        }
        return parts;
    };
    head_segments = split(head);
    tail_segments = split(tail);
    int total = 0;
    auto parse_group = [](const std::string &segment, uint32_t &out) {
        if (segment.empty() || segment.size() > 4) return false;
        out = 0;
        for (char c : segment) {
            uint32_t d;
            if (!hex_digit(c, d)) return false;
            out = (out << 4) | d;
        }
        return true;
    };
    auto parse_v4_tail = [&](const std::string &segment, int position) {
        const auto v4 = parse_ipv4(segment);
        if (!v4.has_value() || position + 2 > 16) return false;
        groups[static_cast<size_t>(position)] = v4->bytes[0];
        groups[static_cast<size_t>(position) + 1] = v4->bytes[1];
        groups[static_cast<size_t>(position) + 2] = v4->bytes[2];
        groups[static_cast<size_t>(position) + 3] = v4->bytes[3];
        return true;
    };
    int written = 0;
    auto append_group = [&](uint32_t value) {
        if (written + 2 > 16) return false;
        groups[static_cast<size_t>(written)] = static_cast<uint8_t>(value >> 8);
        groups[static_cast<size_t>(written) + 1] = static_cast<uint8_t>(value & 0xFF);
        written += 2;
        return true;
    };
    auto append_segment_list = [&](const std::vector<std::string> &segments, bool allow_v4_last) {
        for (size_t i = 0; i < segments.size(); i++) {
            const std::string &segment = segments[i];
            const bool last = i + 1 == segments.size();
            if (last && allow_v4_last && segment.find('.') != std::string::npos) {
                if (!parse_v4_tail(segment, written)) return false;
                written += 4;
                continue;
            }
            uint32_t value;
            if (!parse_group(segment, value)) return false;
            if (!append_group(value)) return false;
        }
        return true;
    };
    if (!compressed) {
        if (!append_segment_list(head_segments, true)) return std::nullopt;
        total = written;
        if (total != 16) return std::nullopt;
    } else {
        if (!head_segments.empty() && !append_segment_list(head_segments, false)) return std::nullopt;
        const int before_tail = written;
        if (!tail_segments.empty() && !append_segment_list(tail_segments, true)) return std::nullopt;
        if (written > 14) return std::nullopt;  // "::" must expand to at least one zero group
        // shift tail groups to the end
        const int tail_bytes = written - before_tail;
        if (tail_bytes > 0 && before_tail < 16) {
            Bytes shifted{};
            for (int i = 0; i < tail_bytes; i++) {
                shifted[static_cast<size_t>(15 - i)] =
                    groups[static_cast<size_t>(written - 1 - i)];
            }
            for (int i = 0; i < tail_bytes; i++) {
                groups[static_cast<size_t>(15 - i)] = shifted[static_cast<size_t>(15 - i)];
            }
            for (int i = before_tail; i < 16 - tail_bytes; i++) groups[static_cast<size_t>(i)] = 0;
        } else {
            for (int i = before_tail; i < 16; i++) groups[static_cast<size_t>(i)] = 0;
        }
        total = 16;
    }
    out.bytes = groups;
    return out;
}

inline std::optional<Address> parse_address(const std::string &text) {
    if (text.empty() || text.size() > 45 || text.find('%') != std::string::npos) return std::nullopt;
    if (text.find(':') != std::string::npos) return parse_ipv6(text);
    return parse_ipv4(text);
}

inline std::string format_v4(const Address &a) {
    std::string out;
    for (int i = 0; i < 4; i++) {
        if (i != 0) out.push_back('.');
        out += std::to_string(a.bytes[static_cast<size_t>(i)]);
    }
    return out;
}

inline std::string format_v6(const Address &a) {
    uint32_t groups[8];
    for (int i = 0; i < 8; i++) {
        groups[i] = (static_cast<uint32_t>(a.bytes[static_cast<size_t>(i * 2)]) << 8) |
                    a.bytes[static_cast<size_t>(i * 2 + 1)];
    }
    int best_start = -1, best_length = 0;
    int current_start = -1, current_length = 0;
    for (int i = 0; i < 8; i++) {
        if (groups[i] == 0) {
            if (current_start < 0) current_start = i;
            current_length++;
            if (current_length > best_length) {
                best_start = current_start;
                best_length = current_length;
            }
        } else {
            current_start = -1;
            current_length = 0;
        }
    }
    std::string out;
    if (best_length <= 1) best_start = -1;
    auto append_group = [&](int index) {
        static const char *kHex = "0123456789abcdef";
        char buffer[5];
        int length = 0;
        uint32_t value = groups[index];
        if (value == 0) {
            buffer[length++] = '0';
        } else {
            while (value != 0) {
                buffer[length++] = kHex[value & 0xF];
                value >>= 4;
            }
        }
        for (int i = length - 1; i >= 0; i--) out.push_back(buffer[i]);
    };
    for (int i = 0; i < 8; i++) {
        if (i == best_start) {
            out += i == 0 ? "::" : ":";
            i += best_length - 1;
            if (i == 7) {
                // The zero run reaches the last group: RFC 5952 needs "::".
                if (best_start != 0) out.push_back(':');
                break;
            }
            continue;
        }
        if (i != 0) out.push_back(':');
        append_group(i);
    }
    return out;
}

inline std::string format(const Address &a) {
    return a.version == 4 ? format_v4(a) : format_v6(a);
}

inline std::optional<Network> make_network(const std::string &address_text, int prefix, bool strict) {
    const auto address = parse_address(address_text);
    if (!address.has_value()) return std::nullopt;
    const int max_prefix = address->version == 4 ? 32 : 128;
    if (prefix < 0 || prefix > max_prefix) return std::nullopt;
    const Bytes raw = to_bytes(*address);
    const Bytes masked = mask(raw, prefix);
    if (strict && compare(raw, masked) != 0) return std::nullopt;
    Network out;
    out.base = masked;
    out.version = address->version;
    out.prefix = prefix;
    return out;
}

inline Bytes range_end(const Network &net) {
    Bytes out = net.base;
    const int bits = net.version == 4 ? 32 : 128;
    for (int bit = net.prefix; bit < bits; bit++) {
        const int byte = bit / 8;
        const int offset = 7 - (bit % 8);
        out[static_cast<size_t>(byte)] |= static_cast<uint8_t>(1u << offset);
    }
    return out;
}

// True when the union of same-family networks covers one of the two half
// spaces, which is exactly when CPython's collapse_addresses would yield a
// network with prefixlen <= 1. Used only for the global-route-union check.
inline bool covers_half_space(const std::vector<Network> &networks, int version, int half) {
    const int nbytes = version == 4 ? 4 : 16;
    Bytes half_start{}, half_end{};
    if (half == 0) {
        half_end[0] = 0x7F;
        for (int i = 1; i < nbytes; i++) half_end[static_cast<size_t>(i)] = 0xFF;
    } else {
        half_start[0] = 0x80;
        for (int i = 0; i < nbytes; i++) half_end[static_cast<size_t>(i)] = 0xFF;
    }
    std::vector<const Network *> same_family;
    for (const Network &net : networks) {
        if (net.version == version) same_family.push_back(&net);
    }
    std::sort(same_family.begin(), same_family.end(),
              [](const Network *a, const Network *b) { return compare(a->base, b->base) < 0; });
    bool covered_any = false;
    Bytes covered{};
    for (const Network *net : same_family) {
        const Bytes end = range_end(*net);
        if (compare(end, half_start) < 0) continue;   // entirely before the half
        if (compare(net->base, half_end) > 0) break;  // sorted: everything after is too
        if (covered_any && compare(net->base, covered) > 0) {
            Bytes next = covered;
            increment(next);
            if (compare(net->base, next) > 0) return false;  // unreachable gap
        }
        covered_any = true;
        if (compare(end, covered) > 0) covered = end;
        if (compare(covered, half_end) >= 0) return true;
    }
    return false;
}

}  // namespace ip_math
