#pragma once
#include <arpa/nameser.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace securelink::dns {
// RFC 1035 sections 4.1 and 4.1.4; compression is decoded by the platform
// resolver library. This is a bounded message parser, not a DNS proxy or route
// authorization policy. The transport must authenticate the response endpoint.
struct Invalid : std::runtime_error { Invalid() : std::runtime_error("invalid DNS message") {} };
struct Question { unsigned id; std::string name; unsigned type; };
struct Address { unsigned type; std::array<std::uint8_t, 16> bytes{}; std::uint32_t ttl; };
struct Reply { bool truncated = false; unsigned rcode = 0; std::vector<Address> addresses; };
inline std::string normalize(std::string name) {
    if (!name.empty() && name.back() == '.') name.pop_back();
    if (name.empty() || name.size() > 253) throw Invalid();
    std::size_t length = 0;
    for (char &c : name) {
        if (c == '.') { if (!length || length > 63) throw Invalid(); length = 0; }
        else {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) throw Invalid();
            if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
            ++length;
        }
    }
    if (!length || length > 63) throw Invalid();
    return name;
}
// RFC 2181 section 8: the sign bit is not part of the TTL range.
inline std::uint32_t lifetime(std::uint32_t ttl) {
    return (ttl & 0x80000000u) ? 0 : ttl;
}
inline Reply parse(const std::uint8_t *data, std::size_t size, const Question &expected) {
    if (!data || size < 12 || size > 65535 || expected.id > 65535
        || (expected.type != ns_t_a && expected.type != ns_t_aaaa)) throw Invalid();
    ns_msg message{};
    if (ns_initparse(data, static_cast<int>(size), &message) != 0
        || ns_msg_id(message) != expected.id || !ns_msg_getflag(message, ns_f_qr)
        || ns_msg_getflag(message, ns_f_z)
        || ns_msg_getflag(message, ns_f_opcode) != ns_o_query || ns_msg_count(message, ns_s_qd) != 1) throw Invalid();
    unsigned count = 0;
    for (auto section : {ns_s_an, ns_s_ns, ns_s_ar}) count += ns_msg_count(message, section);
    if (count > 256) throw Invalid();
    ns_rr question{};
    if (ns_parserr(&message, ns_s_qd, 0, &question) != 0 || ns_rr_class(question) != ns_c_in
        || ns_rr_type(question) != expected.type || normalize(ns_rr_name(question)) != normalize(expected.name)) throw Invalid();
    Reply result;
    result.truncated = ns_msg_getflag(message, ns_f_tc);
    result.rcode = ns_msg_getflag(message, ns_f_rcode);
    // OPT is metadata, not an address. Its high RCODE octet must be read
    // before deciding that this is a successful reply (RFC 6891 section 6.1).
    bool optSeen = false;
    for (auto section : {ns_s_an, ns_s_ns, ns_s_ar}) {
        for (int i = 0; i < ns_msg_count(message, section); ++i) {
            ns_rr record{};
            if (ns_parserr(&message, section, i, &record) != 0) throw Invalid();
            if (ns_rr_type(record) != ns_t_opt) continue;
            if (section != ns_s_ar || optSeen || std::string(ns_rr_name(record)) != ".") throw Invalid();
            optSeen = true;
            const auto metadata = ns_rr_ttl(record);
            if (((metadata >> 16) & 0xff) != 0) throw Invalid(); // unsupported EDNS version
            result.rcode |= static_cast<unsigned>(metadata >> 24) << 4;
            // Check option tuple bounds even though no option authorizes routes.
            std::size_t offset = 0, length = ns_rr_rdlen(record);
            const auto* bytes = ns_rr_rdata(record);
            while (offset < length) {
                if (length - offset < 4) throw Invalid();
                const auto optionLength = (static_cast<unsigned>(bytes[offset + 2]) << 8) | bytes[offset + 3];
                offset += 4;
                if (optionLength > length - offset) throw Invalid();
                offset += optionLength;
            }
        }
    }
    if (result.truncated || result.rcode != ns_r_noerror) return result; // never derive routes from partial/error replies
    struct Alias { std::string target; std::uint32_t ttl; };
    std::map<std::string, Alias> aliases;
    std::set<std::string> nonAliasOwners;
    std::map<std::string, std::vector<Address>> records;
    for (int i = 0; i < ns_msg_count(message, ns_s_an); ++i) {
        ns_rr record{};
        if (ns_parserr(&message, ns_s_an, i, &record) != 0) throw Invalid();
        if (ns_rr_class(record) != ns_c_in) continue;
        const auto owner = normalize(ns_rr_name(record));
        const auto type = ns_rr_type(record);
        if (type == ns_t_cname) {
            char target[NS_MAXDNAME]{};
            const int consumed = ns_name_uncompress(data, data + size, ns_rr_rdata(record), target, sizeof(target));
            if (consumed < 0 || consumed != ns_rr_rdlen(record)) throw Invalid();
            Alias alias{normalize(target), lifetime(ns_rr_ttl(record))};
            auto found = aliases.find(owner);
            if (found != aliases.end() && found->second.target != alias.target) throw Invalid();
            if (found == aliases.end()) aliases.emplace(owner, alias);
            else found->second.ttl = std::min(found->second.ttl, alias.ttl);
        } else {
            // DNSSEC metadata may coexist with CNAME; ordinary data may not.
            // Numeric constants retain compatibility with older nameser SDKs:
            // SIG=24, KEY=25, NXT=30, RRSIG=46, NSEC=47.
            if (type != 24 && type != 25 && type != 30 && type != 46 && type != 47)
                nonAliasOwners.insert(owner);
            if (type != expected.type) continue;
            const unsigned length = type == ns_t_a ? 4 : 16;
            if (ns_rr_rdlen(record) != length) throw Invalid();
            Address address{static_cast<unsigned>(type), {}, lifetime(ns_rr_ttl(record))};
            std::copy_n(ns_rr_rdata(record), length, address.bytes.begin());
            records[owner].push_back(address);
        }
    }
    std::string name = normalize(expected.name);
    std::set<std::string> visited;
    std::uint32_t ttl = UINT32_MAX;
    for (unsigned hops = 0; hops <= 16; ++hops) {
        if (!visited.insert(name).second) throw Invalid();
        auto alias = aliases.find(name);
        auto answers = records.find(name);
        if (alias != aliases.end()) {
            if (nonAliasOwners.count(name) || hops == 16) throw Invalid();
            ttl = std::min(ttl, alias->second.ttl); name = alias->second.target;
        } else {
            if (answers != records.end()) {
                // A configured resolver's entire RRset has its lowest TTL
                // (RFC 2181 section 5.2), further limited by the CNAME chain.
                for (const auto& address : answers->second) ttl = std::min(ttl, address.ttl);
                for (auto address : answers->second) {
                    address.ttl = ttl;
                    result.addresses.push_back(address);
                }
            }
            return result;
        }
    }
    throw Invalid();
}
} // namespace securelink::dns
