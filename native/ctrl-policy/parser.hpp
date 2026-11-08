#pragma once
#include <cstddef>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace securelink::ctrl {
// Implements the reviewed ctrl -> static DNS mapping contract, not routing
// permission. Unknown keys, malformed fields and unsupported address/domain
// forms fail the entire snapshot instead of the vendor's permissive skipping.
// Every row is validated even if an earlier duplicate would win. Empty-only
// arguments also reject instead of being skipped. Every accepted ctrl mapping
// retains an any-address policy intent. This is not permission to install
// system routes; the vendor flag updates an internal IP policy tree.
// No vendor source or runtime response is embedded here. The limits below are
// our bounded resource policy, not claimed vendor defaults.
using Option = std::vector<std::string>;
using Options = std::vector<Option>;
struct StaticMapping { std::string domain; std::vector<std::string> addresses; bool addressPolicyAny = true; };
struct Snapshot {
    std::vector<StaticMapping> mappings;
    std::size_t optionCount = 0;
    std::size_t duplicateKeys = 0;
    std::size_t duplicateDomains = 0;
};
enum class Failure { Limit, MalformedOption, UnsupportedKey, MissingField,
                     UnsupportedDomain, UnsupportedAddress };
struct Invalid : std::runtime_error {
    Failure failure;
    explicit Invalid(Failure value) : std::runtime_error("unsupported ctrl policy"), failure(value) {}
};
inline constexpr std::size_t maximumOptions = 64;
inline constexpr std::size_t maximumArguments = 32;
inline constexpr std::size_t maximumArgumentBytes = 512;
inline constexpr std::size_t maximumInputBytes = 32768;
inline constexpr std::size_t maximumAddresses = 16;

inline bool exactDomain(std::string_view value) {
    if (value.empty() || value.size() > 253) return false;
    std::size_t label = 0;
    char previous = 0;
    for (char c : value) {
        if (c == '.') {
            if (!label || label > 63 || previous == '-') return false;
            label = 0;
        } else {
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                  || (c >= '0' && c <= '9') || c == '-')) return false;
            if (!label && c == '-') return false;
            ++label;
        }
        previous = c;
    }
    return label && label <= 63 && previous != '-';
}
inline bool ipv4(std::string_view value) {
    unsigned components = 0;
    std::size_t offset = 0;
    while (offset < value.size()) {
        const auto delimiter = value.find('.', offset);
        const auto end = delimiter == std::string_view::npos ? value.size() : delimiter;
        const auto length = end - offset;
        if (!length || length > 3 || (length > 1 && value[offset] == '0')) return false;
        unsigned number = 0;
        for (std::size_t i = offset; i < end; ++i) {
            if (value[i] < '0' || value[i] > '9') return false;
            number = number * 10 + static_cast<unsigned>(value[i] - '0');
        }
        if (number > 255 || ++components > 4) return false;
        if (delimiter == std::string_view::npos) return components == 4;
        offset = end + 1;
    }
    return false;
}
inline std::vector<std::string> addresses(std::string_view value) {
    if (value.empty()) throw Invalid(Failure::UnsupportedAddress);
    std::vector<std::string> result;
    std::size_t offset = 0;
    for (;;) {
        // The vendor converts semicolon to ampersand before its DNS consumer
        // splits addresses. Both delimiters therefore have the same meaning.
        const auto delimiter = value.find_first_of(";&", offset);
        const auto end = delimiter == std::string_view::npos ? value.size() : delimiter;
        const auto item = value.substr(offset, end - offset);
        if (!ipv4(item)) throw Invalid(Failure::UnsupportedAddress);
        if (result.size() == maximumAddresses) throw Invalid(Failure::Limit);
        result.emplace_back(item);
        if (delimiter == std::string_view::npos) return result;
        offset = end + 1;
    }
}
inline Snapshot parse(const Options &options) {
    if (options.size() > maximumOptions) throw Invalid(Failure::Limit);
    std::size_t total = 0;
    // Bound and validate input before allocating any parsed field maps.
    for (const auto &option : options) {
        if (option.empty() || option.front() != "ctrl" || option.size() == 1)
            throw Invalid(Failure::MalformedOption);
        if (option.size() - 1 > maximumArguments) throw Invalid(Failure::Limit);
        for (const auto &argument : option) {
            if (argument.size() > maximumArgumentBytes || argument.size() > maximumInputBytes - total)
                throw Invalid(Failure::Limit);
            total += argument.size();
            for (unsigned char c : argument)
                if (c < 0x20 || c > 0x7e) throw Invalid(Failure::MalformedOption);
        }
    }
    Snapshot result;
    result.optionCount = options.size();
    std::map<std::string, std::size_t> seen;
    for (const auto &option : options) {
        std::map<std::string, std::string> fields;
        for (std::size_t i = 1; i < option.size(); ++i) {
            const std::string_view argument = option[i];
            std::size_t offset = 0;
            bool any = false;
            while (offset < argument.size()) {
                while (offset < argument.size() && argument[offset] == ' ') ++offset;
                if (offset == argument.size()) break;
                const auto delimiter = argument.find(' ', offset);
                const auto end = delimiter == std::string_view::npos ? argument.size() : delimiter;
                const auto token = argument.substr(offset, end - offset);
                const auto colon = token.find(':');
                if (colon == std::string_view::npos || colon == 0
                    || token.find(':', colon + 1) != std::string_view::npos)
                    throw Invalid(Failure::MalformedOption);
                const auto key = token.substr(0, colon), value = token.substr(colon + 1);
                if (key != "domain" && key != "sourceIp") throw Invalid(Failure::UnsupportedKey);
                if (!fields.emplace(std::string(key), std::string(value)).second) ++result.duplicateKeys;
                any = true;
                offset = end;
            }
            if (!any) throw Invalid(Failure::MalformedOption);
        }
        const auto domain = fields.find("domain"), source = fields.find("sourceIp");
        if (domain == fields.end() || source == fields.end()) throw Invalid(Failure::MissingField);
        if (!exactDomain(domain->second)) throw Invalid(Failure::UnsupportedDomain);
        auto parsed = addresses(source->second);
        if (!seen.emplace(domain->second, result.mappings.size()).second) {
            ++result.duplicateDomains;
            continue;
        }
        result.mappings.push_back({domain->second, std::move(parsed)});
    }
    return result; // caller publishes only this complete value; no partial output
}
} // namespace securelink::ctrl
