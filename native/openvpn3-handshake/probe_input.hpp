#pragma once
// Shared stdin contract for the handshake probe and the merged data engine:
// one JSON object with an exact key allowlist, fixed size budgets and no
// nested containers beyond the bounded peerInfo map. Both consumers must stay
// byte-compatible; the probe self-test exercises this parser directly.
#import <Foundation/Foundation.h>
#include <string>
#include <utility>
#include <vector>

namespace probe_input {

struct Parsed {
    std::string profile;
    std::string username;
    std::string password;
    std::vector<std::pair<std::string, std::string>> peerInfo;
    bool vendorConfusion = false;
    bool activeShapingNotExercised = false;
    bool gmsslRenegotiationNotExercised = false;
};

inline bool stringValue(NSDictionary *object, NSString *key, std::string &value, std::size_t maximum) {
    id field = object[key];
    if (![field isKindOfClass:[NSString class]]) return false;
    NSData *data = [field dataUsingEncoding:NSUTF8StringEncoding];
    if (!data || data.length > maximum) return false;
    value.assign(static_cast<const char *>(data.bytes), data.length);
    return value.find('\0') == std::string::npos;
}

inline bool optionalBoolean(NSDictionary *object, NSString *key, bool &value) {
    id field = object[key];
    if (!field) { value = false; return true; }
    if (CFGetTypeID((__bridge CFTypeRef)field) != CFBooleanGetTypeID()) return false;
    value = [field boolValue];
    return true;
}

inline bool parse(const std::string &input, Parsed &out) {
    NSData *data = [NSData dataWithBytes:input.data() length:input.size()];
    id parsed = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![parsed isKindOfClass:[NSDictionary class]]) return false;
    NSArray *inputKeys = @[@"config", @"username", @"password", @"peerInfo", @"vendorConfusion", @"activeShapingNotExercised", @"gmsslRenegotiationNotExercised"];
    for (id key in parsed) if (![inputKeys containsObject:key]) return false;
    if (!optionalBoolean(parsed, @"vendorConfusion", out.vendorConfusion)
        || !optionalBoolean(parsed, @"activeShapingNotExercised", out.activeShapingNotExercised)
        || !optionalBoolean(parsed, @"gmsslRenegotiationNotExercised", out.gmsslRenegotiationNotExercised)) return false;
    if (!stringValue(parsed, @"config", out.profile, 2 * 1024 * 1024) || out.profile.empty()
        || !stringValue(parsed, @"username", out.username, 4096) || out.username.empty()
        || !stringValue(parsed, @"password", out.password, 16384) || out.password.empty()) return false;
    // Optional fixed-key UV values go directly to peerInfo, never into config text.
    id extra = parsed[@"peerInfo"];
    if (extra) {
        if (![extra isKindOfClass:[NSDictionary class]] || [extra count] > 5) return false;
        NSArray *allowed = @[@"UV_CODE", @"UV_SL_SERVERTYPE", @"UV_EXTRA_PARAM_3", @"UV_EXTRA_PARAM_4", @"UV_EXTRA_PARAM_5"];
        for (id key in extra) {
            if (![key isKindOfClass:[NSString class]] || ![allowed containsObject:key]) return false;
            std::string value;
            if (!stringValue(extra, key, value, 8192) || value.empty() || value.find_first_of("\r\n") != std::string::npos)
                return false;
            out.peerInfo.emplace_back([key UTF8String], std::move(value));
        }
    }
    return true;
}

}  // namespace probe_input
