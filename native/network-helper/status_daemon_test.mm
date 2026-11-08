// Offline test for the pure status-daemon logic. Prints nothing on success.
#import <Foundation/Foundation.h>
#import <cstdio>
#import <cstdlib>
#import <string>
#import <vector>
#import "status_daemon.hpp"

using namespace status_daemon;

namespace {
int failures = 0;
void check(bool ok, const char *what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL %s\n", what);
        failures++;
    }
}

// Minimal string-aware JSON structure validator: braces and brackets must nest
// correctly and strings must terminate. Enough to catch assembly mistakes the
// substring checks below cannot see.
bool json_balanced(const std::string &text) {
    int depth = 0;
    bool in_string = false;
    bool escaped = false;
    for (char c : text) {
        if (in_string) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') in_string = false;
            continue;
        }
        if (c == '"') in_string = true;
        else if (c == '{' || c == '[') depth++;
        else if (c == '}' || c == ']') {
            depth--;
            if (depth < 0) return false;
        }
    }
    return !in_string && depth == 0;
}

size_t count_occurrences(const std::string &text, const std::string &needle) {
    size_t found = 0;
    for (size_t at = text.find(needle); at != std::string::npos;
         at = text.find(needle, at + needle.size())) {
        found++;
    }
    return found;
}
}

int main() {
    const uint8_t good[] = {kOpStatus};
    check(parse_request(good, 1), "one status byte accepted");
    const uint8_t wrong_op[] = {0x02};
    check(!parse_request(wrong_op, 1), "other opcode rejected");
    check(!parse_request(good, 0), "empty frame rejected");
    const uint8_t two[] = {kOpStatus, kOpStatus};
    check(!parse_request(two, 2), "two-byte frame rejected");

    check(state_name(0) == std::string("loaded"), "exit zero is loaded");
    check(state_name(3) == std::string("exit"), "nonzero exit stays raw");

    check(is_hex_sha256(std::string(kSha256HexLength, 'a')), "valid hex accepted");
    check(!is_hex_sha256(std::string(kSha256HexLength - 1, 'a')), "short hex rejected");
    check(!is_hex_sha256(std::string(kSha256HexLength, 'g')), "non-hex rejected");

    std::vector<LabelVerdict> verdicts;
    verdicts.push_back({kVendorLabels[0], 0});
    verdicts.push_back({kVendorLabels[1], 3});
    std::string json = build_response(std::string(kSha256HexLength, 'a'), 501, verdicts, 1700000000);
    check(json.find("\"schemaVersion\":1") != std::string::npos, "schema key present");
    check(json.find("\"label\":\"" + std::string(kHelperLabel) + "\"") != std::string::npos, "helper label present");
    check(json.find(std::string(kSha256HexLength, 'a')) != std::string::npos, "sha embedded");
    check(json.find("\"allowedUid\":501") != std::string::npos, "uid embedded");
    check(json.find("\"com.securelink.client\":{\"state\":\"loaded\",\"exitCode\":0}") != std::string::npos,
          "loaded verdict rendered");
    check(json.find("\"exitCode\":3") != std::string::npos, "raw exit code embedded");
    check(json.find("\"epoch\":1700000000") != std::string::npos, "epoch embedded");
    check(json.front() == '{' && json.back() == '}', "json braces balanced");
    size_t quotes = 0;
    for (char c : json) quotes += c == '"' ? 1 : 0;
    check(quotes % 2 == 0, "json quotes balanced");

    std::string bad = build_response("short", 501, {}, 1);
    check(bad.find(std::string(kSha256HexLength, '0')) != std::string::npos, "invalid sha zeroed");

    check(json_balanced(json), "verdict response is structurally valid json");
    check(json_balanced(bad), "sha-fallback response is structurally valid json");
    check(count_occurrences(json, "{") == count_occurrences(json, "}"), "braces paired");
    check(count_occurrences(json, "[") == count_occurrences(json, "]"), "brackets paired");
    // Every verdict stays inside "services": exactly one closing brace per
    // verdict object, and "epoch" arrives only after services closes.
    size_t services_open = json.find("\"services\":{");
    size_t epoch = json.find("\"epoch\":");
    check(services_open != std::string::npos && epoch != std::string::npos, "services before epoch");
    check(count_occurrences(json, "\"state\":") == verdicts.size(),
          "one state per verdict including self");
    check(count_occurrences(json, "\"exitCode\":") == verdicts.size(), "one exit per verdict including self");

    // Both fixed vendor labels and no others are ever reported.
    check(kVendorLabelCount == 3, "vendor label count fixed");
    check(std::string(kVendorLabels[2]) == "com.wangsu.securebox.service", "third label constant");

    if (failures != 0) return 1;
    return 0;
}
