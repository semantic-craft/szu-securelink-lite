#pragma once
// Bounded strict JSON input for the plan validator, mirroring Python
// json.loads semantics that network_plan.decode_capture relies on:
// duplicate object names are rejected before dictionaries erase them,
// NaN/Infinity are invalid numbers, bools never equal ints, and invalid
// UTF-8, trailing bytes or unbounded depth are rejected outright.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace plan_input {

inline constexpr size_t kMaxBytes = 65536;
inline constexpr int kMaxDepth = 100;

enum class Type : uint8_t { null, boolean, integer, real, string, array, object };

struct Value;
using Members = std::vector<std::pair<std::string, Value>>;

struct Value {
    Type type = Type::null;
    bool boolean = false;
    long long integer = 0;
    double real = 0;
    std::string text;
    std::vector<Value> items;
    Members members;

    bool is_object() const { return type == Type::object; }
    bool is_bool() const { return type == Type::boolean; }
    bool is_int() const { return type == Type::integer; }
    bool is_string() const { return type == Type::string; }
    bool is_array() const { return type == Type::array; }
    const Value *find(const std::string &key) const {
        for (const auto &member : members) {
            if (member.first == key) return &member.second;
        }
        return nullptr;
    }
};

enum class Error : uint8_t { none, duplicate_field, invalid_number, invalid_json };

struct Result {
    Value value;
    Error error = Error::none;
};

class Parser {
public:
    Result run(const uint8_t *data, size_t length) {
        Result result;
        if (length > kMaxBytes || !valid_utf8(data, length)) {
            result.error = Error::invalid_json;
            return result;
        }
        cursor_ = data;
        end_ = data + length;
        skip_space();
        if (!parse_value(result.value, 0)) {
            result.error = error_;
            return result;
        }
        skip_space();
        if (cursor_ != end_) {
            result.error = Error::invalid_json;
            return result;
        }
        return result;
    }

private:
    const uint8_t *cursor_ = nullptr;
    const uint8_t *end_ = nullptr;
    Error error_ = Error::none;

    bool fail(Error error) {
        error_ = error;
        return false;
    }

    void skip_space() {
        while (cursor_ != end_ && (*cursor_ == ' ' || *cursor_ == '\t' || *cursor_ == '\n' || *cursor_ == '\r')) {
            cursor_++;
        }
    }

    bool literal(const char *word) {
        for (; *word != '\0'; word++) {
            if (cursor_ == end_ || *cursor_ != static_cast<uint8_t>(*word)) return false;
            cursor_++;
        }
        return true;
    }

    bool parse_value(Value &out, int depth) {
        if (depth > kMaxDepth) return fail(Error::invalid_json);
        if (cursor_ == end_) return fail(Error::invalid_json);
        const uint8_t c = *cursor_;
        switch (c) {
            case '{': return parse_object(out, depth);
            case '[': return parse_array(out, depth);
            case '"': {
                out.type = Type::string;
                return parse_string(out.text);
            }
            case 't':
                if (!literal("true")) return fail(Error::invalid_json);
                out.type = Type::boolean;
                out.boolean = true;
                return true;
            case 'f':
                if (!literal("false")) return fail(Error::invalid_json);
                out.type = Type::boolean;
                out.boolean = false;
                return true;
            case 'n':
                if (!literal("null")) return fail(Error::invalid_json);
                out.type = Type::null;
                return true;
            case 'N':
                return fail(Error::invalid_number);
            default:
                if (c == '-' || (c >= '0' && c <= '9')) return parse_number(out);
                return fail(Error::invalid_json);
        }
    }

    bool parse_number(Value &out) {
        const uint8_t *start = cursor_;
        bool negative = false;
        if (*cursor_ == '-') {
            negative = true;
            cursor_++;
        }
        if (cursor_ == end_) return fail(Error::invalid_json);
        if (*cursor_ == '0') {
            cursor_++;
        } else if (*cursor_ >= '1' && *cursor_ <= '9') {
            while (cursor_ != end_ && *cursor_ >= '0' && *cursor_ <= '9') cursor_++;
        } else {
            return fail(Error::invalid_json);
        }
        bool real = false;
        if (cursor_ != end_ && *cursor_ == '.') {
            real = true;
            cursor_++;
            if (cursor_ == end_ || *cursor_ < '0' || *cursor_ > '9') return fail(Error::invalid_json);
            while (cursor_ != end_ && *cursor_ >= '0' && *cursor_ <= '9') cursor_++;
        }
        if (cursor_ != end_ && (*cursor_ == 'e' || *cursor_ == 'E')) {
            real = true;
            cursor_++;
            if (cursor_ != end_ && (*cursor_ == '+' || *cursor_ == '-')) cursor_++;
            if (cursor_ == end_ || *cursor_ < '0' || *cursor_ > '9') return fail(Error::invalid_json);
            while (cursor_ != end_ && *cursor_ >= '0' && *cursor_ <= '9') cursor_++;
        }
        std::string digits(reinterpret_cast<const char *>(start), static_cast<size_t>(cursor_ - start));
        if (!real) {
            out.type = Type::integer;
            int overflow = 0;
            out.integer = 0;
            for (char c : digits) {
                if (c == '-') continue;
                if (__builtin_mul_overflow(out.integer, 10, &out.integer) ||
                    __builtin_add_overflow(out.integer, c - '0', &out.integer)) {
                    overflow = 1;
                    break;
                }
            }
            if (overflow) {
                // Python ints are unbounded; the validator always bounds the
                // range, so a clamped value only ever fails that range check.
                out.integer = negative ? (-9007199254740999LL) : 9007199254740999LL;
            }
            if (negative && !overflow) out.integer = -out.integer;
            return true;
        }
        out.type = Type::real;
        out.real = std::stod(digits);
        return true;
    }

    bool parse_string(std::string &out) {
        cursor_++;  // opening quote
        while (true) {
            if (cursor_ == end_) return fail(Error::invalid_json);
            const uint8_t c = *cursor_;
            if (c == '"') {
                cursor_++;
                return true;
            }
            if (c == '\\') {
                cursor_++;
                if (cursor_ == end_) return fail(Error::invalid_json);
                const uint8_t escape = *cursor_++;
                switch (escape) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        uint32_t code = 0;
                        if (!hex4(code)) return fail(Error::invalid_json);
                        if (code >= 0xD800 && code <= 0xDBFF) {
                            if (cursor_ + 1 < end_ && cursor_[0] == '\\' && cursor_[1] == 'u') {
                                cursor_ += 2;
                                uint32_t low = 0;
                                if (!hex4(low)) return fail(Error::invalid_json);
                                if (low < 0xDC00 || low > 0xDFFF) return fail(Error::invalid_json);
                                code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                            } else {
                                return fail(Error::invalid_json);
                            }
                        } else if (code >= 0xDC00 && code <= 0xDFFF) {
                            return fail(Error::invalid_json);
                        }
                        append_utf8(out, code);
                        break;
                    }
                    default:
                        return fail(Error::invalid_json);
                }
                continue;
            }
            if (c < 0x20) return fail(Error::invalid_json);
            out.push_back(static_cast<char>(c));
            cursor_++;
        }
    }

    bool hex4(uint32_t &out) {
        out = 0;
        for (int i = 0; i < 4; i++) {
            if (cursor_ == end_) return false;
            const uint8_t c = *cursor_++;
            uint32_t digit;
            if (c >= '0' && c <= '9') digit = static_cast<uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') digit = static_cast<uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') digit = static_cast<uint32_t>(c - 'A' + 10);
            else return false;
            out = (out << 4) | digit;
        }
        return true;
    }

    static void append_utf8(std::string &out, uint32_t code) {
        if (code < 0x80) out.push_back(static_cast<char>(code));
        else if (code < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (code >> 6)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        } else if (code < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (code >> 12)));
            out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (code >> 18)));
            out.push_back(static_cast<char>(0x80 | ((code >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        }
    }

    bool parse_array(Value &out, int depth) {
        out.type = Type::array;
        cursor_++;
        skip_space();
        if (cursor_ != end_ && *cursor_ == ']') {
            cursor_++;
            return true;
        }
        while (true) {
            out.items.emplace_back();
            skip_space();
            if (!parse_value(out.items.back(), depth + 1)) return false;
            skip_space();
            if (cursor_ == end_) return fail(Error::invalid_json);
            if (*cursor_ == ',') {
                cursor_++;
                continue;
            }
            if (*cursor_ == ']') {
                cursor_++;
                return true;
            }
            return fail(Error::invalid_json);
        }
    }

    bool parse_object(Value &out, int depth) {
        out.type = Type::object;
        cursor_++;
        skip_space();
        if (cursor_ != end_ && *cursor_ == '}') {
            cursor_++;
            return true;
        }
        while (true) {
            skip_space();
            if (cursor_ == end_ || *cursor_ != '"') return fail(Error::invalid_json);
            std::string key;
            if (!parse_string(key)) return false;
            for (const auto &member : out.members) {
                if (member.first == key) return fail(Error::duplicate_field);
            }
            skip_space();
            if (cursor_ == end_ || *cursor_ != ':') return fail(Error::invalid_json);
            cursor_++;
            skip_space();
            out.members.emplace_back();
            out.members.back().first = std::move(key);
            if (!parse_value(out.members.back().second, depth + 1)) return false;
            skip_space();
            if (cursor_ == end_) return fail(Error::invalid_json);
            if (*cursor_ == ',') {
                cursor_++;
                continue;
            }
            if (*cursor_ == '}') {
                cursor_++;
                return true;
            }
            return fail(Error::invalid_json);
        }
    }

    static bool valid_utf8(const uint8_t *data, size_t length) {
        size_t i = 0;
        while (i < length) {
            const uint8_t b = data[i];
            if (b < 0x80) {
                i++;
                continue;
            }
            int continuation = 0;
            uint32_t code = 0;
            if ((b & 0xE0) == 0xC0) { continuation = 1; code = b & 0x1F; }
            else if ((b & 0xF0) == 0xE0) { continuation = 2; code = b & 0x0F; }
            else if ((b & 0xF8) == 0xF0) { continuation = 3; code = b & 0x07; }
            else return false;
            if (i + static_cast<size_t>(continuation) >= length) return false;
            for (int k = 1; k <= continuation; k++) {
                if ((data[i + static_cast<size_t>(k)] & 0xC0) != 0x80) return false;
                code = (code << 6) | (data[i + static_cast<size_t>(k)] & 0x3F);
            }
            if (continuation == 1 && code < 0x80) return false;
            if (continuation == 2 && code < 0x800) return false;
            if (continuation == 3 && code < 0x10000) return false;
            if (code > 0x10FFFF) return false;
            if (code >= 0xD800 && code <= 0xDFFF) return false;
            i += static_cast<size_t>(continuation) + 1;
        }
        return true;
    }
};

inline Result parse(const uint8_t *data, size_t length) {
    return Parser().run(data, length);
}

}  // namespace plan_input
