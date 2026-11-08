#include "ipc.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <Security/Security.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ucred.h>
#include <sys/resource.h>
#include <bsm/libbsm.h>
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <cstring>
#include <limits>

namespace network_helper {
static bool equal(const Binding &a, const Binding &b) {
    return a.session == b.session && a.challenge == b.challenge && a.plan_digest == b.plan_digest;
}
template <class T> static bool nonzero(const T &value) {
    return std::any_of(value.begin(), value.end(), [](auto byte) { return byte != 0; });
}
std::optional<Request> parse_frame(const Bytes &frame) {
    constexpr size_t header = 92;
    if (frame.size() < header + 4 || frame.size() > 65536) return {};
    uint32_t length = 0;
    for (size_t i = 0; i < 4; ++i) length = (length << 8) | frame[i];
    if (length != frame.size() - 4 || frame[4] != 1 || frame[6] || frame[7]
        || frame[5] < 1 || frame[5] > 7) return {};
    Request result{};
    result.op = static_cast<Op>(frame[5]);
    for (size_t i = 8; i < 16; ++i) result.sequence = (result.sequence << 8) | frame[i];
    if (!result.sequence) return {};
    std::copy_n(frame.begin() + 16, 16, result.binding.session.begin());
    std::copy_n(frame.begin() + 32, 32, result.binding.challenge.begin());
    std::copy_n(frame.begin() + 64, 32, result.binding.plan_digest.begin());
    result.plan.assign(frame.begin() + 96, frame.end());
    const bool payload_expected = result.op == Op::prepare || result.op == Op::update;
    if (payload_expected ? result.plan.empty() || result.plan.size() > 64000 : !result.plan.empty()) return {};
    return result;
}
Flow::Flow(Binding binding, uint64_t start, uint64_t duration, PlanValidator validator)
    : binding_(binding), validator_(std::move(validator)), deadline_(start), last_ms_(start), heartbeat_ms_(start) {
    // 900000 matches the authority's audited-lifetime bound (15 minutes).
    if (!duration || duration > 900000 || start > std::numeric_limits<uint64_t>::max() - duration
        || !nonzero(binding.session) || !nonzero(binding.challenge) || !nonzero(binding.plan_digest) || !validator_)
        state_ = State::closed;
    else deadline_ += duration;
}
Decision Flow::disconnected() { state_ = State::closed; return Decision::cleanup; }
Decision Flow::tick(uint64_t now) {
    if (state_ == State::closed || now < last_ms_ || now >= deadline_ || now - heartbeat_ms_ >= 6000)
        return disconnected();
    last_ms_ = now;
    return Decision::accepted;
}
Decision Flow::receive(const Request &r, uint64_t now) {
    if (tick(now) == Decision::cleanup) return Decision::cleanup;
    if (!equal(r.binding, binding_) || sequence_ == std::numeric_limits<uint64_t>::max() || r.sequence != sequence_ + 1)
        return disconnected();
    sequence_ = r.sequence;
    // prepare and the in-session update are the only payload-bearing frames.
    if (r.op != Op::prepare && r.op != Op::update && !r.plan.empty()) return disconnected();
    if (r.op == Op::disconnect) return disconnected();
    if (r.op == Op::hello && state_ == State::fresh) { state_ = State::greeted; return Decision::accepted; }
    if (r.op == Op::prepare && state_ == State::greeted) {
        if (r.plan.empty() || r.plan.size() > 64000) return disconnected();
        Digest digest{};
        CC_SHA256(r.plan.data(), static_cast<CC_LONG>(r.plan.size()), digest.data());
        if (digest != binding_.plan_digest) return disconnected();
        bool valid = false;
        try { valid = validator_(r.plan); } catch (...) { return disconnected(); }
        if (!valid) return disconnected();
        state_ = State::prepared;
        return Decision::prepare_validated;
    }
    if (r.op == Op::commit && state_ == State::prepared) { state_ = State::committing; return Decision::commit_requested; }
    if (r.op == Op::fd_ack && state_ == State::awaiting_ack) { state_ = State::active; return Decision::active; }
    if (r.op == Op::heartbeat && state_ == State::active) { heartbeat_ms_ = now; return Decision::accepted; }
    // In-session push delta: the same validator and the same silence
    // accounting as heartbeat traffic. The state stays active and the last
    // validated bytes belong to the delta the caller applies.
    if (r.op == Op::update && state_ == State::active) {
        if (r.plan.empty() || r.plan.size() > 64000) return disconnected();
        bool valid = false;
        try { valid = validator_(r.plan); } catch (...) { return disconnected(); }
        if (!valid) return disconnected();
        heartbeat_ms_ = now;
        return Decision::update_requested;
    }
    return disconnected();
}
Decision Flow::committed(bool success, uint64_t now) {
    if (tick(now) == Decision::cleanup || !success || state_ != State::committing) return disconnected();
    state_ = State::awaiting_ack;
    return Decision::accepted;
}

bool verify_peer(int socket, const PeerExpectation &expected) {
    xucred credential{};
    socklen_t size = sizeof(credential);
    if (getsockopt(socket, SOL_LOCAL, LOCAL_PEERCRED, &credential, &size) || size != sizeof(credential)
        || credential.cr_version != XUCRED_VERSION || credential.cr_uid != expected.uid) return false;
    audit_token_t token{};
    size = sizeof(token);
    if (getsockopt(socket, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size) || size != sizeof(token)
        || std::memcmp(&token, expected.audit_token.data(), sizeof(token))
        || audit_token_to_euid(token) != expected.uid || !nonzero(expected.cdhash)) return false;
    CFDataRef data = CFDataCreate(nullptr, reinterpret_cast<const UInt8 *>(&token), sizeof(token));
    if (!data) return false;
    const void *key = kSecGuestAttributeAudit, *value = data;
    CFDictionaryRef attributes = CFDictionaryCreate(nullptr, &key, &value, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    SecCodeRef code = nullptr;
    OSStatus status = attributes ? SecCodeCopyGuestWithAttributes(nullptr, attributes, kSecCSDefaultFlags, &code) : errSecAllocate;
    if (attributes) CFRelease(attributes);
    CFRelease(data);
    if (status != errSecSuccess || !code) return false;
    status = SecCodeCheckValidity(code, kSecCSStrictValidate, nullptr);
    SecStaticCodeRef static_code = nullptr;
    CFDictionaryRef information = nullptr;
    bool valid = status == errSecSuccess && SecCodeCopyStaticCode(code, kSecCSDefaultFlags, &static_code) == errSecSuccess
        && SecCodeCopySigningInformation(static_code, kSecCSSigningInformation, &information) == errSecSuccess;
    if (valid) {
        auto hash = static_cast<CFDataRef>(CFDictionaryGetValue(information, kSecCodeInfoUnique));
        valid = hash && CFGetTypeID(hash) == CFDataGetTypeID() && CFDataGetLength(hash) == static_cast<CFIndex>(expected.cdhash.size())
            && !std::memcmp(CFDataGetBytePtr(hash), expected.cdhash.data(), expected.cdhash.size());
    }
    if (information) CFRelease(information);
    if (static_code) CFRelease(static_code);
    CFRelease(code);
    return valid;
}
Received::Received(Received &&other) noexcept : bytes(std::move(other.bytes)), fd(other.fd), eof(other.eof), valid(other.valid), must_exit(other.must_exit) { other.fd = -1; }
Received::~Received() { if (fd >= 0) close(fd); }
int Received::release_fd() { int result = fd; fd = -1; return result; }
Received receive_chunk(int socket, bool expect_one_fd) {
    Received result;
    rlimit descriptor_limit{};
    if (getrlimit(RLIMIT_NOFILE, &descriptor_limit) || !descriptor_limit.rlim_cur
        || descriptor_limit.rlim_cur > 1048576) return result;
    result.bytes.resize(65536);
    std::vector<char> control(static_cast<size_t>(descriptor_limit.rlim_cur) * CMSG_SPACE(sizeof(int)));
    iovec io{result.bytes.data(), result.bytes.size()};
    msghdr message{};
    message.msg_iov = &io; message.msg_iovlen = 1; message.msg_control = control.data(); message.msg_controllen = static_cast<socklen_t>(control.size());
    ssize_t count = recvmsg(socket, &message, MSG_DONTWAIT);
    if (count < 0) { result.bytes.clear(); return result; }
    std::vector<int> fds;
    result.must_exit = message.msg_flags & MSG_CTRUNC;
    bool valid = !(message.msg_flags & (MSG_CTRUNC | MSG_TRUNC));
    if (message.msg_controllen > control.size()) { valid = false; result.must_exit = true; }
    message.msg_controllen = std::min(message.msg_controllen, static_cast<socklen_t>(control.size()));
    for (auto *c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c)) {
        size_t available = control.data() + message.msg_controllen - reinterpret_cast<char *>(c);
        if (available < CMSG_LEN(0) || c->cmsg_len < CMSG_LEN(0)) { valid = false; break; }
        bool truncated = c->cmsg_len > available;
        if (truncated) { valid = false; result.must_exit = true; }
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) { valid = false; if (truncated) break; else continue; }
        size_t size = std::min(static_cast<size_t>(c->cmsg_len), available) - CMSG_LEN(0);
        if (size % sizeof(int)) valid = false;
        for (size_t i = 0; i + sizeof(int) <= size; i += sizeof(int)) {
            int fd; std::memcpy(&fd, CMSG_DATA(c) + i, sizeof(fd)); fds.push_back(fd);
        }
        if (truncated) break;
    }
    result.bytes.resize(static_cast<size_t>(count));
    result.eof = count == 0;
    valid = valid && count > 0 && fds.size() == (expect_one_fd ? 1 : 0);
    if (expect_one_fd) valid = valid && count == 1 && result.bytes[0] == 0x46;
    if (valid && expect_one_fd) {
        int flags = fcntl(fds[0], F_GETFD);
        valid = flags >= 0 && fcntl(fds[0], F_SETFD, flags | FD_CLOEXEC) == 0;
    }
    if (valid && expect_one_fd) result.fd = fds[0];
    else for (int fd : fds) close(fd);
    result.valid = valid;
    return result;
}
bool send_fd_marker(int socket, int fd) {
    int enabled = 1;
    if (fd < 0 || setsockopt(socket, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled))) return false;
    uint8_t marker = 0x46;
    iovec io{&marker, 1};
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
    msghdr message{};
    message.msg_iov = &io; message.msg_iovlen = 1; message.msg_control = control; message.msg_controllen = sizeof(control);
    auto *c = CMSG_FIRSTHDR(&message);
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(c), &fd, sizeof(fd));
    return sendmsg(socket, &message, MSG_DONTWAIT) == 1;
}
}
