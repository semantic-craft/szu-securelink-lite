#pragma once
#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

namespace network_helper {
using Bytes = std::vector<uint8_t>;
using Digest = std::array<uint8_t, 32>;
enum class Op : uint8_t { hello = 1, prepare, commit, fd_ack, heartbeat, disconnect, update = 7 };
struct Binding {
    std::array<uint8_t, 16> session;
    Digest challenge;
    Digest plan_digest;
};
struct Request {
    Op op;
    uint64_t sequence;
    Binding binding;
    Bytes plan;
};
std::optional<Request> parse_frame(const Bytes &frame);

// Pure sequencing only: the caller must authenticate the socket before every
// request and drive tick from a monotonic clock even without incoming bytes.
enum class Decision { rejected, accepted, prepare_validated, commit_requested, active,
                       update_requested, cleanup };
class Flow {
public:
    using PlanValidator = std::function<bool(const Bytes &)>;
    Flow(Binding binding, uint64_t start_ms, uint64_t duration_ms, PlanValidator validator);
    Decision receive(const Request &request, uint64_t now_ms);
    Decision committed(bool success, uint64_t now_ms);
    Decision tick(uint64_t now_ms);
    Decision disconnected();
    // Unit 5: audited apply work counts as traffic. A large plan applies for
    // several seconds synchronously; the caller refreshes the silence clock
    // so the daemon does not judge its own work as peer silence.
    void keepalive(uint64_t now_ms) { heartbeat_ms_ = now_ms; }
private:
    enum class State { fresh, greeted, prepared, committing, awaiting_ack, active, closed };
    Binding binding_;
    PlanValidator validator_;
    State state_ = State::fresh;
    uint64_t deadline_, last_ms_, heartbeat_ms_, sequence_ = 0;
};

struct PeerExpectation {
    uint32_t uid;
    std::array<uint32_t, 8> audit_token;
    std::array<uint8_t, 20> cdhash;
};
bool verify_peer(int socket, const PeerExpectation &expected);

struct Received {
    Bytes bytes;
    int fd = -1;
    bool eof = false;
    bool valid = false;
    bool must_exit = false;
    Received() = default;
    Received(const Received &) = delete;
    Received &operator=(const Received &) = delete;
    Received(Received &&other) noexcept;
    ~Received();
    int release_fd();
};
Received receive_chunk(int socket, bool expect_one_fd);
bool send_fd_marker(int socket, int fd);
}
