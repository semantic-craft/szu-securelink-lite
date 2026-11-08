// Offline engine-client scenarios over a socketpair with a fake helper. The
// fake helper speaks the audited frame format and hands back descriptors that
// are deliberately NOT utun sockets; the engine must refuse them. Data-session
// scenarios inject a utun name so the handshake reaches the active phase and
// the pump/disconnect sequencing is exercised end to end. Real utun
// acceptance is 3e under administrator authorization.
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <net/if.h>
#import <poll.h>
#import <sys/socket.h>
#import <chrono>
#import <mutex>
#import <thread>
#import <vector>
#import <cstdio>
#import <cstring>
#import <string>
#import "engine_transaction.hpp"

namespace {

int failures = 0;
void check(bool ok, const char *what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL %s\n", what);
        failures++;
    }
}

constexpr char kPlanJson[] = "{\"version\": 2}";

network_helper::Binding make_binding(const std::string &plan) {
    network_helper::Binding binding;
    binding.session.fill(0xA1);
    binding.challenge.fill(0x22);
    // The digest rides in the frame; the helper validates bytes against it.
    CC_SHA256(plan.data(), static_cast<CC_LONG>(plan.size()), binding.plan_digest.data());
    return binding;
}

// Frames read by the fake helper, mirroring the audited parser's layout.
std::vector<uint8_t> read_frame(int fd) {
    std::vector<uint8_t> header(4);
    size_t done = 0;
    while (done < 4) {
        ssize_t n = ::read(fd, header.data() + done, 4 - done);
        if (n <= 0) return {};
        done += static_cast<size_t>(n);
    }
    uint32_t length = (static_cast<uint32_t>(header[0]) << 24) |
                      (static_cast<uint32_t>(header[1]) << 16) |
                      (static_cast<uint32_t>(header[2]) << 8) |
                      static_cast<uint32_t>(header[3]);
    // length counts everything after the BE32 prefix; the smallest
    // frame is a 92-byte header with no payload.
    if (length < 92 || length > 65536) return {};
    std::vector<uint8_t> frame(4 + length);
    for (size_t i = 0; i < 4; i++) frame[i] = header[i];
    done = 4;
    while (done < frame.size()) {
        ssize_t n = ::read(fd, frame.data() + done, frame.size() - done);
        if (n <= 0) return {};
        done += static_cast<size_t>(n);
    }
    return frame;
}

struct SeenFrame {
    int op = 0;
    uint64_t sequence = 0;
};
std::mutex seen_mutex;

// Blocking helper reads must not hang the suite: poll first, then read.
bool readable_within(int fd, int timeout_ms) {
    pollfd wanted = {fd, POLLIN, 0};
    return ::poll(&wanted, 1, timeout_ms) > 0;
}

struct ServerScript {
    std::vector<uint8_t> non_utun_fd_payload;  // fd handed to the engine
    bool send_fd = true;
    bool expect_disconnect = true;
    bool run_active_phase = false;             // read fd_ack/heartbeats/disconnect
    bool close_after_fd = false;               // simulate a dead helper mid-session
};

void fake_helper(int fd, ServerScript script, std::vector<int> *seen_ops) {
    auto record = [&](const network_helper::Request &request) {
        std::lock_guard<std::mutex> lock(seen_mutex);
        seen_ops->push_back(static_cast<int>(request.op));
    };
    for (int index = 0; index < 3; index++) {
        const auto frame = read_frame(fd);
        if (frame.empty()) return;
        const auto request = network_helper::parse_frame(frame);
        if (!request.has_value()) return;
        record(*request);
    }
    if (script.send_fd) {
        (void)network_helper::send_fd_marker(fd, script.non_utun_fd_payload[0]);
    }
    if (script.close_after_fd) {
        // Consume (and record) the fd_ack so the handshake completes, then
        // drop the session so a pump heartbeat hits EPIPE mid-run.
        if (readable_within(fd, 2000)) {
            const auto frame = read_frame(fd);
            const auto request = network_helper::parse_frame(frame);
            if (request.has_value()) record(*request);
        }
        ::close(fd);
        return;
    }
    if (!script.run_active_phase) {
        if (!script.expect_disconnect) return;
        const auto frame = read_frame(fd);
        if (frame.empty()) return;
        const auto request = network_helper::parse_frame(frame);
        if (request.has_value() && request->op == network_helper::Op::disconnect) {
            record(*request);
        }
        return;
    }
    // Active phase: read every frame until disconnect or a 3s quiet deadline.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline) {
        if (!readable_within(fd, 200)) continue;
        const auto frame = read_frame(fd);
        if (frame.empty()) return;
        const auto request = network_helper::parse_frame(frame);
        if (!request.has_value()) return;
        record(*request);
        if (request->op == network_helper::Op::disconnect) return;
    }
}

struct FakeNet {
    bool authenticate_result = true;
    std::string forced_utun_name;  // data scenarios: inject a utun identity

    bool authenticate(int, const tunnel_transaction::CodeExpectation &) { return authenticate_result; }
    bool wait_readable(int fd, int timeout_ms) {
        return readable_within(fd, timeout_ms);
    }
    uint64_t now_ms() {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
    }
    bool send(int fd, const network_helper::Bytes &bytes) {
        size_t done = 0;
        while (done < bytes.size()) {
            ssize_t n = ::write(fd, bytes.data() + done, bytes.size() - done);
            if (n <= 0) return false;
            done += static_cast<size_t>(n);
        }
        return true;
    }
    network_helper::Received receive_fd(int fd) {
        return network_helper::receive_chunk(fd, true);
    }
    bool utun_name(int fd, std::string *out) {
        if (!forced_utun_name.empty()) {
            *out = forced_utun_name;
            return true;
        }
        char buffer[IFNAMSIZ]{};
        socklen_t size = sizeof(buffer);
        if (::getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, buffer, &size) != 0) return false;
        *out = buffer;
        return true;
    }
};

std::vector<int> snapshot_ops(const std::vector<int> *seen_ops) {
    std::lock_guard<std::mutex> lock(seen_mutex);
    return *seen_ops;
}

// Data-session scenario: forced utun identity, active-phase pump, disconnect.
void run_data_scenario(bool helper_dies) {
    int fake_fd_pair[2];
    check(::socketpair(AF_UNIX, SOCK_STREAM, 0, fake_fd_pair) == 0, "socketpair for fake fd");

    int session_pair[2];
    check(::socketpair(AF_UNIX, SOCK_STREAM, 0, session_pair) == 0, "socketpair for session");
    const int engine_fd = session_pair[0];
    const int helper_fd = session_pair[1];

    std::vector<int> seen_ops;
    ServerScript script;
    script.non_utun_fd_payload = {static_cast<uint8_t>(fake_fd_pair[0])};
    script.run_active_phase = true;
    script.close_after_fd = helper_dies;
    std::thread server(fake_helper, helper_fd, script, &seen_ops);

    engine_transaction::EngineApproval approval;
    approval.binding = make_binding(kPlanJson);
    approval.peer.uid = 0;  // helper must be root
    approval.plan = kPlanJson;
    approval.duration_ms = 120000;

    engine_transaction::EngineHooks<FakeNet> hooks{FakeNet{}};
    hooks.net.forced_utun_name = "utun9";
    uint64_t sequence = 0;
    const auto handshake = engine_transaction::engine_handshake(engine_fd, approval, hooks, sequence);
    check(handshake.phase == "active", "data handshake reaches active");
    check(handshake.fd_accepted, "data handshake accepts the descriptor");
    check(handshake.tunnel_interface == "utun9", "data handshake reports the utun name");
    check(handshake.tunnel_fd >= 0, "data handshake owns the tunnel descriptor");

    engine_transaction::EnginePump pump;
    pump.fd = engine_fd;  // heartbeats ride the transaction socket
    pump.binding = approval.binding;
    pump.sequence = sequence;
    pump.start(hooks.net, helper_dies ? 100 : 100);
    std::this_thread::sleep_for(std::chrono::milliseconds(helper_dies ? 300 : 350));
    bool update_sent = false;
    if (!helper_dies) {
        // Unit 4: the in-session delta rides the same socket, serialized with
        // the heartbeat pump, with the sequence continuing.
        update_sent = pump.send_update(hooks.net, "{\"version\": 2}");
    }
    pump.stop();
    check(pump.heartbeats_sent >= 1 || helper_dies, "pump sent heartbeats while active");
    const bool disconnect_sent = pump.disconnect(hooks.net);
    check(disconnect_sent != helper_dies, "disconnect outcome matches helper liveness");
    check(update_sent != helper_dies, "update send outcome matches helper liveness");

    server.join();

    const auto ops = snapshot_ops(&seen_ops);
    check(ops.size() >= 4 && ops[0] == 1 && ops[1] == 2 && ops[2] == 3,
          "hello, prepare, commit arrived in order");
    if (!helper_dies) {
        // fd_ack then at least one heartbeat, an update, then a disconnect.
        const auto ack = std::find(ops.begin(), ops.end(), 4);
        check(ack != ops.end(), "fd_ack recorded by the helper");
        const auto first_beat = std::find(ops.begin(), ops.end(), 5);
        check(first_beat != ops.end(), "heartbeat recorded by the helper");
        const auto update = std::find(ops.begin(), ops.end(), 7);
        check(update != ops.end(), "update frame recorded by the helper");
        check(update < std::find(ops.begin(), ops.end(), 6), "update precedes the disconnect");
        check(!ops.empty() && ops.back() == 6, "disconnect ends the data session");
        check(pump.send_failed == false, "no pump failures against a live helper");
    } else {
        check(pump.send_failed == true, "pump reports the send failure");
        check(!disconnect_sent, "disconnect against a dead helper fails");
    }

    ::close(fake_fd_pair[0]);
    ::close(fake_fd_pair[1]);
    ::close(engine_fd);
    ::close(helper_fd);
}

}  // namespace

int main() {
    ::signal(SIGPIPE, SIG_IGN);  // dead-helper scenarios must report EPIPE, not die
    // Fake descriptor: a socketpair end, deliberately not a utun socket.
    int fake_fd_pair[2];
    check(::socketpair(AF_UNIX, SOCK_STREAM, 0, fake_fd_pair) == 0, "socketpair for fake fd");

    int session_pair[2];
    int engine_fd = -1, helper_fd = -1;
    check(::socketpair(AF_UNIX, SOCK_STREAM, 0, session_pair) == 0, "socketpair for session");
    engine_fd = session_pair[0];
    helper_fd = session_pair[1];

    std::vector<int> seen_ops;
    ServerScript script;
    script.non_utun_fd_payload = {static_cast<uint8_t>(fake_fd_pair[0])};
    std::thread server(fake_helper, helper_fd, script, &seen_ops);

    engine_transaction::EngineApproval approval;
    approval.binding = make_binding(kPlanJson);
    approval.peer.uid = 0;  // helper must be root
    approval.plan = kPlanJson;
    approval.duration_ms = 120000;

    engine_transaction::EngineHooks<FakeNet> hooks{FakeNet{}};
    const auto result = engine_transaction::run_engine(engine_fd, approval, hooks);

    server.join();
    check(result.phase == "rejected-fd", "non-utun descriptor refused");
    check(result.fd_accepted == false, "fake fd never accepted");
    check(result.tunnel_interface.empty(), "no interface name from a fake fd");
    const auto ops = snapshot_ops(&seen_ops);
    const bool order_ok = ops.size() >= 3 &&
                          ops[0] == 1 && ops[1] == 2 && ops[2] == 3;
    check(order_ok, "hello, prepare, commit arrived in order");
    const bool disconnect_seen = std::find(ops.begin(), ops.end(), 6) != ops.end();
    check(disconnect_seen, "engine sent disconnect after refusing the fd");

    ::close(fake_fd_pair[0]);
    ::close(fake_fd_pair[1]);
    ::close(engine_fd);
    ::close(helper_fd);

    run_data_scenario(false);
    run_data_scenario(true);

    if (failures != 0) return 1;
    return 0;
}
