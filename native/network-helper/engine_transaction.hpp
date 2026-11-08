#pragma once
// Engine-side transaction client, the counterpart of tunnel_transaction.hpp.
// The engine authenticates the helper, sends hello/prepare/commit, receives
// exactly one FD, refuses any descriptor that is not a utun control socket,
// and only then acknowledges. Offline tests run it against a fake helper over
// a socketpair; a real utun fd can only pass the verification in 3e.
// Pure policy: no main(), no direct socket creation.
#include <net/if_utun.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <atomic>
#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "ipc.hpp"
#include "tunnel_transaction.hpp"

namespace engine_transaction {

struct EngineApproval {
    network_helper::Binding binding;          // session/challenge/plan digest
    tunnel_transaction::CodeExpectation peer; // expected helper identity
    std::string plan;                      // raw capture bytes to submit
    uint64_t duration_ms = 0;
    uint64_t hold_ms = 0;                  // keep the session open post-ack
};

inline network_helper::Bytes make_frame(network_helper::Op op, uint64_t sequence,
                                        const network_helper::Binding &binding,
                                        const std::string &payload) {
    network_helper::Bytes frame(96 + payload.size(), 0);
    const uint32_t length = static_cast<uint32_t>(frame.size() - 4);
    frame[0] = static_cast<uint8_t>(length >> 24);
    frame[1] = static_cast<uint8_t>(length >> 16);
    frame[2] = static_cast<uint8_t>(length >> 8);
    frame[3] = static_cast<uint8_t>(length);
    frame[4] = 1;
    frame[5] = static_cast<uint8_t>(op);
    for (int i = 0; i < 8; i++) {
        frame[8 + i] = static_cast<uint8_t>(sequence >> (8 * (7 - i)));
    }
    for (int i = 0; i < 16; i++) frame[16 + i] = binding.session[static_cast<size_t>(i)];
    for (int i = 0; i < 32; i++) frame[32 + i] = binding.challenge[static_cast<size_t>(i)];
    for (int i = 0; i < 32; i++) frame[64 + i] = binding.plan_digest[static_cast<size_t>(i)];
    for (size_t i = 0; i < payload.size(); i++) frame[96 + i] = static_cast<uint8_t>(payload[i]);
    return frame;
}

// Hooks injected for offline fakes; the real client uses sockets and
// verify_peer from ipc.mm.
template <class Net>
struct EngineHooks {
    Net net;
    bool debug_sends = false;  // set by tests/diagnostics, prints frame sends
              // utun_name(fd, &out), wait_readable(fd, ms), now_ms()
};

struct EngineResult {
    std::string phase = "idle";  // idle|connected|rejected-peer|rejected-fd|cleanup|active
    bool fd_accepted = false;
    std::string tunnel_interface;
};

// Result of the transaction up to and including the fd acknowledgement. The
// tunnel_fd is owned by the caller once fd_accepted. Failure paths mirror the
// pinned run_engine semantics: a failed fd_ack returns "cleanup" without a
// disconnect, every earlier failure sends its disconnect here.
struct EngineHandshakeResult {
    std::string phase = "idle";  // idle|connected|rejected-peer|rejected-fd|cleanup|active
    bool fd_accepted = false;
    std::string tunnel_interface;
    int tunnel_fd = -1;
};

template <class Net>
EngineHandshakeResult engine_handshake(int fd, const EngineApproval &approval, EngineHooks<Net> &hooks,
                                       uint64_t &sequence) {
    EngineHandshakeResult result;
    if (!hooks.net.authenticate(fd, approval.peer)) {
        result.phase = "rejected-peer";
        return result;
    }
    auto send = [&](network_helper::Op op, const std::string &payload = "") {
        sequence++;
        return hooks.net.send(fd, make_frame(op, sequence, approval.binding, payload));
    };
    if (!send(network_helper::Op::hello)) {
        result.phase = "cleanup";
        return result;
    }
    result.phase = "connected";
    if (!send(network_helper::Op::prepare, approval.plan)) {
        result.phase = "cleanup";
        return result;
    }
    if (!send(network_helper::Op::commit)) {
        result.phase = "cleanup";
        return result;
    }
    // receive_chunk is deliberately nonblocking; wait for readability under
    // an audited silence ceiling instead of spinning or blocking. The unit-5
    // plan legitimately applies 125+ static route spawns before the fd
    // arrives, so the ceiling covers a large audited apply, not just silence.
    const uint64_t silence_deadline = hooks.net.now_ms() + 30000;
    bool readable = false;
    while (hooks.net.now_ms() < silence_deadline) {
        if (hooks.net.wait_readable(fd, 100)) {
            readable = true;
            break;
        }
    }
    if (!readable) {
        result.phase = "cleanup";
        (void)send(network_helper::Op::disconnect);
        return result;
    }
    auto received = hooks.net.receive_fd(fd);
    if (received.must_exit) {
        // Truncated descriptors: this process must not continue (audited rule).
        result.phase = "cleanup";
        (void)send(network_helper::Op::disconnect);
        return result;
    }
    if (!received.valid || received.fd < 0) {
        result.phase = "cleanup";
        (void)send(network_helper::Op::disconnect);
        return result;
    }
    std::string name;
    if (!hooks.net.utun_name(received.fd, &name) || name.rfind("utun", 0) != 0) {
        // Not a utun control socket: refuse the descriptor outright.
        result.phase = "rejected-fd";
        (void)send(network_helper::Op::disconnect);
        return result;
    }
    result.tunnel_interface = name;
    result.tunnel_fd = received.release_fd();
    result.fd_accepted = true;
    if (!send(network_helper::Op::fd_ack)) {
        result.phase = "cleanup";
        return result;
    }
    result.phase = "active";
    return result;
}

// Data-engine session pump: heartbeats stay within the daemon's audited
// six-second silence ceiling while the OpenVPN3 session runs on another
// thread; after the session ends the pump stops and the caller sends the
// final disconnect so the daemon converges journal cleanup. Sequence
// ownership is strictly single-threaded per phase: handshake, pump worker,
// then post-session cleanup on the caller thread.
struct EnginePump {
    int fd = -1;
    network_helper::Binding binding;
    uint64_t sequence = 0;
    std::atomic<bool> running{false};
    std::atomic<bool> send_failed{false};
    uint64_t heartbeats_sent = 0;
    std::mutex send_mutex;  // heartbeats, updates and disconnect share one socket
    std::thread worker;

    template <class Net>
    void start(Net &net, uint64_t interval_ms = 1000) {
        running = true;
        worker = std::thread([this, &net, interval_ms] {
            while (running.load()) {
                // Slice the wait so stop() converges within one slice.
                for (uint64_t waited = 0; running.load() && waited < interval_ms; waited += 100)
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (!running.load()) break;
                const std::lock_guard<std::mutex> lock(send_mutex);
                if (send_failed.load()) return;
                if (!net.send(fd, make_frame(network_helper::Op::heartbeat, ++sequence, binding, ""))) {
                    send_failed = true;
                    return;
                }
                heartbeats_sent++;
            }
        });
    }
    void stop() {
        running = false;
        if (worker.joinable()) worker.join();
    }
    // In-session push delta (unit 4): serialized with the pump so frames
    // never interleave mid-write. Sequence authority stays with the pump.
    template <class Net>
    bool send_update(Net &net, const std::string &payload) {
        const std::lock_guard<std::mutex> lock(send_mutex);
        if (send_failed.load()) return false;
        const bool ok = net.send(fd, make_frame(network_helper::Op::update, ++sequence, binding, payload));
        if (!ok) send_failed = true;
        return ok;
    }
    template <class Net>
    bool disconnect(Net &net) {
        const std::lock_guard<std::mutex> lock(send_mutex);
        return net.send(fd, make_frame(network_helper::Op::disconnect, ++sequence, binding, ""));
    }
};

template <class Net>
EngineResult run_engine(int fd, const EngineApproval &approval, EngineHooks<Net> &hooks) {
    EngineResult result;
    uint64_t sequence = 0;
    const auto handshake = engine_handshake(fd, approval, hooks, sequence);
    result.phase = handshake.phase;
    result.fd_accepted = handshake.fd_accepted;
    result.tunnel_interface = handshake.tunnel_interface;
    if (!handshake.fd_accepted) return result;
    // Hold the session open on the audited heartbeat cadence (caller chooses
    // hold_ms, zero = immediate), then disconnect so the daemon converges
    // journal cleanup. The sequence counter stays authoritative.
    const uint64_t deadline = hooks.net.now_ms() + approval.hold_ms;
    while (hooks.net.now_ms() < deadline) {
        hooks.net.wait_readable(fd, 300);
        if (!hooks.net.send(fd, make_frame(network_helper::Op::heartbeat, ++sequence, approval.binding, ""))) break;
    }
    if (!hooks.net.send(fd, make_frame(network_helper::Op::disconnect, ++sequence, approval.binding, ""))) {
        result.phase = "cleanup";
        return result;
    }
    return result;
}

}  // namespace engine_transaction
