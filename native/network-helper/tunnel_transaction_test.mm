// Offline scenarios for the tunnel transaction driver. Builds real wire
// frames against the audited parser, drives the daemon policy through fakes,
// and asserts ownership semantics: nothing outside the journal is applied,
// cleanup always converges, and only approved plans reach the executor.
// Prints nothing on success; failures go to stderr with exit 1.
#import <CommonCrypto/CommonDigest.h>
#import <Foundation/Foundation.h>
#import <arpa/inet.h>
#import <cstdio>
#import <cstring>
#import <string>
#import <vector>
#import "ipc.hpp"
#import "tunnel_transaction.hpp"

namespace {

int failures = 0;
void check(bool ok, const char *what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL %s\n", what);
        failures++;
    }
}

constexpr char kPlanJson[] =
    "{\"version\": 2, \"ctrlOptionsCaptured\": true, \"ctrlOptionCount\": 0, \"ctrlDuplicateKeys\": 0,"
    " \"ctrlDuplicateDomains\": 0, \"ctrlMappings\": [], \"domainOptionsCaptured\": true,"
    " \"domainOptions\": [], \"complete\": true, \"failure\": null, \"layer\": 3, \"mtu\": 1400,"
    " \"remote\": {\"address\": \"198.51.100.4\", \"ipv6\": false},"
    " \"addresses\": [{\"address\": \"10.20.0.2\", \"prefixLength\": 30, \"gateway\": \"10.20.0.1\","
    " \"ipv6\": false, \"net30\": false}],"
    " \"routes\": [{\"address\": \"10.30.0.0\", \"prefixLength\": 16, \"metric\": -1, \"ipv6\": false}],"
    " \"excludedRoutes\": [], \"routeMetricDefault\": -1, \"redirect\": null,"
    " \"dns\": {\"fromDhcp\": true, \"searchDomains\": [], \"servers\": [{\"priority\": 0,"
    " \"addresses\": [{\"address\": \"10.30.0.53\", \"port\": 0}],"
    " \"domains\": [\"campus.example\", \"finance.campus.example\"]}]},"
    " \"allowIPv4\": true, \"allowIPv6\": null, \"allowLocalDNS\": true, \"sessionNameDiscarded\": true}";

// Same fixture shape with a different pushed prefix: the unit-4 delta plan.
constexpr char kDeltaPlanJson[] =
    "{\"version\": 2, \"ctrlOptionsCaptured\": true, \"ctrlOptionCount\": 0, \"ctrlDuplicateKeys\": 0,"
    " \"ctrlDuplicateDomains\": 0, \"ctrlMappings\": [], \"domainOptionsCaptured\": true,"
    " \"domainOptions\": [], \"complete\": true, \"failure\": null, \"layer\": 3, \"mtu\": 1400,"
    " \"remote\": {\"address\": \"198.51.100.4\", \"ipv6\": false},"
    " \"addresses\": [{\"address\": \"10.20.0.2\", \"prefixLength\": 30, \"gateway\": \"10.20.0.1\","
    " \"ipv6\": false, \"net30\": false}],"
    " \"routes\": [{\"address\": \"203.0.113.0\", \"prefixLength\": 24, \"metric\": -1, \"ipv6\": false}],"
    " \"excludedRoutes\": [], \"routeMetricDefault\": -1, \"redirect\": null,"
    " \"dns\": {\"fromDhcp\": true, \"searchDomains\": [], \"servers\": []},"
    " \"allowIPv4\": true, \"allowIPv6\": null, \"allowLocalDNS\": true, \"sessionNameDiscarded\": true}";

std::array<uint8_t, 16> session_bytes() {
    std::array<uint8_t, 16> out{};
    out.fill(0xA1);
    return out;
}

std::array<uint8_t, 32> digest_of(const std::string &plan) {
    std::array<uint8_t, 32> out{};
    CC_SHA256(plan.data(), static_cast<CC_LONG>(plan.size()), out.data());
    return out;
}

network_helper::Bytes make_frame(network_helper::Op op, uint64_t sequence,
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

struct FakeNet {
    bool authenticate_result = true;
    uint64_t clock = 1000;
    std::vector<network_helper::Bytes> frames;
    size_t cursor = 0;
    bool fd_marker_sent = false;

    bool authenticate(int, const tunnel_transaction::CodeExpectation &) { return authenticate_result; }
    bool wait_readable(int, int) { return cursor < frames.size(); }
    uint64_t now_ms() {
        clock += 100;
        return clock;
    }
    bool send_fd_marker(int, int) {
        fd_marker_sent = true;
        return true;
    }
    network_helper::Received receive(int, bool) {
        network_helper::Received received;
        if (cursor >= frames.size()) {
            received.eof = true;
            return received;
        }
        received.bytes = frames[cursor++];
        received.valid = true;
        return received;
    }
};

struct FakeExecutor {
    int open_count = 0;
    int close_count = 0;
    bool fail_open = false;
    std::string fail_apply_key;
    std::vector<std::string> applied_keys;
    std::vector<std::string> removed_keys;

    int tunnel_open() {
        open_count++;
        return fail_open ? -1 : 42;
    }
    bool close_tunnel(int) {
        close_count++;
        return true;
    }
    std::string tunnel_name() { return "utun9"; }
    long long tunnel_ifindex() { return 9; }
    std::string tunnel_identity() { return "b5c9d692-528e-44d3-966c-9f3772fbc3a9"; }
    bool tunnel_close(int) {
        close_count++;
        return true;
    }
    bool tunnel_removed() { return true; }
    bool apply_op(const plan_ops::Operation &op) {
        if (op.key == fail_apply_key) return false;
        applied_keys.push_back(op.key);
        return true;
    }
    bool remove_op(const plan_ops::Operation &op) {
        removed_keys.push_back(op.key);
        return true;
    }
};

tunnel_transaction::Approval approval_for(const std::string &plan) {
    tunnel_transaction::Approval approval;
    network_helper::Binding approved;
    approved.session = session_bytes();
    approved.challenge.fill(0x22);
    approved.plan_digest = digest_of(plan);
    approval.preapproved_binding = approved;
    approval.context.session_id = "f50ed258-6ef7-4f2c-9b63-c0838c89c9fa";
    approval.context.duration_seconds = 120;
    approval.context.remote_port = 443;
    approval.context.verified_dns_suffixes = {"campus.example"};
    approval.duration_ms = 120000;
    approval.peer.uid = 501;
    return approval;
}

}  // namespace

int main() {
    const std::string plan(kPlanJson);
    const std::string delta(kDeltaPlanJson);
    network_helper::Binding binding{};

    // Happy path: full transaction, then client disconnect converges cleanup.
    {
        auto net = FakeNet{};
        auto exec = FakeExecutor{};
        const auto approval = approval_for(plan);
        binding = *approval.preapproved_binding;
        net.frames.push_back(make_frame(network_helper::Op::hello, 1, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::prepare, 2, binding, plan));
        net.frames.push_back(make_frame(network_helper::Op::commit, 3, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::fd_ack, 4, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::heartbeat, 5, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::disconnect, 6, binding, ""));
        tunnel_transaction::Hooks<FakeNet, FakeExecutor> hooks{&net, &exec};
        const auto result = tunnel_transaction::run_transaction(7, approval, hooks);
        check(result.engine_authenticated, "engine authenticated");
        check(result.phase == "cleanup", "disconnect ends in cleanup");
        check(result.applied.size() == 5, "five owned operations applied");
        check(result.applied.size() == result.removed.size(), "cleanup removes everything applied");
        check(result.removed.front() == result.applied.back(), "removal order is reverse");
        check(result.fd_sent && result.fd_ack_received, "fd handed over and acknowledged");
        check(hooks.exec->open_count == 1 && hooks.exec->close_count == 1, "tunnel opened and closed once");
        check(result.tunnel_fd == -1, "no fd retained after cleanup");
    }

    // Digest mismatch: prepare bytes differ from the approved digest.
    {
        auto net = FakeNet{};
        auto exec = FakeExecutor{};
        const auto approval = approval_for(plan);
        binding = *approval.preapproved_binding;
        net.frames.push_back(make_frame(network_helper::Op::hello, 1, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::prepare, 2, binding, plan + " "));
        tunnel_transaction::Hooks<FakeNet, FakeExecutor> hooks{&net, &exec};
        const auto result = tunnel_transaction::run_transaction(7, approval, hooks);
        check(result.phase == "rejected", "digest mismatch ends rejected");
        check(result.applied.empty() && result.removed.empty(), "nothing applied on digest mismatch");
        check(hooks.exec->open_count == 0, "executor never opened");
    }

    // Digest matches but the plan content fails validation.
    {
        const std::string invalid = "{\"version\":1}";
        auto approval = approval_for(plan);
        approval.preapproved_binding->plan_digest = digest_of(invalid);
        auto net = FakeNet{};
        auto exec = FakeExecutor{};
        binding = *approval.preapproved_binding;
        net.frames.push_back(make_frame(network_helper::Op::hello, 1, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::prepare, 2, binding, invalid));
        tunnel_transaction::Hooks<FakeNet, FakeExecutor> hooks{&net, &exec};
        const auto result = tunnel_transaction::run_transaction(7, approval, hooks);
        check(result.phase == "rejected", "invalid plan ends rejected");
        check(result.applied.empty(), "invalid plan never reaches the executor");
        check(hooks.exec->open_count == 0, "executor never opened for invalid plan");
    }

    // Ordering violation: prepare before hello.
    {
        auto net = FakeNet{};
        auto exec = FakeExecutor{};
        const auto approval = approval_for(plan);
        binding = *approval.preapproved_binding;
        net.frames.push_back(make_frame(network_helper::Op::prepare, 1, binding, plan));
        net.frames.push_back(make_frame(network_helper::Op::hello, 2, binding, ""));
        tunnel_transaction::Hooks<FakeNet, FakeExecutor> hooks{&net, &exec};
        const auto result = tunnel_transaction::run_transaction(7, approval, hooks);
        check(result.phase == "rejected", "ordering violation ends rejected");
        check(result.applied.empty(), "ordering violation applies nothing");
    }

    // Executor cannot open the tunnel.
    {
        auto net = FakeNet{};
        auto exec = FakeExecutor{};
        exec.fail_open = true;
        const auto approval = approval_for(plan);
        binding = *approval.preapproved_binding;
        net.frames.push_back(make_frame(network_helper::Op::hello, 1, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::prepare, 2, binding, plan));
        net.frames.push_back(make_frame(network_helper::Op::commit, 3, binding, ""));
        tunnel_transaction::Hooks<FakeNet, FakeExecutor> hooks{&net, &exec};
        const auto result = tunnel_transaction::run_transaction(7, approval, hooks);
        check(result.phase == "failed-open", "open failure reported");
        check(result.applied.empty(), "open failure applies nothing");
        check(result.fd_sent == false, "no fd on open failure");
    }

    // Apply failure partway: created operations roll back in reverse.
    {
        auto net = FakeNet{};
        auto exec = FakeExecutor{};
        exec.fail_apply_key = "State:/Network/Service/szu-securelink-f50ed258-6ef7-4f2c-9b63-c0838c89c9fa/DNS";
        const auto approval = approval_for(plan);
        binding = *approval.preapproved_binding;
        net.frames.push_back(make_frame(network_helper::Op::hello, 1, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::prepare, 2, binding, plan));
        net.frames.push_back(make_frame(network_helper::Op::commit, 3, binding, ""));
        tunnel_transaction::Hooks<FakeNet, FakeExecutor> hooks{&net, &exec};
        const auto result = tunnel_transaction::run_transaction(7, approval, hooks);
        check(result.phase == "cleanup", "apply failure ends in cleanup");
        check(result.applied.size() == 4, "four operations applied before failure");
        check(result.removed.size() == 4, "four applied operations rolled back");
        check(result.removed.front() == result.applied.back(), "rollback order is reverse");
        check(hooks.exec->close_count == 1, "tunnel closed after rollback");
        check(!result.fd_sent, "no fd when the commit failed");
    }

    // Authentication gate.
    {
        auto net = FakeNet{};
        auto exec = FakeExecutor{};
        net.authenticate_result = false;
        const auto approval = approval_for(plan);
        tunnel_transaction::Hooks<FakeNet, FakeExecutor> hooks{&net, &exec};
        const auto result = tunnel_transaction::run_transaction(7, approval, hooks);
        check(result.phase == "rejected", "unauthenticated peer rejected");
        check(result.engine_authenticated == false, "authentication flag unset");
        check(hooks.exec->open_count == 0, "executor untouched without authentication");
    }

    // Learned binding: no preapproved binding, the authenticated hello is the
    // bootstrap. Same happy path must succeed end to end.
    {
        auto net = FakeNet{};
        auto exec = FakeExecutor{};
        auto approval = approval_for(plan);
        approval.preapproved_binding.reset();
        binding = *approval_for(plan).preapproved_binding;
        net.frames.push_back(make_frame(network_helper::Op::hello, 1, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::prepare, 2, binding, plan));
        net.frames.push_back(make_frame(network_helper::Op::commit, 3, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::fd_ack, 4, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::disconnect, 5, binding, ""));
        tunnel_transaction::Hooks<FakeNet, FakeExecutor> hooks{&net, &exec};
        const auto result = tunnel_transaction::run_transaction(7, approval, hooks);
        check(result.phase == "cleanup", "learned-binding session converges cleanup");
        check(result.applied.size() == 5 && result.removed.size() == 5,
              "learned binding applies and rolls back all operations");
        check(result.fd_sent && result.fd_ack_received, "learned binding hands over the fd");
    }

    // Unit 5: staged static policy routes ride the same journal; one covered
    // by the plan is skipped, one new range is applied and rolled back first.
    {
        auto net = FakeNet{};
        auto exec = FakeExecutor{};
        auto approval = approval_for(plan);
        approval.context.static_routes = {"10.30.0.0/16", "198.51.100.0/24"};
        binding = *approval.preapproved_binding;
        net.frames.push_back(make_frame(network_helper::Op::hello, 1, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::prepare, 2, binding, plan));
        net.frames.push_back(make_frame(network_helper::Op::commit, 3, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::fd_ack, 4, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::disconnect, 5, binding, ""));
        tunnel_transaction::Hooks<FakeNet, FakeExecutor> hooks{&net, &exec};
        const auto result = tunnel_transaction::run_transaction(7, approval, hooks);
        check(result.phase == "cleanup", "static-route session converges cleanup");
        check(result.applied.size() == 6, "one covered static route skipped, one applied");
        check(result.applied.back() == "route:198.51.100.0/24", "static route applied after the plan");
        check(result.removed.size() == 6, "static route rolls back before the base plan");
        check(result.issues.empty(), "static-route session reports no issues");
    }

    // Static route apply failure rolls the whole audited set back.
    {
        auto net = FakeNet{};
        auto exec = FakeExecutor{};
        exec.fail_apply_key = "route:198.51.100.0/24";
        auto approval = approval_for(plan);
        approval.context.static_routes = {"198.51.100.0/24"};
        binding = *approval.preapproved_binding;
        net.frames.push_back(make_frame(network_helper::Op::hello, 1, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::prepare, 2, binding, plan));
        net.frames.push_back(make_frame(network_helper::Op::commit, 3, binding, ""));
        tunnel_transaction::Hooks<FakeNet, FakeExecutor> hooks{&net, &exec};
        const auto result = tunnel_transaction::run_transaction(7, approval, hooks);
        check(result.phase == "cleanup", "static apply failure ends in cleanup");
        check(result.applied.size() == 5, "failed static route contributes nothing");
        check(result.removed.size() == 5, "base plan rolls back after static failure");
    }

    // EOF before fd_ack: everything applied is still rolled back.
    {
        auto net = FakeNet{};
        auto exec = FakeExecutor{};
        const auto approval = approval_for(plan);
        binding = *approval.preapproved_binding;
        net.frames.push_back(make_frame(network_helper::Op::hello, 1, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::prepare, 2, binding, plan));
        net.frames.push_back(make_frame(network_helper::Op::commit, 3, binding, ""));
        tunnel_transaction::Hooks<FakeNet, FakeExecutor> hooks{&net, &exec};
        const auto result = tunnel_transaction::run_transaction(7, approval, hooks);
        check(result.fd_sent, "fd was sent before the peer vanished");
        check(result.fd_ack_received == false, "fd_ack never arrived");
        check(result.phase == "cleanup", "eof ends in cleanup");
        check(result.applied.size() == result.removed.size(), "eof rolls back everything");
    }

    // Unit 4: in-session update applies pushed routes on top of the base.
    {
        auto net = FakeNet{};
        auto exec = FakeExecutor{};
        const auto approval = approval_for(plan);
        binding = *approval.preapproved_binding;
        net.frames.push_back(make_frame(network_helper::Op::hello, 1, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::prepare, 2, binding, plan));
        net.frames.push_back(make_frame(network_helper::Op::commit, 3, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::fd_ack, 4, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::update, 5, binding, delta));
        net.frames.push_back(make_frame(network_helper::Op::disconnect, 6, binding, ""));
        tunnel_transaction::Hooks<FakeNet, FakeExecutor> hooks{&net, &exec};
        const auto result = tunnel_transaction::run_transaction(7, approval, hooks);
        check(result.phase == "cleanup", "update session converges cleanup");
        check(result.applied.size() == 6, "update adds the pushed route to applied");
        check(result.applied.back() == "route:203.0.113.0/24", "pushed route applied last");
        check(result.removed.size() == 6, "update rolls back with the base plan");
        check(result.removed.front() == "route:203.0.113.0/24", "pushed route removed first");
        check(result.fd_sent && result.fd_ack_received, "update session handed over the fd");
        check(result.issues.empty(), "update session reports no issues");
    }

    // Duplicate update key fails the session closed with full rollback.
    {
        auto net = FakeNet{};
        auto exec = FakeExecutor{};
        const auto approval = approval_for(plan);
        binding = *approval.preapproved_binding;
        net.frames.push_back(make_frame(network_helper::Op::hello, 1, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::prepare, 2, binding, plan));
        net.frames.push_back(make_frame(network_helper::Op::commit, 3, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::fd_ack, 4, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::update, 5, binding, plan));  // base again
        tunnel_transaction::Hooks<FakeNet, FakeExecutor> hooks{&net, &exec};
        const auto result = tunnel_transaction::run_transaction(7, approval, hooks);
        check(result.phase == "cleanup", "duplicate update ends in cleanup");
        check(result.applied.size() == 5, "duplicate update applied nothing extra");
        check(result.removed.size() == 5, "duplicate update rolls the base plan back");
        check(result.fd_sent && result.fd_ack_received, "duplicate update kept the fd exchange");
    }

    // Invalid delta bytes: the validator rejects, nothing rolls forward.
    {
        auto net = FakeNet{};
        auto exec = FakeExecutor{};
        const auto approval = approval_for(plan);
        binding = *approval.preapproved_binding;
        net.frames.push_back(make_frame(network_helper::Op::hello, 1, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::prepare, 2, binding, plan));
        net.frames.push_back(make_frame(network_helper::Op::commit, 3, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::fd_ack, 4, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::update, 5, binding, "SECRET-GARBAGE"));
        tunnel_transaction::Hooks<FakeNet, FakeExecutor> hooks{&net, &exec};
        const auto result = tunnel_transaction::run_transaction(7, approval, hooks);
        check(result.phase == "rejected", "invalid delta ends rejected");
        // The base plan was applied before the bad update and must roll back.
        check(result.applied.size() == 5, "invalid delta applied nothing extra");
        check(result.removed.size() == 5, "invalid delta rolls the base plan back");
    }

    // Delta apply failure rolls back the base plan too.
    {
        auto net = FakeNet{};
        auto exec = FakeExecutor{};
        exec.fail_apply_key = "route:203.0.113.0/24";
        const auto approval = approval_for(plan);
        binding = *approval.preapproved_binding;
        net.frames.push_back(make_frame(network_helper::Op::hello, 1, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::prepare, 2, binding, plan));
        net.frames.push_back(make_frame(network_helper::Op::commit, 3, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::fd_ack, 4, binding, ""));
        net.frames.push_back(make_frame(network_helper::Op::update, 5, binding, delta));
        tunnel_transaction::Hooks<FakeNet, FakeExecutor> hooks{&net, &exec};
        const auto result = tunnel_transaction::run_transaction(7, approval, hooks);
        check(result.phase == "cleanup", "delta apply failure ends in cleanup");
        check(result.applied.size() == 5, "failed delta contributes no applied op");
        check(result.removed.size() == 5, "base plan rolls back after delta failure");
        check(hooks.exec->close_count == 1, "tunnel closed after delta failure");
    }

    if (failures != 0) return 1;
    return 0;
}
