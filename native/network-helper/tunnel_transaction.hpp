#pragma once
// Daemon-side tunnel transaction driver. Composes the audited IPC primitives
// (network_helper::Flow / verify_peer / FD marker) with the 3a validator and
// the 3b executor model: only a plan whose bytes hash to the bootstrap-approved
// digest AND pass the strict validator reaches the executor, and every applied
// operation is owned by the journal until cleanup. Offline tests drive this
// through fakes; the real daemon (3e) supplies sockets and the System utun.
// Pure policy: no main(), no socket creation, no direct OS calls.
#include <map>
#include <sys/types.h>
#include <optional>
#include <string>
#include <vector>

#include "ipc.hpp"
#include "plan_ops.hpp"
#include "plan_validator.hpp"

namespace tunnel_transaction {

// Peer identity policy: uid, the audited code's identifier, and an optional
// staged cdhash (hex). Identifier pinning always applies; the cdhash pins the
// exact binary when the install step provides it.
struct CodeExpectation {
    uid_t uid = 0;
    std::string identifier;
    std::string cdhash_hex;  // empty means identifier pinning only
};

// Trusted bootstrap data. The digest and peer expectation are established out
// of band; when preapproved_binding is absent the driver learns the binding
// from the authenticated hello frame (per-connection launchd instances have
// no other channel), and the independent executor-side validator remains the
// policy authority either way.
struct Approval {
    std::optional<network_helper::Binding> preapproved_binding;
    plan_validator::Context context;  // trusted validation context
    CodeExpectation peer;             // expected engine identity
    uint64_t duration_ms = 0;         // hard lifetime, at most 120000
};

// Hooks the driver needs. The real daemon implements these over sockets,
// Security.framework and the System utun; tests implement fakes.
template <class Net, class Executor>
struct Hooks {
    Net *net = nullptr;        // authenticate(fd), now_ms(), wait_readable, receive, send_fd_marker
    Executor *exec = nullptr;  // tunnel lifecycle + journal application
};

struct TransactionResult {
    std::string phase = "idle";                 // idle|rejected|active|cleanup|failed-open
    std::vector<std::string> applied;           // op keys applied by the executor
    std::vector<std::string> removed;           // op keys removed during cleanup
    std::vector<std::string> issues;            // "code:path" from the journal
    int tunnel_fd = -1;
    bool fd_sent = false;
    bool fd_ack_received = false;
    bool engine_authenticated = false;
    // Audit evidence (unit 5): the lease and the exact created records let the
    // daemon publish a journal file whose shape mirrors network_plan.py.
    plan_ops::InterfaceLease lease;
    bool lease_valid = false;
    std::vector<plan_ops::Operation> created_ops;
};

// Frames the client sends: hello, prepare(plan), commit, fd_ack, heartbeat,
// disconnect. The daemon replies with exactly one FD marker.
template <class Net, class Executor>
TransactionResult run_transaction(int fd, const Approval &approval, Hooks<Net, Executor> &hooks) {
    TransactionResult result;
    if (!hooks.net->authenticate(fd, approval.peer)) {
        result.phase = "rejected";
        return result;
    }
    result.engine_authenticated = true;

    std::optional<std::vector<uint8_t>> approved_plan;
    std::optional<plan_validator::Plan> validated_plan;
    auto validator = [&](const network_helper::Bytes &plan) -> bool {
        const auto decoded = plan_input::parse(plan.data(), plan.size());
        if (decoded.error != plan_input::Error::none) {
            std::fprintf(stderr, "validator: parse error %d\n", static_cast<int>(decoded.error));
            return false;
        }
        const auto validation = plan_validator::validate_capture(decoded.value, approval.context);
        if (!validation.has_plan) {
            for (const auto &single : validation.issues) {
                std::fprintf(stderr, "validator issue: %s %s\n",
                             single.code.c_str(), single.path.c_str());
            }
            return false;
        }
        approved_plan = plan;
        validated_plan = validation.plan;
        return true;
    };

    std::optional<network_helper::Flow> flow_storage;
    network_helper::Flow *flow = nullptr;
    auto cleanup = [&](plan_ops::Journal *journal,
                       const std::optional<plan_ops::InterfaceLease> &lease,
                       const std::map<std::string, plan_ops::Operation> &current) {
        if (flow != nullptr) flow->disconnected();
        if (journal != nullptr && lease.has_value()) {
            const auto outcome = journal->cleanup(current, lease);
            for (const auto &removal : outcome.removals) {
                if (hooks.exec->remove_op(removal)) result.removed.push_back(removal.key);
            }
            for (const auto &single : outcome.issues) {
                result.issues.push_back(single.code + ":" + single.path);
            }
        }
        if (result.tunnel_fd >= 0) {
            hooks.exec->close_tunnel(result.tunnel_fd);
            result.tunnel_fd = -1;
        }
        if (result.phase.empty() || result.phase == "idle") result.phase = "cleanup";
    };

    std::optional<plan_ops::InterfaceLease> lease;
    std::optional<plan_ops::Journal> journal;
    std::map<std::string, plan_ops::Operation> current;

    const uint64_t connected_ms = hooks.net->now_ms();
    while (true) {
        // Wait for a frame within this slice. Before hello the engine may
        // still be authenticating, so a quiet slice must not kill the
        // bootstrap; once the Flow exists it judges silence and lifetime.
        if (!hooks.net->wait_readable(fd, 200)) {
            const auto now = hooks.net->now_ms();
            if (flow == nullptr) {
                if (now - connected_ms >= approval.duration_ms) {
                    cleanup(nullptr, lease, current);
                    return result;
                }
                continue;
            }
            if (flow->tick(now) == network_helper::Decision::cleanup) {
                cleanup(journal.has_value() ? &*journal : nullptr, lease, current);
                return result;
            }
            continue;
        }
        auto received = hooks.net->receive(fd, false);
        std::fprintf(stderr, "driver: recv bytes=%zu eof=%d valid=%d must_exit=%d\n",
                     received.bytes.size(), received.eof ? 1 : 0,
                     received.valid ? 1 : 0, received.must_exit ? 1 : 0);
        if (received.must_exit) {
            // Descriptor truncation is unrecoverable per the audited contract.
            cleanup(journal.has_value() ? &*journal : nullptr, lease, current);
            return result;
        }
        if (received.eof) {
            cleanup(journal.has_value() ? &*journal : nullptr, lease, current);
            return result;
        }
        if (!received.valid) {
            cleanup(journal.has_value() ? &*journal : nullptr, lease, current);
            return result;
        }
        const auto request = network_helper::parse_frame(received.bytes);
        if (!request.has_value()) {
            std::fprintf(stderr, "driver: parse failed head=%02x%02x%02x%02x%02x%02x%02x%02x\n",
                         received.bytes.size() > 0 ? received.bytes[0] : 0,
                         received.bytes.size() > 1 ? received.bytes[1] : 0,
                         received.bytes.size() > 2 ? received.bytes[2] : 0,
                         received.bytes.size() > 3 ? received.bytes[3] : 0,
                         received.bytes.size() > 4 ? received.bytes[4] : 0,
                         received.bytes.size() > 5 ? received.bytes[5] : 0,
                         received.bytes.size() > 6 ? received.bytes[6] : 0,
                         received.bytes.size() > 7 ? received.bytes[7] : 0);
            cleanup(journal.has_value() ? &*journal : nullptr, lease, current);
            return result;
        }
        std::fprintf(stderr, "driver: frame op=%d seq=%llu payload=%zu\n",
                     static_cast<int>(request->op),
                     static_cast<unsigned long long>(request->sequence),
                     request->plan.size());
        if (flow == nullptr) {
            if (!approval.preapproved_binding.has_value()) {
                // Per-connection launchd instance: the authenticated hello is
                // the trusted bootstrap for session/challenge/plan digest.
                if (request->op != network_helper::Op::hello) {
                    cleanup(nullptr, lease, current);
                    return result;
                }
                flow_storage.emplace(request->binding, hooks.net->now_ms(),
                                     approval.duration_ms, validator);
            } else {
                flow_storage.emplace(*approval.preapproved_binding, hooks.net->now_ms(),
                                     approval.duration_ms, validator);
            }
            flow = &*flow_storage;
        }
        const auto decision = flow->receive(*request, hooks.net->now_ms());
        std::fprintf(stderr, "driver: decision=%d phase=%s\n", static_cast<int>(decision),
                     result.phase.c_str());
        switch (decision) {
            case network_helper::Decision::rejected:
                // Flow treats every rejection as a disconnect; nothing to do.
                continue;
            case network_helper::Decision::cleanup: {
                // A client disconnect frame is the designed session end; any
                // other cleanup decision is a protocol rejection.
                result.phase = request->op == network_helper::Op::disconnect
                                   ? "cleanup"
                                   : "rejected";
                cleanup(journal.has_value() ? &*journal : nullptr, lease, current);
                return result;
            }
            case network_helper::Decision::accepted:
                continue;
            case network_helper::Decision::prepare_validated: {
                // Plan bytes are held by the validator; nothing is applied yet.
                continue;
            }
            case network_helper::Decision::commit_requested: {
                if (!approved_plan.has_value()) {
                    cleanup(journal.has_value() ? &*journal : nullptr, lease, current);
                    return result;
                }
                const int tunnel_fd = hooks.exec->tunnel_open();
                if (tunnel_fd < 0) {
                    const auto now = hooks.net->now_ms();
                    flow->committed(false, now);
                    cleanup(journal.has_value() ? &*journal : nullptr, lease, current);
                    result.phase = "failed-open";
                    return result;
                }
                result.tunnel_fd = tunnel_fd;
                const plan_ops::InterfaceLease used_lease{
                    approval.context.session_id, hooks.exec->tunnel_name(),
                    hooks.exec->tunnel_ifindex(), hooks.exec->tunnel_identity()};
                auto plan_ops_list = plan_ops::operations(*validated_plan, used_lease);
                const auto static_ops = plan_ops::static_route_operations(
                    *validated_plan, used_lease, approval.context.static_routes);
                std::fprintf(stderr, "driver: %zu static policy routes\n", static_ops.size());
                plan_ops_list.insert(plan_ops_list.end(), static_ops.begin(), static_ops.end());
                journal.emplace(plan_ops_list, used_lease);
                lease = used_lease;
                result.lease = used_lease;
                result.lease_valid = true;
                std::fprintf(stderr, "driver: committing %zu operations\n",
                             journal->expected().size());
                bool all_applied = true;
                for (size_t index = 0; index < journal->expected().size(); index++) {
                    const plan_ops::Operation &op = journal->expected()[index];
                    const plan_ops::Operation after = op;  // executor records the canonical form
                    flow->keepalive(hooks.net->now_ms());  // apply work is traffic
                    if (!hooks.exec->apply_op(op)) {
                        std::fprintf(stderr, "driver: apply failed index=%zu key=%s\n",
                                     index, op.key.c_str());
                        journal->record(index, "failed", &op, nullptr);
                        all_applied = false;
                        break;
                    }
                    current[op.key] = after;
                    journal->record(index, "created", nullptr, &after);
                    result.applied.push_back(op.key);
                    result.created_ops.push_back(after);
                }
                const auto now = hooks.net->now_ms();
                if (!all_applied) {
                    const auto outcome = journal->cleanup(current, lease);
                    for (const auto &removal : outcome.removals) {
                        if (hooks.exec->remove_op(removal)) result.removed.push_back(removal.key);
                    }
                    for (const auto &single : outcome.issues) {
                        result.issues.push_back(single.code + ":" + single.path);
                    }
                    flow->committed(false, now);
                    hooks.exec->close_tunnel(result.tunnel_fd);
                    result.tunnel_fd = -1;
                    result.phase = "cleanup";
                    return result;
                }
                flow->committed(true, now);
                if (!hooks.net->send_fd_marker(fd, result.tunnel_fd)) {
                    cleanup(journal.has_value() ? &*journal : nullptr, lease, current);
                    return result;
                }
                result.fd_sent = true;
                continue;
            }
            case network_helper::Decision::update_requested: {
                // The just-validated bytes are the in-session push delta.
                if (!approved_plan.has_value() || !validated_plan.has_value() || !lease.has_value()
                    || !journal.has_value()) {
                    cleanup(journal.has_value() ? &*journal : nullptr, lease, current);
                    result.phase = "cleanup";
                    return result;
                }
                const auto validated_delta = std::move(*validated_plan);
                approved_plan.reset();
                validated_plan.reset();
                const auto push_ops = plan_ops::push_operations(validated_delta, *lease);
                std::fprintf(stderr, "driver: update with %zu pushed routes\n", push_ops.size());
                for (const auto &op : push_ops) {
                    if (current.count(op.key) != 0) {
                        // A duplicate against anything live (base plan or an
                        // earlier delta) fails the session closed.
                        std::fprintf(stderr, "driver: update duplicate key %s\n", op.key.c_str());
                        cleanup(journal.has_value() ? &*journal : nullptr, lease, current);
                        result.phase = "cleanup";
                        return result;
                    }
                }
                // One journal owns the whole interface: append the delta and
                // record continuing indices so cleanup removes the pushed
                // routes first, in reverse application order.
                const size_t base_count = journal->expected().size();
                journal->append(push_ops);
                bool all_applied = true;
                for (size_t index = base_count; index < journal->expected().size(); index++) {
                    const plan_ops::Operation &op = journal->expected()[index];
                    const plan_ops::Operation after = op;
                    flow->keepalive(hooks.net->now_ms());  // apply work is traffic
                    if (!hooks.exec->apply_op(op)) {
                        std::fprintf(stderr, "driver: update apply failed key=%s\n", op.key.c_str());
                        journal->record(index, "failed", &op, nullptr);
                        all_applied = false;
                        break;
                    }
                    current[op.key] = after;
                    journal->record(index, "created", nullptr, &after);
                    result.applied.push_back(op.key);
                    result.created_ops.push_back(after);
                }
                if (!all_applied) {
                    cleanup(journal.has_value() ? &*journal : nullptr, lease, current);
                    result.phase = "cleanup";
                    return result;
                }
                continue;
            }
            case network_helper::Decision::active: {
                result.fd_ack_received = true;
                result.phase = "active";
                continue;
            }
        }
    }
}

}  // namespace tunnel_transaction
