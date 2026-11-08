#include "ipc.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <cassert>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <cstring>
using namespace network_helper;
static Binding binding() {
    Binding b{}; b.session[0] = 1; b.challenge[0] = 2;
    const char *plan = "{}"; CC_SHA256(plan, 2, b.plan_digest.data()); return b;
}
static Request request(Op op, uint64_t seq) {
    return {op, seq, binding(), op == Op::prepare ? Bytes{'{','}'} : Bytes{}};
}
static int open_fd_count() {
    int count = 0;
    for (int fd = 0; fd < 4096; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++count;
    return count;
}
static Bytes frame(Request r) {
    Bytes data(96); uint32_t length = 92 + r.plan.size();
    for (int i = 3; i >= 0; --i) { data[i] = length & 255; length >>= 8; }
    data[4] = 1; data[5] = static_cast<uint8_t>(r.op);
    for (int i = 15; i >= 8; --i) { data[i] = r.sequence & 255; r.sequence >>= 8; }
    std::copy(r.binding.session.begin(), r.binding.session.end(), data.begin() + 16);
    std::copy(r.binding.challenge.begin(), r.binding.challenge.end(), data.begin() + 32);
    std::copy(r.binding.plan_digest.begin(), r.binding.plan_digest.end(), data.begin() + 64);
    data.insert(data.end(), r.plan.begin(), r.plan.end()); return data;
}
int main() {
    auto bytes = frame(request(Op::hello, 1));
    assert(parse_frame(bytes));
    for (size_t size = 0; size < bytes.size(); ++size) assert(!parse_frame(Bytes(bytes.begin(), bytes.begin() + size)));
    for (size_t offset : {size_t(0),size_t(4),size_t(5),size_t(6),size_t(7)}) {
        auto bad = bytes; bad[offset] = 255; assert(!parse_frame(bad));
    }
    auto bad = bytes; bad.push_back(0); assert(!parse_frame(bad));
    assert(!parse_frame(frame(request(Op::hello, 0))));
    assert(parse_frame(frame(request(Op::prepare, 2))));
    auto valid = [](const Bytes &p) { return p == Bytes{'{','}'}; };
    Flow flow(binding(), 100, 10000, valid);
    assert(flow.receive(request(Op::hello, 1), 100) == Decision::accepted);
    assert(flow.receive(request(Op::prepare, 2), 101) == Decision::prepare_validated);
    assert(flow.receive(request(Op::commit, 3), 102) == Decision::commit_requested);
    assert(flow.committed(true, 103) == Decision::accepted);
    assert(flow.receive(request(Op::fd_ack, 4), 104) == Decision::active);
    assert(flow.receive(request(Op::heartbeat, 5), 5000) == Decision::accepted);
    assert(flow.receive(request(Op::heartbeat, 6), 10000) == Decision::accepted);
    // In-session update: same validator, silence reset, state stays active,
    // and the audited lifetime deadline is unchanged.
    auto pushed = request(Op::update, 7);
    pushed.plan = Bytes{'{','}'};
    assert(flow.receive(pushed, 10025) == Decision::update_requested);
    assert(flow.receive(request(Op::heartbeat, 8), 10050) == Decision::accepted);
    assert(flow.tick(10100) == Decision::cleanup);  // lifetime, not silence
    assert(flow.receive(request(Op::hello, 9), 10101) == Decision::cleanup);
    Flow replay(binding(), 0, 120000, valid);
    assert(replay.receive(request(Op::hello, 1), 0) == Decision::accepted);
    assert(replay.receive(request(Op::hello, 1), 1) == Decision::cleanup);
    Flow premature(binding(), 0, 10000, valid);
    assert(premature.receive(request(Op::commit, 1), 0) == Decision::cleanup);
    Flow mismatch(binding(), 0, 10000, valid);
    auto mismatched = request(Op::hello, 1); mismatched.binding.challenge[1] = 1;
    assert(mismatch.receive(mismatched, 0) == Decision::cleanup);
    Flow digest(binding(), 0, 10000, valid);
    digest.receive(request(Op::hello, 1), 0);
    auto changed = request(Op::prepare, 2); changed.plan.push_back(' ');
    assert(digest.receive(changed, 1) == Decision::cleanup);
    Flow rejecting(binding(), 0, 10000, [](const Bytes &) { return false; });
    rejecting.receive(request(Op::hello, 1), 0);
    assert(rejecting.receive(request(Op::prepare, 2), 1) == Decision::cleanup);
    Flow absent(binding(), 0, 10000, {}); assert(absent.tick(0) == Decision::cleanup);
    Flow long_lived(binding(), 0, 900001, valid); assert(long_lived.tick(0) == Decision::cleanup);
    Flow maxed(binding(), 0, 900000, valid); assert(maxed.tick(1) == Decision::accepted);  // new audited lifetime cap
    Flow rollback(binding(), 100, 10000, valid); assert(rollback.tick(99) == Decision::cleanup);
    Flow heartbeat(binding(), 0, 10000, valid); assert(heartbeat.tick(6000) == Decision::cleanup);
    // Audited apply work refreshes the silence clock (unit 5 large plans).
    Flow worker(binding(), 100, 10000, valid);
    assert(worker.receive(request(Op::hello, 1), 100) == Decision::accepted);
    assert(worker.receive(request(Op::prepare, 2), 101) == Decision::prepare_validated);
    assert(worker.receive(request(Op::commit, 3), 102) == Decision::commit_requested);
    assert(worker.committed(true, 103) == Decision::accepted);
    assert(worker.receive(request(Op::fd_ack, 4), 104) == Decision::active);
    worker.keepalive(104);
    assert(worker.tick(6100) == Decision::accepted);  // 6s of apply work, still alive
    assert(worker.tick(6200) == Decision::cleanup);   // silence after work stops
    Flow eof(binding(), 0, 10000, valid); assert(eof.disconnected() == Decision::cleanup);
    // Update lifecycle beyond the happy path.
    {
        Flow updater(binding(), 100, 10000, valid);
        assert(updater.receive(request(Op::hello, 1), 100) == Decision::accepted);
        assert(updater.receive(request(Op::prepare, 2), 101) == Decision::prepare_validated);
        assert(updater.receive(request(Op::commit, 3), 102) == Decision::commit_requested);
        assert(updater.committed(true, 103) == Decision::accepted);
        assert(updater.receive(request(Op::fd_ack, 4), 104) == Decision::active);
        auto good = request(Op::update, 5); good.plan = Bytes{'{','}'};
        assert(updater.receive(good, 5000) == Decision::update_requested);
        auto again = request(Op::update, 6); again.plan = Bytes{'{','}'};
        assert(updater.receive(again, 5500) == Decision::update_requested);  // daemon dedupes
        auto bad = request(Op::update, 7); bad.plan = Bytes{'x'};
        assert(updater.receive(bad, 6000) == Decision::cleanup);
    }
    {
        Flow emptier(binding(), 100, 10000, valid);
        assert(emptier.receive(request(Op::hello, 1), 100) == Decision::accepted);
        assert(emptier.receive(request(Op::prepare, 2), 101) == Decision::prepare_validated);
        assert(emptier.receive(request(Op::commit, 3), 102) == Decision::commit_requested);
        assert(emptier.committed(true, 103) == Decision::accepted);
        assert(emptier.receive(request(Op::fd_ack, 4), 104) == Decision::active);
        auto empty = request(Op::update, 5);  // no payload
        assert(emptier.receive(empty, 5000) == Decision::cleanup);
    }
    {
        Flow premature(binding(), 100, 10000, valid);
        assert(premature.receive(request(Op::hello, 1), 100) == Decision::accepted);
        auto early = request(Op::update, 2); early.plan = Bytes{'{','}'};
        assert(premature.receive(early, 101) == Decision::cleanup);  // active only
    }
    int sockets[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(!verify_peer(sockets[0], PeerExpectation{}));
    int source = open("/dev/null", O_RDONLY | O_CLOEXEC); assert(source >= 0);
    assert(send_fd_marker(sockets[0], source));
    { auto received = receive_chunk(sockets[1], true); assert(received.valid && received.fd >= 0);
      assert(fcntl(received.fd, F_GETFD) & FD_CLOEXEC); }
    assert(send_fd_marker(sockets[0], source));
    { auto unexpected = receive_chunk(sockets[1], false); assert(!unexpected.valid && unexpected.fd < 0); }
    for (size_t number : {size_t(2), size_t(32)}) {
        int before = open_fd_count();
        std::vector<int> descriptors(number, source);
        std::vector<char> control(CMSG_SPACE(number * sizeof(int)));
        char marker = 0x46; iovec io{&marker, 1}; msghdr message{};
        message.msg_iov = &io; message.msg_iovlen = 1;
        message.msg_control = control.data(); message.msg_controllen = control.size();
        auto *c = CMSG_FIRSTHDR(&message); c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(number * sizeof(int));
        std::memcpy(CMSG_DATA(c), descriptors.data(), number * sizeof(int));
        assert(sendmsg(sockets[0], &message, 0) == 1);
        auto rejected = receive_chunk(sockets[1], true); assert(!rejected.valid && rejected.fd < 0);
        assert(open_fd_count() == before);
    }
    char marker = 0x46; assert(write(sockets[0], &marker, 1) == 1);
    { auto missing = receive_chunk(sockets[1], true); assert(!missing.valid); }
    close(source); close(sockets[0]);
    { auto closed = receive_chunk(sockets[1], false); assert(closed.eof && !closed.valid); }
    assert(!send_fd_marker(sockets[1], sockets[1]));
    close(sockets[1]);
}
