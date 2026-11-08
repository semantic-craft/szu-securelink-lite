// Privileged read-only status daemon. Launchd socket-activates it, so it idles
// at zero footprint and exists only to answer the fixed status request. It
// spawns /bin/launchctl with fixed argv, reports raw exit codes, and never
// mutates the system. Tunnel setup stays out of this daemon by design.
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <mach-o/dyld.h>
#import <launch.h>
#import <arpa/inet.h>
#import <fcntl.h>
#import <signal.h>
#import <spawn.h>
#import <poll.h>
#import <sys/socket.h>
#import <sys/time.h>
#import <unistd.h>
#import <algorithm>
#import <cstdio>
#import <cstdlib>
#import <cstring>
#import <optional>
#import <string>
#import <vector>
#import "status_daemon.hpp"

using namespace status_daemon;

extern char **environ;

namespace {

constexpr int kRecvTimeoutSeconds = 5;
constexpr int kIdleExitSeconds = 10;
constexpr size_t kMaxFrameBytes = 4096;

bool read_exact(int fd, uint8_t *out, size_t length) {
    size_t done = 0;
    while (done < length) {
        ssize_t n = ::read(fd, out + done, length - done);
        if (n > 0) {
            done += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

bool write_all(int fd, const uint8_t *data, size_t length) {
    size_t done = 0;
    while (done < length) {
        ssize_t n = ::write(fd, data + done, length - done);
        if (n > 0) {
            done += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

int run_launchctl_print(const std::string &target) {
    // Fixed argv built from constants only. Output goes to /dev/null because
    // only the exit code is evidence; nothing from the child enters responses.
    const char *argv[] = {"/bin/launchctl", "print", target.c_str(), nullptr};
    posix_spawnattr_t attributes = nullptr;
    posix_spawn_file_actions_t actions = nullptr;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    pid_t child = -1;
    int spawn_error = posix_spawn(&child, argv[0], &actions, &attributes,
                                  const_cast<char *const *>(argv), environ);
    posix_spawn_file_actions_destroy(&actions);
    if (spawn_error != 0) return -1;
    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

std::string own_executable_sha256() {
    uint32_t size = 4096;
    std::vector<char> path(size);
    if (_NSGetExecutablePath(path.data(), &size) != 0) return "";
    std::vector<char> resolved(PATH_MAX, 0);
    if (realpath(path.data(), resolved.data()) == nullptr) return "";
    FILE *file = std::fopen(resolved.data(), "rb");
    if (file == nullptr) return "";
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    std::vector<uint8_t> buffer(65536);
    size_t total = 0;
    size_t n = 0;
    while ((n = std::fread(buffer.data(), 1, buffer.size(), file)) > 0) {
        CC_SHA256_Update(&context, buffer.data(), static_cast<CC_LONG>(n));
        total += n;
        if (total > 32u * 1024u * 1024u) break;
    }
    std::fclose(file);
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &context);
    static const char *kHex = "0123456789abcdef";
    std::string hex;
    hex.reserve(CC_SHA256_DIGEST_LENGTH * 2);
    for (uint8_t byte : digest) {
        hex.push_back(kHex[byte >> 4]);
        hex.push_back(kHex[byte & 0x0f]);
    }
    return hex;
}

bool peer_allowed(int fd, unsigned allowed_uid) {
    uid_t euid = static_cast<uid_t>(-1);
    gid_t egid = static_cast<gid_t>(-1);
    if (::getpeereid(fd, &euid, &egid) != 0) return false;
    return euid == 0 || euid == static_cast<uid_t>(allowed_uid);
}

void handle_connection(int fd, unsigned allowed_uid) {
    struct timeval timeout{kRecvTimeoutSeconds, 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    uint8_t length_bytes[4];
    if (!read_exact(fd, length_bytes, sizeof(length_bytes))) return;
    uint32_t length = (static_cast<uint32_t>(length_bytes[0]) << 24) |
                      (static_cast<uint32_t>(length_bytes[1]) << 16) |
                      (static_cast<uint32_t>(length_bytes[2]) << 8) |
                      static_cast<uint32_t>(length_bytes[3]);
    if (length != kRequestFrameLength) return;
    uint8_t payload[1];
    if (!read_exact(fd, payload, sizeof(payload))) return;
    if (!parse_request(payload, sizeof(payload))) return;
    if (!peer_allowed(fd, allowed_uid)) return;

    std::vector<LabelVerdict> verdicts;
    verdicts.push_back({kHelperLabel, run_launchctl_print(std::string("system/") + kHelperLabel)});
    for (size_t i = 0; i < kVendorLabelCount; i++) {
        verdicts.push_back({kVendorLabels[i],
                            run_launchctl_print(std::string("system/") + kVendorLabels[i])});
    }
    std::string response = build_response(own_executable_sha256(), allowed_uid, verdicts,
                                          static_cast<long long>(time(nullptr)));
    if (response.size() > kMaxFrameBytes) return;
    uint8_t header[4] = {
        static_cast<uint8_t>(response.size() >> 24), static_cast<uint8_t>(response.size() >> 16),
        static_cast<uint8_t>(response.size() >> 8), static_cast<uint8_t>(response.size())};
    if (!write_all(fd, header, sizeof(header))) return;
    (void)write_all(fd, reinterpret_cast<const uint8_t *>(response.data()), response.size());
}

int serve(int listen_fd, unsigned allowed_uid) {
    // Launchd starts this job because a connection arrived, and KeepAlive is
    // false: answer exactly once and exit, so idle footprint stays at zero.
    // A ten-second poll guard exits if the activation raced with a retry.
    struct pollfd wanted = {listen_fd, POLLIN, 0};
    int ready = ::poll(&wanted, 1, kIdleExitSeconds * 1000);
    if (ready <= 0) return ready == 0 ? 0 : 1;
    int fd = ::accept(listen_fd, nullptr, nullptr);
    if (fd < 0) return 1;
    handle_connection(fd, allowed_uid);
    ::close(fd);
    return 0;
}

std::optional<unsigned> parse_uid_argument(int argc, char **argv) {
    std::optional<unsigned> uid;
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--allowed-uid") == 0 && i + 1 < argc) {
            char *end = nullptr;
            long value = std::strtol(argv[i + 1], &end, 10);
            if (end != nullptr && *end == '\0' && value >= 0 && value <= 1000000) {
                uid = static_cast<unsigned>(value);
            }
            i++;
        }
    }
    return uid;
}

}  // namespace

int main(int argc, char **argv) {
    std::optional<unsigned> uid = parse_uid_argument(argc, argv);
    if (!uid.has_value()) {
        std::fputs("usage: status-daemon --allowed-uid <uid>\n", stderr);
        return 64;
    }
    int *sockets_fd = nullptr;
    size_t count = 0;
    int activation_error = launch_activate_socket("Listeners", &sockets_fd, &count);
    if (activation_error != 0 || count == 0 || sockets_fd == nullptr) {
        std::fputs("no launchd socket\n", stderr);
        return 71;
    }
    signal(SIGPIPE, SIG_IGN);
    int result = serve(sockets_fd[0], *uid);
    for (size_t i = 0; i < count; i++) ::close(sockets_fd[i]);
    free(sockets_fd);
    return result;
}
