#pragma once
// Reusable utun tunnel port for the executor, mirroring the reviewed probe
// (native/utun-capability/main.cpp): PF_SYSTEM control socket, dynamic unit
// allocation, validated utun<N> name, close-then-confirm-removal. The daemon
// owns the fd until the journal releases the interface; templates allow the
// same lifecycle to run against fakes offline.
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <unistd.h>

namespace utun_tunnel {

class System {
public:
    std::string name;
    int open() {
        const int fd = ::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (fd >= 0 && ::fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
            const int saved = errno;
            ::close(fd);
            errno = saved;
            return -1;
        }
        return fd;
    }
    bool connect(int fd) {
        ctl_info info{};
        std::memcpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(UTUN_CONTROL_NAME));
        if (::ioctl(fd, CTLIOCGINFO, &info) != 0) return false;
        sockaddr_ctl address{};
        address.sc_len = sizeof(address);
        address.sc_family = AF_SYSTEM;
        address.ss_sysaddr = AF_SYS_CONTROL;
        address.sc_id = info.ctl_id;
        address.sc_unit = 0;  // dynamically allocate a fresh unit, never select one
        return ::connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0;
    }
    bool read_name(int fd) {
        char buffer[IFNAMSIZ]{};
        socklen_t size = sizeof(buffer);
        if (::getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, buffer, &size) != 0) return false;
        if (size > sizeof(buffer) || !std::memchr(buffer, 0, sizeof(buffer)) ||
            std::strncmp(buffer, "utun", 4) != 0 || buffer[4] == '\0') {
            errno = EINVAL;
            return false;
        }
        for (const char *p = buffer + 4; *p != '\0'; p++) {
            if (*p < '0' || *p > '9') {
                errno = EINVAL;
                return false;
            }
        }
        name = buffer;
        return true;
    }
    bool close(int fd) { return ::close(fd) == 0; }
    bool removed() {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
        while (std::chrono::steady_clock::now() < deadline) {
            errno = 0;
            if (::if_nametoindex(name.c_str()) == 0) {
                return errno == 0 || errno == ENXIO || errno == ENODEV;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        errno = ETIMEDOUT;
        return false;
    }
};

// Lifecycle used by both the real System and offline fakes. Every return after
// open converges on exactly one close; a closed fd must be confirmed gone
// before ownership can be released.
struct LifecycleResult {
    bool created = false;
    bool closed = false;
    bool removed = false;
    int error = 0;
};

template <class Ops>
LifecycleResult run_lifecycle(Ops &ops) {
    LifecycleResult result;
    const int fd = ops.open();
    if (fd < 0) {
        result.error = errno;
        return result;
    }
    if (!ops.connect(fd)) {
        result.error = errno;
        result.closed = ops.close(fd);
        if (!result.closed && result.error == 0) result.error = errno;
        return result;
    }
    result.created = true;
    if (!ops.read_name(fd)) {
        result.error = errno;
        result.closed = ops.close(fd);
        if (!result.closed && result.error == 0) result.error = errno;
        return result;
    }
    result.closed = ops.close(fd);
    if (!result.closed && result.error == 0) result.error = errno;
    if (result.closed) {
        result.removed = ops.removed();
        if (!result.removed && result.error == 0) result.error = errno;
    }
    return result;
}

// Offline fake mirroring the probe's failure-point matrix.
class Fake {
public:
    int fail_at = 0;
    int closes = 0;
    bool removed_seen = false;

    bool failed(int stage) {
        if (stage == fail_at) {
            errno = EACCES;
            return true;
        }
        return false;
    }
    int open() { return failed(1) ? -1 : 42; }
    bool connect(int) { return !failed(2); }
    bool read_name(int) { return !failed(3); }
    bool close(int) {
        closes++;
        return !failed(5);
    }
    bool removed() {
        removed_seen = true;
        return !failed(6);
    }
};

}  // namespace utun_tunnel
