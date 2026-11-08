import Foundation
import Darwin

public enum SessionLeaseError: Error, Equatable { case busy, unsafeFile, systemFailure }

/// Cooperative exclusion for our app builds and probes, not for the vendor GUI.
/// Keep the empty lock file: unlinking it could split concurrent owners across inodes.
final class SessionLease {
    private var descriptor: Int32
    init(path: String = "/tmp/szu-securelink.\(geteuid()).session.lock") throws {
        let fd = Darwin.open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard fd >= 0 else { throw SessionLeaseError.systemFailure }
        var owned = false
        defer { if !owned { Darwin.close(fd) } }
        var metadata = stat()
        guard fstat(fd, &metadata) == 0 else { throw SessionLeaseError.systemFailure }
        guard metadata.st_uid == geteuid(), metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_mode & 0o077 == 0, metadata.st_nlink == 1 else { throw SessionLeaseError.unsafeFile }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            throw errno == EWOULDBLOCK ? SessionLeaseError.busy : SessionLeaseError.systemFailure
        }
        descriptor = fd
        owned = true
    }
    func release() {
        guard descriptor >= 0 else { return }
        flock(descriptor, LOCK_UN)
        Darwin.close(descriptor)
        descriptor = -1
    }
    deinit { release() }
}
