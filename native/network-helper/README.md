# Bounded helper IPC library

This library has no production entry point, privilege launcher, listener, utun
creation, network configuration or executor. The only executable is the offline
test. A passing test does not authorize or demonstrate a privileged connection.

## Wire and transaction

Each frame is BE32 length followed by version (1 byte, value 1), operation
(1 byte), two zero reserved bytes, BE64 sequence, session bytes (16), challenge
(32), approved SHA256 plan digest (32), and payload. Total frame limit is 65536
bytes; prepare payload is 1–64000 bytes. All other payloads must be empty.
Operations 1–6 are hello, prepare, commit, fd-ack, heartbeat, disconnect.
`parse_frame` accepts exactly one complete frame, rejects partial/trailing data.
The future stream driver must bound accumulation before allocating based on a
length prefix, split/coalesce complete frames, and fail closed on malformed data.

Bootstrap supplies binding and peer expectations through a trusted channel,
never request fields or user-writable authorization files. The raw prepare bytes
must match the approved digest and pass an independent executor-side parser and
policy validator. No default validator exists. A callback returning true is not
a production implementation: strict schema, duplicates, routes, DNS, MTU and
operation ownership remain that validator's responsibility. There are no command,
environment, executable-path or generic filesystem operations in this protocol.
Dynamic routes require a separately reviewed policy and protocol extension; they
cannot be smuggled through heartbeat or a second prepare.

`Flow` is pure sequencing, not a security capability. The driver must verify the
socket before processing every request, watch the authenticated process identity
for exit, and call tick independently using monotonic milliseconds. Hard lifetime
is at most 120 seconds; silence is at most 6 seconds, including preparation and
FD acknowledgement. Heartbeats never extend the hard deadline. EOF, invalid
ordering/binding/sequence, time reversal and timeout enter permanent cleanup.
Commit is only a request: the executor records actual ownership, configures the
approved operations, reports committed(success), sends one FD, and awaits ack.
No acknowledgement means cleanup, not an active tunnel.

## OS identity and descriptors

`verify_peer` checks LOCAL_PEERCRED UID, exact LOCAL_PEERTOKEN audit identity and
the dynamic code's validity plus expected CDHash. Expectations must be established
by the trusted bootstrap, not by querying arbitrary client-provided PIDs. Verify
both directions: engine expects UID 0 and the exact authorized helper identity;
helper expects the authorized engine UID and identity. The socketpair test covers
negative authentication only; successful cross-process signed identity, exec and
PID-reuse behavior remain unverified. Authentication must not be inferred from
inherited socketpair credentials or random socket names.

FD transfer is a separate single-byte 0x46 marker with exactly one SCM_RIGHTS FD.
The sender must await the transaction state before transferring; do not pipeline
normal frames with this marker. Receivers reject missing, extra, truncated or
unexpected descriptors, close all visible rejected descriptors, and set CLOEXEC.
Darwin can install descriptors beyond a truncated ancillary buffer. The receiver
therefore reserves up to the current descriptor-limit times per-descriptor cmsg
space (limit capped at 1048576), rather than space for just one expected FD.
Limits beyond that bound reject before recvmsg. Unexpected truncation still sets
must_exit: the driver must perform bounded owned-state cleanup and terminate the
receiving process to close potentially invisible descriptors. It must never
continue or retry in that process. Tests verify no FD-count growth for rejected
2-FD and 32-FD messages; they do not claim kernel-proof absence of truncation.
`Received` owns the FD until release_fd. The caller must additionally verify its
utun socket type/name and owned interface receipt before accepting it, and select
the engine's required blocking mode. receive_chunk is nonblocking; its invalid
result is not permission to retry indefinitely. The driver applies the deadline
and treats errors/EOF as cleanup. No helper FD close revokes the engine's copy.

Root must never execute this user-writable development binary directly. The
separate audited bootstrap still needs a root-owned immutable staging copy,
fixed hash/signature verification and approved session policy. Neither this
library nor a successful parser test implements that trust boundary, process
monitoring, crash rollback, atomic route deletion or DNS reconciliation.
