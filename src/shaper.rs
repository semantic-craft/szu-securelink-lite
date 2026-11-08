//! Deterministic 1/1024-second TUN-read traffic shaper and probe exemption filter.
//!
//! Models the recovered vendor window scheduling algorithm:
//! - Clamps non-zero limits into `100..=0x5000_0000` bytes/window.
//! - Exempts 46-byte ICMP `Securelink` keepalive probes from byte accounting.
//! - Queues excess packets up to caller-specified packet and byte capacities.

use std::collections::VecDeque;

/// Logical clock tick in 1/1024-second units.
pub type Tick = u64;

/// Metadata token representing a single outbound TUN packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    /// Monotonic packet identifier assigned by the caller.
    pub id: u64,
    /// Total byte length including the 4-byte Darwin `utun` header when present.
    pub bytes: usize,
    /// Whether this packet is exempt from window byte accounting.
    pub count_exempt: bool,
}

/// Scheduling decision returned by [`WindowQueue::submit`] and [`WindowQueue::poll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum Action {
    /// Packet may be transmitted immediately.
    Send = 0,
    /// Packet was queued until the current window expires.
    Queued = 1,
    /// Queued packet exceeded the next window budget during replay and was dropped.
    DropReplayExcess = 2,
    /// Queue packet count or byte capacity was exhausted.
    DropCapacity = 3,
    /// Queue was stopped via [`WindowQueue::cancel`].
    DropStopped = 4,
    /// Pending packet was flushed during cancellation.
    DropCancelled = 5,
    /// Packet length was `0` or exceeded `65539` bytes.
    DropInvalidPacket = 6,
}

/// Paired packet token and scheduling [`Action`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShaperResult {
    /// The evaluated packet token.
    pub packet: Packet,
    /// The resulting scheduling action.
    pub action: Action,
}

/// Computes the effective per-window byte limit from a signed configuration integer.
///
/// # Examples
/// ```
/// use szu_securelink_rs::shaper::effective_limit;
/// assert_eq!(effective_limit(0), 0);
/// assert_eq!(effective_limit(50), 100);
/// assert_eq!(effective_limit(65536), 65536);
/// ```
#[inline]
#[must_use]
pub fn effective_limit(value: i32) -> u64 {
    if value == 0 {
        0
    } else {
        value.clamp(100, 0x5000_0000) as u64
    }
}

/// Checks whether a raw IPv4 datagram (with or without a 4-byte `utun` family header)
/// matches the fixed-offset 46-byte ICMP `Securelink` probe signature.
///
/// # Examples
/// ```
/// use szu_securelink_rs::shaper::is_count_exempt;
/// let mut pkt = vec![0u8; 46];
/// pkt[2] = 0; pkt[3] = 46; pkt[9] = 1; pkt[20] = 8;
/// pkt[36..46].copy_from_slice(b"Securelink");
/// assert!(is_count_exempt(&pkt, false));
/// ```
#[inline]
#[must_use]
pub fn is_count_exempt(data: &[u8], utun_header: bool) -> bool {
    let offset = if utun_header { 4 } else { 0 };
    if data.len() < offset + 46 {
        return false;
    }
    let ip = &data[offset..];
    ip[9] == 1
        && ip[2] == 0
        && ip[3] == 46
        && (ip[20] == 0 || ip[20] == 8)
        && &ip[36..46] == b"Securelink"
}

/// Bounded FIFO window scheduler for TUN-read rate limiting.
#[derive(Debug, Clone)]
pub struct WindowQueue {
    limit: u64,
    start: Tick,
    packet_cap: usize,
    byte_cap: usize,
    queue: VecDeque<Packet>,
    queued_bytes: usize,
    counted: u64,
    due: Option<Tick>,
    stopped: bool,
}

impl WindowQueue {
    /// Creates a new [`WindowQueue`] with bounded packet and byte capacities.
    ///
    /// # Errors
    /// Returns `Err` if `packet_cap` is outside `1..=4096` or `byte_cap` is outside `1..=67_108_864`.
    pub fn new(
        configured_limit: i32,
        start: Tick,
        packet_cap: usize,
        byte_cap: usize,
    ) -> Result<Self, &'static str> {
        if packet_cap == 0 || packet_cap > 4096 || byte_cap == 0 || byte_cap > 64 * 1024 * 1024 {
            return Err("invalid shaper queue bounds");
        }
        Ok(Self {
            limit: effective_limit(configured_limit),
            start,
            packet_cap,
            byte_cap,
            queue: VecDeque::with_capacity(packet_cap.min(128)),
            queued_bytes: 0,
            counted: 0,
            due: None,
            stopped: false,
        })
    }

    /// Submits a packet at logical clock `now` and returns its immediate [`ShaperResult`].
    #[inline]
    pub fn submit(&mut self, packet: Packet, now: Tick) -> ShaperResult {
        if self.stopped {
            return ShaperResult {
                packet,
                action: Action::DropStopped,
            };
        }
        if packet.bytes == 0 || packet.bytes > 65_539 {
            return ShaperResult {
                packet,
                action: Action::DropInvalidPacket,
            };
        }
        if self.limit == 0 || !self.over_limit(packet) {
            return self.send(packet);
        }
        let elapsed = now.saturating_sub(self.start);
        if self.due.is_none() && elapsed >= 1025 {
            self.start = now;
            self.counted = 0;
            return self.send(packet);
        }
        if self.queue.len() >= self.packet_cap
            || packet.bytes > self.byte_cap.saturating_sub(self.queued_bytes)
        {
            return ShaperResult {
                packet,
                action: Action::DropCapacity,
            };
        }
        self.queue.push_back(packet);
        self.queued_bytes += packet.bytes;
        if self.due.is_none() {
            let ms = elapsed - (3 * elapsed) / 128;
            let delay_ms = if ms <= 998 { 1000 - ms } else { 1 };
            let delay = delay_ms + (3 * delay_ms) / 128;
            self.due = Some(now.saturating_add(delay));
        }
        ShaperResult {
            packet,
            action: Action::Queued,
        }
    }

    /// Polls the queue at `now`, releasing queued packets if the window deadline has arrived.
    pub fn poll(&mut self, now: Tick) -> Vec<ShaperResult> {
        let mut out = Vec::new();
        self.poll_into(now, &mut out);
        out
    }

    /// Zero-allocation variant of [`WindowQueue::poll`] that appends results into `out`.
    #[inline]
    pub fn poll_into(&mut self, now: Tick, out: &mut Vec<ShaperResult>) {
        out.clear();
        let Some(due) = self.due else { return };
        if self.stopped || now < due {
            return;
        }
        out.reserve(self.queue.len());
        self.start = now;
        self.counted = 0;
        self.due = None;
        while let Some(packet) = self.queue.pop_front() {
            let res = if self.over_limit(packet) {
                ShaperResult {
                    packet,
                    action: Action::DropReplayExcess,
                }
            } else {
                self.send(packet)
            };
            out.push(res);
        }
        self.queued_bytes = 0;
    }

    /// Cancels all queued packets and marks the queue stopped until [`WindowQueue::restart`].
    pub fn cancel(&mut self) -> Vec<ShaperResult> {
        let out = self
            .queue
            .drain(..)
            .map(|packet| ShaperResult {
                packet,
                action: Action::DropCancelled,
            })
            .collect();
        self.queued_bytes = 0;
        self.counted = 0;
        self.due = None;
        self.stopped = true;
        out
    }

    /// Restarts a stopped queue at `now`.
    pub fn restart(&mut self, now: Tick) -> Result<(), &'static str> {
        if !self.queue.is_empty() {
            return Err("cancel shaper before restart");
        }
        self.start = now;
        self.counted = 0;
        self.due = None;
        self.stopped = false;
        Ok(())
    }

    /// Returns the active timer deadline, if any.
    #[must_use]
    pub fn deadline(&self) -> Option<Tick> {
        self.due
    }

    #[inline]
    fn over_limit(&self, packet: Packet) -> bool {
        self.limit != 0
            && self.counted != 0
            && (self.counted > self.limit || (packet.bytes as u64) > self.limit - self.counted)
    }

    #[inline]
    fn send(&mut self, packet: Packet) -> ShaperResult {
        if !packet.count_exempt {
            self.counted += packet.bytes as u64;
        }
        ShaperResult {
            packet,
            action: Action::Send,
        }
    }
}
