//! Strict IPv4/IPv6 address and CIDR prefix math matching CPython 3.15 `ipaddress`.
//!
//! Enforces:
//! - Dotted-quad IPv4 parsing without leading zeros (`01.2.3.4` rejected).
//! - Defensive bit-masking with clamped prefix bounds (`0..=128`).
//! - Reserved, loopback, link-local, multicast, and `0.0.0.0/8` assignment rejection.

/// Parsed IPv4 or IPv6 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpAddress {
    /// IP version (`4` or `6`).
    pub version: u8,
    /// Raw address bytes (IPv4 uses `bytes[0..4]`, IPv6 uses `bytes[0..16]`).
    pub bytes: [u8; 16],
}

/// Address range classification flags matching CPython 3.15 `ipaddress`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Classification {
    /// `0.0.0.0` or `::`.
    pub unspecified: bool,
    /// `127.0.0.0/8` or `::1`.
    pub loopback: bool,
    /// `224.0.0.0/4` or `ff00::/8`.
    pub multicast: bool,
    /// `169.254.0.0/16` or `fe80::/10`.
    pub link_local: bool,
    /// IETF reserved block (`240.0.0.0/4` for IPv4 or CPython 3.15 IPv6 reserved ranges).
    pub reserved: bool,
}

/// Masks a 16-byte address array to `prefix` high bits, safely clamping `prefix` to `0..=128`.
///
/// # Examples
/// ```
/// use szu_securelink_rs::ip_math::mask_bytes;
/// let mut raw = [0u8; 16];
/// raw[0] = 192; raw[1] = 168; raw[2] = 247; raw[3] = 6;
/// let masked = mask_bytes(&raw, 20);
/// assert_eq!(&masked[..4], &[192, 168, 240, 0]);
/// ```
#[inline]
#[must_use]
pub fn mask_bytes(value: &[u8; 16], prefix: i32) -> [u8; 16] {
    let clamped = prefix.clamp(0, 128);
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        let remaining = clamped - (i as i32) * 8;
        if remaining >= 8 {
            *slot = value[i];
        } else if remaining <= 0 {
            *slot = 0;
        } else {
            let shift = (8 - remaining) as u32;
            *slot = value[i] & (0xffu8.wrapping_shl(shift));
        }
    }
    out
}

/// Checks whether `value` falls inside the network defined by `(network, prefix)`.
#[inline]
#[must_use]
pub fn network_contains(network: &[u8; 16], prefix: i32, value: &[u8; 16]) -> bool {
    mask_bytes(network, prefix) == mask_bytes(value, prefix)
}

#[inline]
fn reserved_v6(a: &IpAddress) -> bool {
    let hi = a.bytes[0];
    let second = a.bytes[1];
    matches!(
        hi,
        0x00..=0x1f | 0x40..=0xdf | 0xe0..=0xfb
    ) || (hi == 0xfe && second <= 0x7f)
}

/// Classifies an [`IpAddress`] into unspecified, loopback, multicast, link-local, or reserved.
#[inline]
#[must_use]
pub fn classify(a: &IpAddress) -> Classification {
    if a.version == 4 {
        let b = a.bytes;
        Classification {
            unspecified: b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0,
            loopback: b[0] == 127,
            multicast: (224..=239).contains(&b[0]),
            link_local: b[0] == 169 && b[1] == 254,
            reserved: b[0] >= 240,
        }
    } else {
        let mut loop_v6 = [0u8; 16];
        loop_v6[15] = 1;
        Classification {
            unspecified: a.bytes == [0u8; 16],
            loopback: a.bytes == loop_v6,
            multicast: a.bytes[0] == 0xff,
            link_local: a.bytes[0] == 0xfe && (a.bytes[1] & 0xc0) == 0x80,
            reserved: reserved_v6(a),
        }
    }
}

/// Returns `true` if `a` is rejected for tunnel virtual-IP or route endpoint assignment.
///
/// # Examples
/// ```
/// use szu_securelink_rs::ip_math::{parse_ipv4, rejected_for_assignment};
/// assert!(!rejected_for_assignment(&parse_ipv4("192.168.240.166").unwrap()));
/// assert!(rejected_for_assignment(&parse_ipv4("127.0.0.1").unwrap()));
/// assert!(rejected_for_assignment(&parse_ipv4("240.0.0.1").unwrap()));
/// ```
#[inline]
#[must_use]
pub fn rejected_for_assignment(a: &IpAddress) -> bool {
    let c = classify(a);
    let v4_zero_octet = a.version == 4 && a.bytes[0] == 0;
    c.unspecified || c.loopback || c.multicast || c.link_local || c.reserved || v4_zero_octet
}

/// Parses a strict dotted-quad IPv4 string (rejecting leading zeros such as `"01.1.1.1"`).
///
/// # Examples
/// ```
/// use szu_securelink_rs::ip_math::parse_ipv4;
/// assert!(parse_ipv4("192.168.247.6").is_some());
/// assert!(parse_ipv4("192.168.01.1").is_none());
/// ```
#[inline]
#[must_use]
pub fn parse_ipv4(text: &str) -> Option<IpAddress> {
    let raw = text.as_bytes();
    if raw.is_empty() || raw.len() > 15 {
        return None;
    }
    let mut out = IpAddress {
        version: 4,
        bytes: [0u8; 16],
    };
    let mut part = 0usize;
    let mut value: i32 = -1;
    let mut digits = 0usize;

    for i in 0..=raw.len() {
        let c = if i < raw.len() { raw[i] } else { b'.' };
        if c == b'.' {
            if !(0..=255).contains(&value) || part == 4 {
                return None;
            }
            out.bytes[part] = value as u8;
            part += 1;
            value = -1;
            digits = 0;
            continue;
        }
        if !c.is_ascii_digit() {
            return None;
        }
        if value < 0 {
            if c == b'0' && i + 1 < raw.len() && raw[i + 1].is_ascii_digit() {
                return None;
            }
            digits = 1;
            value = (c - b'0') as i32;
            continue;
        }
        digits += 1;
        if digits > 3 {
            return None;
        }
        value = value * 10 + (c - b'0') as i32;
        if value > 255 {
            return None;
        }
    }
    if part == 4 {
        Some(out)
    } else {
        None
    }
}
