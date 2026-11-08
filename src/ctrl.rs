//! Control-channel (`ctrl`) static DNS mapping parser and IPv4 destination classifier.
//!
//! Validates pushed `ctrl` options (`domain:<host> sourceIp:<ip1;ip2>`) and compiles
//! accepted destination IPv4 addresses into a flat sorted `u32` lookup table for
//! zero-allocation packet classification.

use crate::ip_math::{parse_ipv4, rejected_for_assignment};

/// Maximum `ctrl` options accepted in a single snapshot.
pub const MAX_OPTIONS: usize = 64;
/// Maximum arguments per `ctrl` option.
pub const MAX_ARGUMENTS: usize = 32;
/// Maximum UTF-8 bytes per argument.
pub const MAX_ARGUMENT_BYTES: usize = 512;
/// Maximum total UTF-8 bytes across an option snapshot.
pub const MAX_INPUT_BYTES: usize = 32_768;
/// Maximum IPv4 addresses per `sourceIp` field.
pub const MAX_ADDRESSES: usize = 16;

/// Categorized rejection reasons for invalid `ctrl` policy snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtrlFailure {
    /// Option count, argument count, byte budget, or address count exceeded.
    Limit,
    /// Missing `"ctrl"` prefix, non-printable ASCII, or malformed `key:value` token.
    MalformedOption,
    /// Key other than `domain` or `sourceIp`.
    UnsupportedKey,
    /// Option missing required `domain` or `sourceIp` key.
    MissingField,
    /// Domain failed RFC label validation.
    UnsupportedDomain,
    /// Address list empty or contains a non-canonical IPv4 literal.
    UnsupportedAddress,
}

/// Validated `domain -> IPv4 addresses` mapping entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticMapping {
    /// Validated domain name.
    pub domain: String,
    /// Validated dotted-quad IPv4 strings.
    pub addresses: Vec<String>,
    /// Retains the vendor's `any` address policy intent.
    pub address_policy_any: bool,
}

/// Validated snapshot of all `ctrl` options in a generation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// Unique domain mappings in first-seen order.
    pub mappings: Vec<StaticMapping>,
    /// Total `ctrl` options validated.
    pub option_count: usize,
    /// Count of duplicate keys encountered within options.
    pub duplicate_keys: usize,
    /// Count of duplicate domain definitions skipped after validation.
    pub duplicate_domains: usize,
}

/// Validates an exact RFC hostname label sequence (`1..=253` bytes, labels `1..=63`, no leading/trailing `-`).
///
/// # Examples
/// ```
/// use szu_securelink_rs::ctrl::exact_domain;
/// assert!(exact_domain("cwpt.szu.edu.cn"));
/// assert!(!exact_domain("-bad.szu.edu.cn"));
/// ```
#[must_use]
pub fn exact_domain(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    let mut label = 0usize;
    let mut prev = 0u8;
    for &b in value.as_bytes() {
        if b == b'.' {
            if label == 0 || label > 63 || prev == b'-' {
                return false;
            }
            label = 0;
        } else {
            if !b.is_ascii_alphanumeric() && b != b'-' {
                return false;
            }
            if label == 0 && b == b'-' {
                return false;
            }
            label += 1;
        }
        prev = b;
    }
    label > 0 && label <= 63 && prev != b'-'
}

/// Splits and validates a `;`- or `&`-delimited IPv4 address list.
pub fn parse_addresses(value: &str) -> Result<Vec<String>, CtrlFailure> {
    if value.is_empty() {
        return Err(CtrlFailure::UnsupportedAddress);
    }
    let mut result = Vec::new();
    for item in value.split([';', '&']) {
        if parse_ipv4(item).is_none_or(|ip| rejected_for_assignment(&ip)) {
            return Err(CtrlFailure::UnsupportedAddress);
        }
        if result.len() == MAX_ADDRESSES {
            return Err(CtrlFailure::Limit);
        }
        result.push(item.to_string());
    }
    Ok(result)
}

/// Parses and validates a full slice of `ctrl` options.
///
/// # Errors
/// Returns [`CtrlFailure`] if any option violates size bounds or syntax invariants.
pub fn parse_options<S: AsRef<str>>(options: &[Vec<S>]) -> Result<Snapshot, CtrlFailure> {
    if options.len() > MAX_OPTIONS {
        return Err(CtrlFailure::Limit);
    }
    let mut total = 0usize;
    for opt in options {
        if opt.len() <= 1 || opt[0].as_ref() != "ctrl" {
            return Err(CtrlFailure::MalformedOption);
        }
        if opt.len() - 1 > MAX_ARGUMENTS {
            return Err(CtrlFailure::Limit);
        }
        for arg in opt {
            let s = arg.as_ref();
            if s.len() > MAX_ARGUMENT_BYTES || s.len() > MAX_INPUT_BYTES.saturating_sub(total) {
                return Err(CtrlFailure::Limit);
            }
            total += s.len();
            if !s.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
                return Err(CtrlFailure::MalformedOption);
            }
        }
    }

    let mut result = Snapshot {
        mappings: Vec::new(),
        option_count: options.len(),
        duplicate_keys: 0,
        duplicate_domains: 0,
    };

    for opt in options {
        let mut domain_val: Option<&str> = None;
        let mut source_val: Option<&str> = None;
        for arg in &opt[1..] {
            let mut any_token = false;
            for token in arg.as_ref().split(' ').filter(|t| !t.is_empty()) {
                any_token = true;
                let Some(colon) = token.find(':') else {
                    return Err(CtrlFailure::MalformedOption);
                };
                if colon == 0 || token[colon + 1..].contains(':') {
                    return Err(CtrlFailure::MalformedOption);
                }
                let (key, val) = (&token[..colon], &token[colon + 1..]);
                match key {
                    "domain" => {
                        if domain_val.is_some() {
                            result.duplicate_keys += 1;
                        } else {
                            domain_val = Some(val);
                        }
                    }
                    "sourceIp" => {
                        if source_val.is_some() {
                            result.duplicate_keys += 1;
                        } else {
                            source_val = Some(val);
                        }
                    }
                    _ => return Err(CtrlFailure::UnsupportedKey),
                }
            }
            if !any_token {
                return Err(CtrlFailure::MalformedOption);
            }
        }
        let (Some(domain), Some(source)) = (domain_val, source_val) else {
            return Err(CtrlFailure::MissingField);
        };
        if !exact_domain(domain) {
            return Err(CtrlFailure::UnsupportedDomain);
        }
        let parsed = parse_addresses(source)?;
        if result.mappings.iter().any(|m| m.domain == domain) {
            result.duplicate_domains += 1;
            continue;
        }
        result.mappings.push(StaticMapping {
            domain: domain.to_string(),
            addresses: parsed,
            address_policy_any: true,
        });
    }
    Ok(result)
}

/// Classification result for an outbound IP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum PacketDecision {
    /// Destination IPv4 matches an active `ctrl` policy address.
    DestinationAllowed = 0,
    /// Valid IPv4 packet whose destination is not in the `ctrl` table.
    NotCovered = 1,
    /// Truncated or header-corrupted IPv4 datagram.
    InvalidIpv4 = 2,
    /// Non-IPv4 version nibble.
    UnsupportedFamily = 3,
}

/// Host route `/32` intent derived from an active `ctrl` snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRouteIntent {
    /// Dotted-quad IPv4 address.
    pub address: String,
    /// Route prefix length (`32`).
    pub prefix: u8,
    /// Route metric (`0`).
    pub metric: i32,
}

/// Flat sorted IPv4 destination classifier replacing `std::set<std::array<uint8_t, 4>>`.
#[derive(Debug, Clone, Default)]
pub struct Effects {
    destinations: Vec<u32>,
}

impl Effects {
    /// Creates an empty [`Effects`] classifier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            destinations: Vec::new(),
        }
    }

    /// Atomically replaces the active destination set from `options`.
    ///
    /// # Errors
    /// Leaves existing state untouched if [`parse_options`] fails.
    pub fn replace<S: AsRef<str>>(&mut self, options: &[Vec<S>]) -> Result<(), CtrlFailure> {
        let snapshot = parse_options(options)?;
        let mut next = Vec::new();
        for mapping in &snapshot.mappings {
            for addr_str in &mapping.addresses {
                let addr = parse_ipv4(addr_str).ok_or(CtrlFailure::UnsupportedAddress)?;
                let ip_u32 = u32::from_be_bytes([
                    addr.bytes[0],
                    addr.bytes[1],
                    addr.bytes[2],
                    addr.bytes[3],
                ]);
                next.push(ip_u32);
            }
        }
        next.sort_unstable();
        next.dedup();
        self.destinations = next;
        Ok(())
    }

    /// Returns sorted `/32` host route intents for all active destinations.
    #[must_use]
    pub fn initial_routes(&self) -> Vec<HostRouteIntent> {
        self.destinations
            .iter()
            .map(|&ip| {
                let b = ip.to_be_bytes();
                HostRouteIntent {
                    address: format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
                    prefix: 32,
                    metric: 0,
                }
            })
            .collect()
    }

    /// Classifies a raw IPv4 datagram (without Darwin `utun` 4-byte prefix).
    #[inline]
    #[must_use]
    pub fn classify(&self, packet: &[u8]) -> PacketDecision {
        if packet.is_empty() {
            return PacketDecision::InvalidIpv4;
        }
        if (packet[0] >> 4) != 4 {
            return PacketDecision::UnsupportedFamily;
        }
        if packet.len() < 20 {
            return PacketDecision::InvalidIpv4;
        }
        let header_len = ((packet[0] & 0x0f) as usize) * 4;
        let total_len = ((packet[2] as usize) << 8) | (packet[3] as usize);
        if header_len < 20
            || header_len > packet.len()
            || total_len != packet.len()
            || total_len < header_len
        {
            return PacketDecision::InvalidIpv4;
        }
        let dst = u32::from_be_bytes([packet[16], packet[17], packet[18], packet[19]]);
        if self.destinations.binary_search(&dst).is_ok() {
            PacketDecision::DestinationAllowed
        } else {
            PacketDecision::NotCovered
        }
    }
}
