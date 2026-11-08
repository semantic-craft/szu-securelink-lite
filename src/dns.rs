//! Pure Safe Rust RFC 1035 / RFC 2181 / RFC 6891 DNS wire-format reply parser.
//!
//! Replaces the legacy C `<arpa/nameser.h>` (`libresolv`) FFI parser with a
//! 100% memory-safe, bounds-checked wire decoder supporting pointer compression,
//! EDNS0 extended RCODEs, CNAME chain resolution (up to 16 hops), and TTL clamping.

/// DNS Type `A` (IPv4 address) constant.
pub const TYPE_A: u16 = 1;
/// DNS Type `CNAME` (canonical name alias) constant.
pub const TYPE_CNAME: u16 = 5;
/// DNS Type `AAAA` (IPv6 address) constant.
pub const TYPE_AAAA: u16 = 28;
/// DNS Type `OPT` (EDNS0 metadata pseudo-RR) constant.
pub const TYPE_OPT: u16 = 41;
/// DNS Class `IN` (Internet) constant.
pub const CLASS_IN: u16 = 1;

/// Error returned when a DNS response packet violates wire format or security invariants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsError;

/// Expected DNS question parameters used to authenticate a DNS wire reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question<'a> {
    /// Expected 16-bit DNS transaction ID.
    pub id: u16,
    /// Expected query domain name.
    pub name: &'a str,
    /// Expected RR type ([`TYPE_A`] or [`TYPE_AAAA`]).
    pub qtype: u16,
}

/// Decoded IPv4 or IPv6 address record with CNAME-clamped TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsAddress {
    /// Record type ([`TYPE_A`] or [`TYPE_AAAA`]).
    pub rr_type: u16,
    /// Raw address bytes (first 4 bytes for IPv4, all 16 bytes for IPv6).
    pub bytes: [u8; 16],
    /// Clamped TTL in seconds (RFC 2181 section 8).
    pub ttl: u32,
}

/// Validated DNS response summary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsReply {
    /// Whether the `TC` (truncated) header bit was set.
    pub truncated: bool,
    /// Combined 12-bit response code (header RCODE + EDNS0 high RCODE bits).
    pub rcode: u16,
    /// Resolved addresses for the queried name or terminal CNAME target.
    pub addresses: Vec<DnsAddress>,
}

/// Normalizes a DNS domain name to lowercase ASCII without a trailing dot,
/// validating label lengths (`1..=63`) and total length (`1..=253`).
///
/// # Examples
/// ```
/// use szu_securelink_rs::dns::normalize_domain;
/// assert_eq!(normalize_domain("CWPT.SZU.EDU.CN.").unwrap(), "cwpt.szu.edu.cn");
/// assert!(normalize_domain("-bad.example").is_ok()); // underscore/hyphen allowed in DNS labels
/// assert!(normalize_domain("").is_err());
/// ```
pub fn normalize_domain(raw: &str) -> Result<String, DnsError> {
    let trimmed = raw.strip_suffix('.').unwrap_or(raw);
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(DnsError);
    }
    let mut out = String::with_capacity(trimmed.len());
    let mut label_len = 0usize;
    for b in trimmed.bytes() {
        if b == b'.' {
            if label_len == 0 || label_len > 63 {
                return Err(DnsError);
            }
            label_len = 0;
            out.push('.');
        } else {
            let lower = match b {
                b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => b,
                b'A'..=b'Z' => b + (b'a' - b'A'),
                _ => return Err(DnsError),
            };
            label_len += 1;
            out.push(lower as char);
        }
    }
    if label_len == 0 || label_len > 63 {
        return Err(DnsError);
    }
    Ok(out)
}

/// Normalizes a 32-bit TTL according to RFC 2181 section 8 (clearing values with MSB set to `0`).
///
/// # Examples
/// ```
/// use szu_securelink_rs::dns::lifetime;
/// assert_eq!(lifetime(300), 300);
/// assert_eq!(lifetime(0x8000_0001), 0);
/// ```
#[inline]
#[must_use]
pub fn lifetime(ttl: u32) -> u32 {
    if (ttl & 0x8000_0000) != 0 {
        0
    } else {
        ttl
    }
}

/// Decodes a potentially pointer-compressed RFC 1035 domain name starting at `offset` into `out`.
/// Returns the wire offset immediately following the name in the original field.
fn decode_name(
    packet: &[u8],
    mut offset: usize,
    out: &mut String,
) -> Result<usize, DnsError> {
    out.clear();
    let mut next_offset = None;
    let mut jumps = 0usize;
    loop {
        if offset >= packet.len() || jumps > 32 {
            return Err(DnsError);
        }
        let len = packet[offset];
        if len == 0 {
            if next_offset.is_none() {
                next_offset = Some(offset + 1);
            }
            break;
        }
        if (len & 0xc0) == 0xc0 {
            if offset + 1 >= packet.len() {
                return Err(DnsError);
            }
            if next_offset.is_none() {
                next_offset = Some(offset + 2);
            }
            let ptr = (((len & 0x3f) as usize) << 8) | (packet[offset + 1] as usize);
            if ptr >= packet.len() {
                return Err(DnsError);
            }
            offset = ptr;
            jumps += 1;
            continue;
        }
        if (len & 0xc0) != 0 {
            return Err(DnsError);
        }
        let label_len = len as usize;
        offset += 1;
        if offset + label_len > packet.len() {
            return Err(DnsError);
        }
        if !out.is_empty() {
            out.push('.');
        }
        for &b in &packet[offset..offset + label_len] {
            let lower = match b {
                b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => b,
                b'A'..=b'Z' => b + (b'a' - b'A'),
                _ => return Err(DnsError),
            };
            out.push(lower as char);
        }
        offset += label_len;
        if out.len() > 253 {
            return Err(DnsError);
        }
    }
    next_offset.ok_or(DnsError)
}

#[inline]
fn read_u16(data: &[u8], offset: usize) -> Result<u16, DnsError> {
    let slice = data.get(offset..offset + 2).ok_or(DnsError)?;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}

#[inline]
fn read_u32(data: &[u8], offset: usize) -> Result<u32, DnsError> {
    let slice = data.get(offset..offset + 4).ok_or(DnsError)?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Parses and validates an RFC 1035 DNS reply wire packet against `expected`.
///
/// # Errors
/// Returns [`DnsError`] if headers, question, OPT pseudo-records, or CNAME chains are malformed.
pub fn parse_reply(packet: &[u8], expected: &Question<'_>) -> Result<DnsReply, DnsError> {
    if packet.len() < 12
        || packet.len() > 65_535
        || (expected.qtype != TYPE_A && expected.qtype != TYPE_AAAA)
    {
        return Err(DnsError);
    }
    let id = read_u16(packet, 0)?;
    let flags = read_u16(packet, 2)?;
    let qdcount = read_u16(packet, 4)?;
    let ancount = read_u16(packet, 6)?;
    let nscount = read_u16(packet, 8)?;
    let arcount = read_u16(packet, 10)?;

    let qr = (flags & 0x8000) != 0;
    let opcode = (flags >> 11) & 0x0f;
    let z_bits = (flags >> 4) & 0x07;
    if id != expected.id || !qr || opcode != 0 || z_bits != 0 || qdcount != 1 {
        return Err(DnsError);
    }
    let total_rr = (ancount as usize) + (nscount as usize) + (arcount as usize);
    if total_rr > 256 {
        return Err(DnsError);
    }

    let expected_name = normalize_domain(expected.name)?;
    let mut name_buf = String::with_capacity(64);
    let mut offset = decode_name(packet, 12, &mut name_buf)?;
    if name_buf != expected_name {
        return Err(DnsError);
    }
    let qtype = read_u16(packet, offset)?;
    let qclass = read_u16(packet, offset + 2)?;
    if qtype != expected.qtype || qclass != CLASS_IN {
        return Err(DnsError);
    }
    offset += 4;

    let mut reply = DnsReply {
        truncated: (flags & 0x0200) != 0,
        rcode: flags & 0x000f,
        addresses: Vec::new(),
    };

    // Fast path for single-answer direct A/AAAA queries without CNAME or OPT records.
    if ancount == 1 && nscount == 0 && arcount == 0 && !reply.truncated && reply.rcode == 0 {
        let next = decode_name(packet, offset, &mut name_buf)?;
        let rr_type = read_u16(packet, next)?;
        let rr_class = read_u16(packet, next + 2)?;
        let ttl = lifetime(read_u32(packet, next + 4)?);
        let rdlen = read_u16(packet, next + 8)? as usize;
        let rdata_start = next + 10;
        if rdata_start + rdlen == packet.len()
            && rr_class == CLASS_IN
            && rr_type == expected.qtype
            && name_buf == expected_name
        {
            let expected_len = if expected.qtype == TYPE_A { 4 } else { 16 };
            if rdlen != expected_len {
                return Err(DnsError);
            }
            let mut bytes = [0u8; 16];
            bytes[..expected_len].copy_from_slice(&packet[rdata_start..rdata_start + expected_len]);
            reply.addresses.push(DnsAddress {
                rr_type,
                bytes,
                ttl,
            });
            return Ok(reply);
        }
    }

    // General multi-record / CNAME / EDNS0 path.
    let mut aliases: Vec<(String, String, u32)> = Vec::new();
    let mut non_alias_owners: Vec<String> = Vec::new();
    let mut records: Vec<(String, DnsAddress)> = Vec::new();
    let mut opt_seen = false;

    for idx in 0..total_rr {
        let in_answer = idx < (ancount as usize);
        let in_additional = idx >= (ancount as usize) + (nscount as usize);
        offset = decode_name(packet, offset, &mut name_buf)?;
        let owner = name_buf.clone();
        let rr_type = read_u16(packet, offset)?;
        let rr_class = read_u16(packet, offset + 2)?;
        let raw_ttl = read_u32(packet, offset + 4)?;
        let rdlen = read_u16(packet, offset + 8)? as usize;
        offset += 10;
        if offset + rdlen > packet.len() {
            return Err(DnsError);
        }

        if rr_type == TYPE_OPT {
            if !in_additional || opt_seen || !owner.is_empty() {
                return Err(DnsError);
            }
            opt_seen = true;
            if ((raw_ttl >> 16) & 0xff) != 0 {
                return Err(DnsError);
            }
            reply.rcode |= ((raw_ttl >> 24) as u16) << 4;
            let mut opt_off = 0usize;
            let rdata = &packet[offset..offset + rdlen];
            while opt_off < rdlen {
                if rdlen - opt_off < 4 {
                    return Err(DnsError);
                }
                let opt_len = read_u16(rdata, opt_off + 2)? as usize;
                opt_off += 4;
                if opt_len > rdlen - opt_off {
                    return Err(DnsError);
                }
                opt_off += opt_len;
            }
        } else if in_answer && rr_class == CLASS_IN {
            if owner.is_empty() {
                return Err(DnsError);
            }
            if rr_type == TYPE_CNAME {
                let mut target_buf = String::new();
                let end = decode_name(packet, offset, &mut target_buf)?;
                if end != offset + rdlen || target_buf.is_empty() {
                    return Err(DnsError);
                }
                let ttl = lifetime(raw_ttl);
                if let Some(existing) = aliases.iter_mut().find(|a| a.0 == owner) {
                    if existing.1 != target_buf {
                        return Err(DnsError);
                    }
                    existing.2 = existing.2.min(ttl);
                } else {
                    aliases.push((owner, target_buf, ttl));
                }
            } else {
                if !matches!(rr_type, 24 | 25 | 30 | 46 | 47) && !non_alias_owners.contains(&owner)
                {
                    non_alias_owners.push(owner.clone());
                }
                if rr_type == expected.qtype {
                    let expected_len = if expected.qtype == TYPE_A { 4 } else { 16 };
                    if rdlen != expected_len {
                        return Err(DnsError);
                    }
                    let mut bytes = [0u8; 16];
                    bytes[..expected_len].copy_from_slice(&packet[offset..offset + expected_len]);
                    records.push((
                        owner,
                        DnsAddress {
                            rr_type,
                            bytes,
                            ttl: lifetime(raw_ttl),
                        },
                    ));
                }
            }
        }
        offset += rdlen;
    }

    if reply.truncated || reply.rcode != 0 {
        reply.addresses.clear();
        return Ok(reply);
    }

    let mut current = expected_name;
    let mut visited: Vec<String> = Vec::new();
    let mut min_ttl = u32::MAX;
    for hops in 0..=16 {
        if visited.contains(&current) {
            return Err(DnsError);
        }
        visited.push(current.clone());
        if let Some((_, target, alias_ttl)) = aliases.iter().find(|a| a.0 == current) {
            if non_alias_owners.contains(&current) || hops == 16 {
                return Err(DnsError);
            }
            min_ttl = min_ttl.min(*alias_ttl);
            current = target.clone();
        } else {
            for (owner, addr) in &records {
                if owner == &current {
                    min_ttl = min_ttl.min(addr.ttl);
                }
            }
            for (owner, mut addr) in records {
                if owner == current {
                    addr.ttl = min_ttl;
                    reply.addresses.push(addr);
                }
            }
            return Ok(reply);
        }
    }
    Err(DnsError)
}
