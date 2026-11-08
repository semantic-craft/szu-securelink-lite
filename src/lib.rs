//! `szu-securelink-rs`: 100% Safe Rust (`#![forbid(unsafe_code)]`) core library for
//! SZU SecureLink Lite, covering confusion stream framing, TUN window traffic shaping,
//! RFC 1035 DNS wire parsing, control-channel policy classification, IP math,
//! campus SSO & academic library shortcuts, and the GPUI-Kit workbench state tree.

#![forbid(unsafe_code)]

extern crate gpui_kit as gpui;

pub mod agent_control;
pub mod confusion;
pub mod ctrl;
pub mod dns;
pub mod gpui_tree;
pub mod gpui_window;
pub mod gpui_workbench;
pub mod ip_math;
pub mod shaper;
pub mod shortcuts;
pub mod sparkle;
pub mod tray_bridge;
pub mod tunnel_actor;
#[cfg(test)]
mod tests;

use confusion::{encode_standard_frame, encode_standard_frame_into, StreamDecoder};
use ctrl::{Effects, PacketDecision};
use dns::{parse_reply, Question, TYPE_A};
use ip_math::{parse_ipv4, rejected_for_assignment};
use shaper::{Packet, ShaperResult, WindowQueue};

/// Deterministic SplitMix64 pseudo-random number generator shared identically with
/// the C++17 baseline harness (`out/rust-migration/legacy_bench.cpp`) for A/B parity verification.
///
/// # Examples
/// ```
/// use szu_securelink_rs::SplitMix64;
/// let mut rng = SplitMix64::new(42);
/// assert_eq!(rng.next_u64(), 13679457532755275413);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Creates a new [`SplitMix64`] instance seeded with `seed`.
    #[inline]
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Generates the next deterministic 64-bit value.
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

#[inline]
fn build_dns_packet_into(buf: &mut [u8; 49], qid: u16, last_octet: u8, ttl: u32) {
    let template: [u8; 49] = [
        (qid >> 8) as u8,
        (qid & 0xff) as u8,
        0x81,
        0x80,
        0x00,
        0x01,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        4,
        b'c',
        b'w',
        b'p',
        b't',
        3,
        b's',
        b'z',
        b'u',
        3,
        b'e',
        b'd',
        b'u',
        2,
        b'c',
        b'n',
        0,
        0x00,
        0x01,
        0x00,
        0x01,
        0xc0,
        0x0c,
        0x00,
        0x01,
        0x00,
        0x01,
        ((ttl >> 24) & 0xff) as u8,
        ((ttl >> 16) & 0xff) as u8,
        ((ttl >> 8) & 0xff) as u8,
        (ttl & 0xff) as u8,
        0x00,
        0x04,
        192,
        168,
        240,
        last_octet,
    ];
    *buf = template;
}

/// Runs the Idiomatic Safe Rust (`safe_rust`) tunnel simulation over `iterations` for `seed`.
#[must_use]
pub fn run_seed_safe(seed: u64, iterations: usize) -> f64 {
    let mut rng = SplitMix64::new(seed);
    let mut digest: u64 = 0xcbf2_9ce4_8422_2325;
    let mut mix = |v: u64| {
        digest ^= v;
        digest = digest.wrapping_mul(0x0100_0000_01b3);
    };

    let mut decoder = StreamDecoder::new();
    let mut shaper = WindowQueue::new(65_536, 100, 512, 4 * 1024 * 1024).unwrap();
    let mut ctrl_effects = Effects::new();
    let ctrl_opts = vec![
        vec!["ctrl", "domain:cwpt.szu.edu.cn sourceIp:192.168.240.166;172.31.7.46"],
        vec!["ctrl", "domain:ehall.szu.edu.cn sourceIp:192.168.240.10&210.39.3.155"],
    ];
    ctrl_effects.replace(&ctrl_opts).unwrap();

    let mut dns_pkt = [0u8; 49];
    for i in 0..iterations {
        let r = rng.next_u64();
        let payload_len = 32 + (r as usize % 96);
        let mut frame = vec![0u8; payload_len + 2];
        frame[0] = ((payload_len >> 8) & 0xff) as u8;
        frame[1] = (payload_len & 0xff) as u8;
        for j in 0..payload_len {
            frame[2 + j] = ((r >> ((j & 7) * 8)) as u8) ^ (j as u8);
        }

        let wire = encode_standard_frame(&frame).unwrap();
        let split = 1 + (r as usize % (wire.len() - 1));
        let out1 = decoder.feed(&wire[..split]).unwrap();
        let out2 = decoder.feed(&wire[split..]).unwrap();
        mix((out1.len() + out2.len()) as u64);
        if let (Some(&first), Some(&last)) = (out2.first(), out2.last()) {
            mix(first as u64);
            mix(last as u64);
        }

        let tick = 100 + (i as u64) * 8;
        let res = shaper.submit(
            Packet {
                id: (i + 1) as u64,
                bytes: payload_len,
                count_exempt: (i % 16) == 0,
            },
            tick,
        );
        mix(res.action as u64);
        if (i % 32) == 31 {
            let polled = shaper.poll(tick + 1200);
            mix(polled.len() as u64);
        }

        let qid = ((r >> 16) & 0xffff) as u16;
        let octet = (1 + (r % 250)) as u8;
        let ttl = (60 + (r % 3600)) as u32;
        build_dns_packet_into(&mut dns_pkt, qid, octet, ttl);
        let reply = parse_reply(
            &dns_pkt,
            &Question {
                id: qid,
                name: "CWPT.SZU.EDU.CN.",
                qtype: TYPE_A,
            },
        )
        .unwrap();
        if let Some(addr) = reply.addresses.first() {
            mix(addr.bytes[3] as u64);
            mix(addr.ttl as u64);
        }

        let dst_last = if (i & 1) != 0 { 166 } else { octet };
        let ipv4_pkt: [u8; 20] = [
            0x45, 0x00, 0x00, 20, 0x00, 0x00, 0x00, 0x00, 64, 6, 0x00, 0x00, 1, 1, 105, 34, 192,
            168, 240, dst_last,
        ];
        let decision: PacketDecision = ctrl_effects.classify(&ipv4_pkt);
        mix(decision as u64);

        let ip_str = format!("192.168.240.{octet}");
        if let Some(parsed_ip) = parse_ipv4(&ip_str) {
            mix(u64::from(rejected_for_assignment(&parsed_ip)));
        }
    }

    100.0 + ((digest % 900_000_000) as f64) / 1_000_000.0
}

/// Runs the pre-allocated zero-allocation SoA/workspace (`soa_simd`) tunnel kernel.
#[must_use]
pub fn run_seed_soa(seed: u64, iterations: usize) -> f64 {
    let mut rng = SplitMix64::new(seed);
    let mut digest: u64 = 0xcbf2_9ce4_8422_2325;
    let mut mix = |v: u64| {
        digest ^= v;
        digest = digest.wrapping_mul(0x0100_0000_01b3);
    };

    let mut decoder = StreamDecoder::new();
    let mut shaper = WindowQueue::new(65_536, 100, 512, 4 * 1024 * 1024).unwrap();
    let mut ctrl_effects = Effects::new();
    let ctrl_opts = vec![
        vec!["ctrl", "domain:cwpt.szu.edu.cn sourceIp:192.168.240.166;172.31.7.46"],
        vec!["ctrl", "domain:ehall.szu.edu.cn sourceIp:192.168.240.10&210.39.3.155"],
    ];
    ctrl_effects.replace(&ctrl_opts).unwrap();

    let mut frame = [0u8; 130];
    let mut wire = Vec::with_capacity(140);
    let mut out1 = Vec::with_capacity(140);
    let mut out2 = Vec::with_capacity(140);
    let mut polled: Vec<ShaperResult> = Vec::with_capacity(64);
    let mut dns_pkt = [0u8; 49];

    for i in 0..iterations {
        let r = rng.next_u64();
        let payload_len = 32 + (r as usize % 96);
        let frame_len = payload_len + 2;
        frame[0] = ((payload_len >> 8) & 0xff) as u8;
        frame[1] = (payload_len & 0xff) as u8;
        let r_bytes = r.to_le_bytes();
        for j in 0..payload_len {
            frame[2 + j] = r_bytes[j & 7] ^ (j as u8);
        }

        encode_standard_frame_into(&frame[..frame_len], &mut wire).unwrap();
        let split = 1 + (r as usize % (wire.len() - 1));
        decoder.feed_into(&wire[..split], &mut out1).unwrap();
        decoder.feed_into(&wire[split..], &mut out2).unwrap();
        mix((out1.len() + out2.len()) as u64);
        if let (Some(&first), Some(&last)) = (out2.first(), out2.last()) {
            mix(first as u64);
            mix(last as u64);
        }

        let tick = 100 + (i as u64) * 8;
        let res = shaper.submit(
            Packet {
                id: (i + 1) as u64,
                bytes: payload_len,
                count_exempt: (i % 16) == 0,
            },
            tick,
        );
        mix(res.action as u64);
        if (i % 32) == 31 {
            shaper.poll_into(tick + 1200, &mut polled);
            mix(polled.len() as u64);
        }

        let qid = ((r >> 16) & 0xffff) as u16;
        let octet = (1 + (r % 250)) as u8;
        let ttl = (60 + (r % 3600)) as u32;
        build_dns_packet_into(&mut dns_pkt, qid, octet, ttl);
        let reply = parse_reply(
            &dns_pkt,
            &Question {
                id: qid,
                name: "cwpt.szu.edu.cn",
                qtype: TYPE_A,
            },
        )
        .unwrap();
        if let Some(addr) = reply.addresses.first() {
            mix(addr.bytes[3] as u64);
            mix(addr.ttl as u64);
        }

        let dst_last = if (i & 1) != 0 { 166 } else { octet };
        let ipv4_pkt: [u8; 20] = [
            0x45, 0x00, 0x00, 20, 0x00, 0x00, 0x00, 0x00, 64, 6, 0x00, 0x00, 1, 1, 105, 34, 192,
            168, 240, dst_last,
        ];
        let decision = ctrl_effects.classify(&ipv4_pkt);
        mix(decision as u64);

        let ip = ip_math::IpAddress {
            version: 4,
            bytes: [192, 168, 240, octet, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        mix(u64::from(rejected_for_assignment(&ip)));
    }

    100.0 + ((digest % 900_000_000) as f64) / 1_000_000.0
}
