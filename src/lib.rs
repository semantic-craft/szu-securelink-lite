//! `szu-securelink-rs`: 100% Safe Rust (`#![forbid(unsafe_code)]`) domain core for
//! SZU SecureLink, covering confusion stream framing, TUN window traffic shaping,
//! RFC 1035 DNS wire parsing, control-channel policy classification, IP math,
//! campus SSO & academic library shortcuts, AI agent control socket orchestration,
//! and the native macOS AppKit host state machine (`crates/host-macos`).

#![forbid(unsafe_code)]

pub mod agent_control;
pub mod async_util;
pub mod confusion;
pub mod ctrl;
pub mod dns;
pub mod gpui_window;
pub mod gpui_workbench;
pub mod host_api;
pub mod ip_math;
pub mod shaper;
pub mod shortcuts;
pub mod sparkle;
pub mod tray_bridge;
pub mod tunnel_actor;
pub mod version_page;
#[cfg(test)]
mod tests;
