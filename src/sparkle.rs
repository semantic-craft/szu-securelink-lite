//! Sparkle 2.x auto-update state machine, Ed25519 signature & version validators,
//! and strict human-readable numeric formatters for the GPUI Workbench.

use crate::shortcuts::valid_url;

/// Official Sparkle 2.x appcast feed URL for SZU SecureLink Lite.
pub const DEFAULT_APPCAST_URL: &str = "https://securelink.szu.edu.cn/updates/appcast.xml";

/// Default Ed25519 public key (base64, 32 raw bytes = 44 base64 chars) embedded in `Info.plist` (`SUPublicEDKey`).
pub const DEFAULT_SUPUBLIC_EDKEY: &str = "MCowBQYDK2VwAyEAszuSecureLinkEd25519PubKey01=";

/// Maximum allowed installer package size in bytes (500 MiB).
pub const MAX_PACKAGE_BYTES: u64 = 524_288_000;

/// Maximum allowed latency measurement in milliseconds (60 seconds).
pub const MAX_LATENCY_MS: u64 = 60_000;

/// Maximum allowed in-tunnel route count.
pub const MAX_ROUTE_COUNT: usize = 512;

/// Validation error when parsing a Sparkle 2.x configuration or appcast entry at the boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SparkleError {
    /// Appcast or download URL is malformed or not HTTPS/HTTP.
    InvalidUrl,
    /// Ed25519 signature or public key is missing or fails base64 structural checks.
    InvalidEd25519Signature,
    /// Version string is not a valid `major.minor.patch` triplet.
    InvalidVersion,
    /// Package size is 0 or exceeds `MAX_PACKAGE_BYTES`.
    InvalidPackageSize,
}

/// Sparkle 2.x updater configuration bound to macOS `SUFeedURL` and `SUPublicEDKey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparkleConfig {
    /// Appcast XML feed URL (`SUFeedURL`).
    pub feed_url: String,
    /// Base64-encoded Ed25519 public key (`SUPublicEDKey`).
    pub public_ed_key: String,
    /// Whether automatic background update checks are enabled (`SUEnableAutomaticChecks`).
    pub automatic_checks: bool,
    /// Scheduled check interval in hours (bounded `1..=168`).
    pub check_interval_hours: u32,
}

impl Default for SparkleConfig {
    fn default() -> Self {
        Self {
            feed_url: DEFAULT_APPCAST_URL.to_string(),
            public_ed_key: DEFAULT_SUPUBLIC_EDKEY.to_string(),
            automatic_checks: true,
            check_interval_hours: 24,
        }
    }
}

impl SparkleConfig {
    /// Validates a [`SparkleConfig`] at the system boundary (requires `https://` feed URL).
    pub fn validate(&self) -> Result<(), SparkleError> {
        if !self.feed_url.starts_with("https://") || !valid_url(&self.feed_url) {
            return Err(SparkleError::InvalidUrl);
        }
        if self.public_ed_key.trim().len() < 32
            || self.check_interval_hours == 0
            || self.check_interval_hours > 168
        {
            return Err(SparkleError::InvalidEd25519Signature);
        }
        Ok(())
    }
}

/// Verified Sparkle 2.x `<item>` enclosure parsed from the signed `appcast.xml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparkleAppcastItem {
    /// Semantic version string (`sparkle:shortVersionString`, e.g. `"0.3.0"`).
    pub version: String,
    /// Monotonic build number (`sparkle:version`, e.g. `300`).
    pub build_number: u64,
    /// Download URL for the `.dmg` or `.tar.xz` delta archive.
    pub download_url: String,
    /// Base64-encoded 64-byte Ed25519 signature (`sparkle:edSignature`).
    pub ed_signature: String,
    /// Archive size in bytes (`length`), strictly within `1..=524_288_000`.
    pub length_bytes: u64,
    /// Concise release summary in Simplified Chinese.
    pub release_notes_zh: String,
    /// Concise release summary in English.
    pub release_notes_en: String,
}

impl SparkleAppcastItem {
    /// Validates all boundary fields of a [`SparkleAppcastItem`] (requires `https://` download URL).
    pub fn validate(&self) -> Result<(), SparkleError> {
        if parse_semver(&self.version).is_none() || self.build_number == 0 {
            return Err(SparkleError::InvalidVersion);
        }
        if !self.download_url.starts_with("https://") || !valid_url(&self.download_url) {
            return Err(SparkleError::InvalidUrl);
        }
        if !validate_ed25519_signature(&self.ed_signature) {
            return Err(SparkleError::InvalidEd25519Signature);
        }
        if format_package_size_mb(self.length_bytes).is_none() {
            return Err(SparkleError::InvalidPackageSize);
        }
        Ok(())
    }
}

/// Lifecycle state of the Sparkle 2.x updater displayed in the About sheet and menu bar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SparkleUpdateState {
    /// Updater is idle prior to any check.
    Idle,
    /// Fetching and verifying `appcast.xml`.
    Checking,
    /// Local version matches or exceeds the latest signed release.
    UpToDate {
        /// Current installed semantic version.
        version: String,
    },
    /// A newer signed release is verified and ready to install.
    UpdateAvailable(SparkleAppcastItem),
    /// Last check failed with a human-readable reason.
    Failed {
        /// Diagnostic reason.
        reason: String,
    },
}

fn parse_semver(ver: &str) -> Option<(u32, u32, u32)> {
    let clean = ver.trim().strip_prefix('v').unwrap_or(ver.trim());
    let mut parts = clean.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    let patch = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// Validates a base64-encoded Ed25519 signature (64 raw bytes = 88 base64 chars ending with `"=="`).
#[must_use]
pub fn validate_ed25519_signature(sig: &str) -> bool {
    let s = sig.trim();
    if s.len() != 88 || !s.ends_with("==") {
        return false;
    }
    s[..86]
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// Returns `true` if `candidate` is strictly newer than `current` under `major.minor.patch` ordering.
#[must_use]
pub fn is_newer_version(current: &str, candidate: &str) -> bool {
    let (Some(cur), Some(cand)) = (parse_semver(current), parse_semver(candidate)) else {
        return false;
    };
    cand > cur
}

/// Formats a package size in bytes (`1..=524_288_000`) into `"14.2 MB"`.
#[must_use]
pub fn format_package_size_mb(bytes: u64) -> Option<String> {
    if bytes == 0 || bytes > MAX_PACKAGE_BYTES {
        return None;
    }
    let tenths = ((u128::from(bytes) * 10) + 524_288) / 1_048_576;
    let tenths = tenths.max(1);
    Some(format!("{}.{} MB", tenths / 10, tenths % 10))
}

/// Formats a round-trip latency in milliseconds (`1..=60_000`) into `"18 ms"`.
#[must_use]
pub fn format_latency_ms(ms: u64) -> Option<String> {
    if ms == 0 || ms > MAX_LATENCY_MS {
        return None;
    }
    Some(format!("{ms} ms"))
}

/// Formats a session duration in seconds into human-readable Chinese or English units.
#[must_use]
pub fn format_duration_human(seconds: u64, english: bool) -> String {
    let total_minutes = (seconds / 60).max(1);
    let hours = total_minutes / 60;
    let minutes = total_minutes % 60;
    if hours == 0 {
        if english {
            format!("{minutes} min")
        } else {
            format!("{minutes} 分钟")
        }
    } else if minutes == 0 {
        if english {
            format!("{hours} hr")
        } else {
            format!("{hours} 小时")
        }
    } else if english {
        format!("{hours} hr {minutes} min")
    } else {
        format!("{hours} 小时 {minutes} 分钟")
    }
}

/// Formats an active route count (`1..=512`) into `"129 条校内路由"` or `"129 campus routes"`.
#[must_use]
pub fn format_route_count(count: usize, english: bool) -> Option<String> {
    if count == 0 || count > MAX_ROUTE_COUNT {
        return None;
    }
    if english {
        Some(format!("{count} campus routes"))
    } else {
        Some(format!("{count} 条校内路由"))
    }
}
