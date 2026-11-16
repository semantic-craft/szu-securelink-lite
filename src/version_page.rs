//! Version & GitHub Releases update-check domain logic and Settings Version page snapshot (`#![forbid(unsafe_code)]`).

#![forbid(unsafe_code)]

use crate::async_util::Sender;
use crate::gpui_workbench::{APP_VERSION, WorkbenchViewModel};
use crate::shortcuts::valid_url;
use crate::sparkle::{MAX_PACKAGE_BYTES, SparkleUpdateState, format_package_size_mb, is_newer_version, parse_semver};
use crate::tunnel_actor::SessionEvent;
use serde_json::{Value, json};
use std::process::Command;
use std::thread;

/// GitHub repository slug (`owner/repo`) hosting public releases.
pub const GITHUB_REPO_SLUG: &str = "semantic-craft/szu-securelink-lite";
/// Public GitHub Releases page URL opened in the user's browser.
pub const GITHUB_RELEASES_PAGE_URL: &str = "https://github.com/semantic-craft/szu-securelink-lite/releases";
/// GitHub REST API endpoint for the latest published release.
pub const GITHUB_LATEST_API_URL: &str = "https://api.github.com/repos/semantic-craft/szu-securelink-lite/releases/latest";
/// Strict URL prefix enforced on parsed GitHub release and asset download URLs.
pub const ALLOWED_GITHUB_URL_PREFIX: &str = "https://github.com/semantic-craft/szu-securelink-lite/";
/// Monotonic bundle build number displayed alongside [`APP_VERSION`].
pub const APP_BUILD_NUMBER: &str = "4";
/// Supported target architecture label shown on the Version & Updates page.
pub const APP_ARCH_LABEL: &str = "macOS arm64 (Apple Silicon)";
/// Short Apple Developer ID signing team label shown on the Version & Updates page.
pub const SIGNING_IDENTITY_SHORT: &str = "Apple Developer ID";

/// Active sub-tab inside the Settings view (`General` vs `Version & Updates`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SettingsTab {
    #[default]
    General,
    Version,
}

impl SettingsTab {
    /// Serializes [`SettingsTab`] into its stable JSON contract token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self { Self::General => "general", Self::Version => "version" }
    }

    /// Parses a JSON or UI token into [`SettingsTab`], defaulting to [`SettingsTab::General`].
    #[must_use]
    pub fn from_token(raw: &str) -> Self {
        if raw.trim().eq_ignore_ascii_case("version") { Self::Version } else { Self::General }
    }
}

/// Validated metadata for a published release fetched from GitHub Releases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteReleaseInfo {
    pub version: String,
    pub tag_name: String,
    pub title: String,
    pub published_date: String,
    pub html_url: String,
    pub download_url: String,
    pub asset_size_bytes: Option<u64>,
    pub notes: String,
}

/// Outcome of a GitHub Releases latest-version check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateCheckResult {
    UpToDate { version: String, checked_at_hm: String, remote: Option<RemoteReleaseInfo> },
    UpdateAvailable { checked_at_hm: String, remote: RemoteReleaseInfo },
    Failed { checked_at_hm: String, reason_zh: String, reason_en: String },
}

/// State persisted in [`WorkbenchViewModel`] for the `Settings -> Version & Updates` page.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VersionPageState {
    pub tab: SettingsTab,
    pub last_checked_hm: Option<String>,
    pub latest_remote: Option<RemoteReleaseInfo>,
    pub last_error_zh: Option<String>,
    pub last_error_en: Option<String>,
}

impl VersionPageState {
    /// Returns the validated package download URL when a newer release exists, else [`GITHUB_RELEASES_PAGE_URL`].
    #[must_use]
    pub fn download_url_or_releases(&self) -> &str {
        self.latest_remote.as_ref().filter(|r| is_newer_version(APP_VERSION, &r.version)).map_or(GITHUB_RELEASES_PAGE_URL, |r| r.download_url.as_str())
    }
}

fn fail(checked_at_hm: &str, zh: &str, en: &str) -> UpdateCheckResult {
    UpdateCheckResult::Failed { checked_at_hm: checked_at_hm.to_string(), reason_zh: zh.to_string(), reason_en: en.to_string() }
}

/// Parses and validates a GitHub `/releases/latest` JSON payload against `current_version`.
#[must_use]
pub fn parse_github_latest_release(raw_json: &[u8], current_version: &str, checked_at_hm: &str) -> UpdateCheckResult {
    let Ok(Value::Object(obj)) = serde_json::from_slice::<Value>(raw_json) else {
        return fail(checked_at_hm, "更新响应格式无效，无法解析版本信息", "Invalid release response JSON");
    };
    if obj.get("draft").and_then(Value::as_bool) == Some(true) || obj.get("prerelease").and_then(Value::as_bool) == Some(true) {
        return UpdateCheckResult::UpToDate { version: current_version.to_string(), checked_at_hm: checked_at_hm.to_string(), remote: None };
    }
    let Some(tag_name) = obj.get("tag_name").and_then(Value::as_str).map(str::trim) else {
        return fail(checked_at_hm, "发布元数据缺少有效版本号标签", "Release metadata missing tag_name");
    };
    let version = tag_name.strip_prefix('v').unwrap_or(tag_name);
    if !version.bytes().all(|b| b.is_ascii_digit() || b == b'.') || parse_semver(version).is_none() {
        return fail(checked_at_hm, "远端版本号格式不受支持", "Unsupported remote semantic version");
    }
    let Some(html_url) = obj.get("html_url").and_then(Value::as_str).map(str::trim).filter(|u| u.starts_with(ALLOWED_GITHUB_URL_PREFIX) && valid_url(u)) else {
        return fail(checked_at_hm, "发布页链接未通过安全来源校验", "Release URL failed origin check");
    };
    let (mut download_url, mut asset_size_bytes) = (html_url.to_string(), None);
    if let Some(assets) = obj.get("assets").and_then(Value::as_array) {
        for asset in assets {
            let name = asset.get("name").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase();
            let Some(dl) = asset.get("browser_download_url").and_then(Value::as_str).map(str::trim) else { continue };
            let dl_lower = dl.to_ascii_lowercase();
            let is_pkg = name.ends_with(".zip") || name.ends_with(".dmg") || dl_lower.ends_with(".zip") || dl_lower.ends_with(".dmg");
            if is_pkg && dl.starts_with(ALLOWED_GITHUB_URL_PREFIX) && valid_url(dl) {
                download_url = dl.to_string();
                asset_size_bytes = asset.get("size").and_then(Value::as_u64).filter(|&s| (1..=MAX_PACKAGE_BYTES).contains(&s));
                break;
            }
        }
    }
    let title = obj.get("name").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).unwrap_or(tag_name).chars().take(120).collect();
    let published_date: String = obj.get("published_at").and_then(Value::as_str).map(|s| s.trim().chars().take(10).collect()).unwrap_or_default();
    let notes: String = obj.get("body").and_then(Value::as_str).unwrap_or("").replace('\r', "").trim().chars().take(1600).collect();
    let remote = RemoteReleaseInfo {
        version: version.to_string(), tag_name: tag_name.to_string(), title, published_date,
        html_url: html_url.to_string(), download_url, asset_size_bytes, notes,
    };
    if is_newer_version(current_version, &remote.version) {
        UpdateCheckResult::UpdateAvailable { checked_at_hm: checked_at_hm.to_string(), remote }
    } else {
        UpdateCheckResult::UpToDate { version: current_version.to_string(), checked_at_hm: checked_at_hm.to_string(), remote: Some(remote) }
    }
}

fn current_hm() -> String {
    Command::new("/bin/date").arg("+%H:%M").output().ok().filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| "--:--".to_string())
}

/// Spawns a background thread querying GitHub Releases via `/usr/bin/curl` and posts [`SessionEvent::UpdateCheckFinished`].
pub fn spawn_github_update_check(evt_tx: Sender<SessionEvent>) {
    thread::spawn(move || {
        let ua = format!("User-Agent: szu-securelink/{APP_VERSION}");
        let output = Command::new("/usr/bin/curl")
            .args(["-fsSL", "--max-time", "8", "--max-filesize", "262144", "-H", "Accept: application/vnd.github+json", "-H", &ua, GITHUB_LATEST_API_URL])
            .output();
        let checked_at = current_hm();
        let result = match output {
            Ok(out) if out.status.success() => parse_github_latest_release(&out.stdout, APP_VERSION, &checked_at),
            Ok(out) => match out.status.code() {
                Some(6 | 7 | 28) => fail(&checked_at, "网络不可达或连接 GitHub 超时，请稍后重试", "Network unreachable or GitHub request timed out"),
                Some(22) => fail(&checked_at, "GitHub Releases 返回 HTTP 错误或触发频率限制", "GitHub Releases returned an HTTP error or rate limit"),
                Some(code) => fail(&checked_at, &format!("检查更新失败（curl 退出码 {code}）"), &format!("Update check failed (curl exit {code})")),
                None => fail(&checked_at, "检查更新请求被中断", "Update check request terminated"),
            },
            Err(_) => fail(&checked_at, "无法启动系统 curl 检查更新", "Failed to invoke system curl for update check"),
        };
        let _ = evt_tx.try_send(SessionEvent::UpdateCheckFinished(result));
    });
}

fn newer_remote(vp: &VersionPageState) -> Option<&RemoteReleaseInfo> {
    vp.latest_remote.as_ref().filter(|r| is_newer_version(APP_VERSION, &r.version))
}

/// Formats the single-line summary string displayed in General Settings and `vm.update_status`.
#[must_use]
pub fn format_update_status_line(sparkle_state: &SparkleUpdateState, vp: &VersionPageState, en: bool) -> String {
    if matches!(sparkle_state, SparkleUpdateState::Checking) {
        return if en { "Checking GitHub Releases…" } else { "正在检查 GitHub Releases 更新…" }.to_string();
    }
    if let SparkleUpdateState::UpdateAvailable(item) = sparkle_state {
        let sz = format_package_size_mb(item.length_bytes).map(|s| format!(" ({s})")).unwrap_or_default();
        return if en { format!("Update available: v{}{sz}", item.version) } else { format!("发现新版本 v{}{sz}", item.version) };
    }
    if let Some(remote) = newer_remote(vp) {
        let sz = remote.asset_size_bytes.and_then(format_package_size_mb).map(|s| format!(" ({s})")).unwrap_or_default();
        return if en { format!("Update available: v{}{sz}", remote.version) } else { format!("发现新版本 v{}{sz}", remote.version) };
    }
    if let (Some(rz), Some(re)) = (&vp.last_error_zh, &vp.last_error_en) {
        return if en { re } else { rz }.clone();
    }
    if let SparkleUpdateState::Failed { reason } = sparkle_state {
        return reason.clone();
    }
    if en { format!("Up to date (v{APP_VERSION})") } else { format!("当前已是最新版本（v{APP_VERSION}）") }
}

fn builtin_changelog(en: bool) -> Vec<Value> {
    let entries = [
        ("0.2.3", "v0.2.3", "2026-11-16",
         if en { "Settings Version Page & Live Update Check" } else { "偏好设置版本页与实时检查更新" },
         if en { "Added Version & Updates tab in Preferences with asynchronous GitHub Releases checks, decoupled headless worker startup I/O, and removed legacy dead code." }
         else { "偏好设置新增「版本与更新」分页与 GitHub Releases 异步版本检查，拆分 Swift 控制面状态域并解耦无头子进程启动开销，清理历史死代码。" }),
        ("0.2.2", "v0.2.2", "2026-11-09",
         if en { "Native AppKit Workbench & Menu Bar" } else { "原生 AppKit 桌面工作台与菜单栏" },
         if en { "Pure Safe Rust core with native AppKit UI, Dock/Menu Bar shell presence, ? info-tip popovers, and instant utun adoption." }
         else { "采用 Pure Safe Rust 内核与原生 AppKit 液态玻璃界面，支持 Dock/菜单栏常驻模式、? 气泡说明与 utun 秒级接管。" }),
        ("0.2.1", "v0.2.1", "2026-11-08",
         if en { "AI Agent Control Plane & Quick Pins" } else { "本机 AI 控制面与菜单栏快捷槽位" },
         if en { "Added Unix domain socket CLI control plane (status/ensure/open-sso/repair), 4 customizable menu bar pins, and auto-connect queue." }
         else { "新增单实例 Unix socket 代理控制面（status/ensure/open-sso/repair）、4 个菜单栏常用服务槽位与断线自动连网队列。" }),
        ("0.2.0", "v0.2.0", "2026-11-07",
         if en { "Pure-Rust Core & Privileged Helper" } else { "独立零信任数据面与深大 CAS 接入" },
         if en { "Independent SZU CAS browser authentication, securelink:// callback guard, and atomic 133-route utun setup via helper." }
         else { "脱离官方 Electron 进程树，独立完成深大 CAS 浏览器认证、一次性回跳校验与 133 条校内静态路由原子装载。" }),
    ];
    entries.into_iter().map(|(ver, tag, date, title, summary)| {
        let installed = ver == APP_VERSION;
        json!({
            "version": ver, "tag": tag, "date": date, "title": title, "summary": summary,
            "is_installed": installed, "is_remote_new": false,
            "status_badge": if installed { if en { "Current" } else { "当前版本" } } else { "" },
        })
    }).collect()
}

/// Builds the JSON snapshot consumed by `VersionPageView.h` for `Settings -> Version & Updates`.
#[must_use]
pub fn build_version_page_snapshot(vm: &WorkbenchViewModel, en: bool) -> Value {
    let vp = &vm.version_page;
    let is_checking = matches!(vm.sparkle_state, SparkleUpdateState::Checking);
    let sparkle_item = match &vm.sparkle_state { SparkleUpdateState::UpdateAvailable(i) => Some(i), _ => None };
    let remote_new = newer_remote(vp);
    let has_update = !is_checking && (sparkle_item.is_some() || remote_new.is_some());
    let has_error = !is_checking && !has_update && (vp.last_error_zh.is_some() || matches!(vm.sparkle_state, SparkleUpdateState::Failed { .. }));
    let state = if is_checking { "checking" } else if has_update { "update_available" } else if has_error { "failed" } else { "up_to_date" };
    let hm = vp.last_checked_hm.as_deref().unwrap_or("--:--");

    let (status_headline, status_detail, download_url) = if is_checking {
        (
            if en { "Checking GitHub Releases…" } else { "正在检查 GitHub Releases 最新版本…" }.to_string(),
            if en { format!("Querying {GITHUB_REPO_SLUG} over HTTPS (8s timeout)") } else { format!("正在通过 HTTPS 查询公开仓库 {GITHUB_REPO_SLUG}…") },
            vp.download_url_or_releases().to_string(),
        )
    } else if let Some(remote) = remote_new {
        let sz = remote.asset_size_bytes.and_then(format_package_size_mb).map(|s| format!(" ({s})")).unwrap_or_default();
        (
            if en { format!("New version available: v{}{sz}", remote.version) } else { format!("发现新版本 v{}{sz}", remote.version) },
            if en { format!("Published {} · Checked {hm} · Installed v{APP_VERSION}", remote.published_date) }
            else { format!("发布于 {} · 检查于 {hm} · 当前已安装 v{APP_VERSION}", remote.published_date) },
            remote.download_url.clone(),
        )
    } else if let Some(item) = sparkle_item {
        let sz = format_package_size_mb(item.length_bytes).map(|s| format!(" ({s})")).unwrap_or_default();
        (
            if en { format!("New version available: v{}{sz}", item.version) } else { format!("发现新版本 v{}{sz}", item.version) },
            if en { format!("Verified Sparkle appcast · Installed v{APP_VERSION}") } else { format!("已通过 Sparkle 签名校验 · 当前已安装 v{APP_VERSION}") },
            item.download_url.clone(),
        )
    } else if has_error {
        let reason = format_update_status_line(&vm.sparkle_state, vp, en);
        let detail = if vp.last_checked_hm.is_some() { if en { format!("{reason} · Checked {hm}") } else { format!("{reason} · 尝试于 {hm}") } } else { reason };
        (if en { "Update check failed" } else { "检查更新失败" }.to_string(), detail, GITHUB_RELEASES_PAGE_URL.to_string())
    } else {
        let detail = if vp.last_checked_hm.is_some() {
            if en { format!("Last checked {hm} · Source: GitHub Releases") } else { format!("上次检查 {hm} · 更新源 GitHub Releases") }
        } else if vm.sparkle_config.automatic_checks {
            if en { "Auto-check runs after launch · Source: GitHub Releases" } else { "已启用启动后自动检查 · 更新源 GitHub Releases" }.to_string()
        } else {
            if en { "Auto-check disabled · Click Check for Updates anytime" } else { "自动检查已关闭 · 可随时点击右侧按钮手动检查" }.to_string()
        };
        (if en { format!("荔连 is up to date (v{APP_VERSION})") } else { format!("当前已是最新版本（v{APP_VERSION}）") }, detail, GITHUB_RELEASES_PAGE_URL.to_string())
    };

    let mut changelog = Vec::new();
    if let Some(remote) = remote_new {
        changelog.push(json!({
            "version": remote.version, "tag": remote.tag_name, "date": remote.published_date, "title": remote.title,
            "summary": if remote.notes.is_empty() { remote.html_url.clone() } else { remote.notes.clone() },
            "is_installed": false, "is_remote_new": true, "status_badge": if en { "New" } else { "新版本" },
        }));
    }
    changelog.extend(builtin_changelog(en));

    json!({
        "app_name": if en { "SZU SecureLink · 荔连" } else { "荔连 · SZU SecureLink" },
        "version": APP_VERSION, "build": APP_BUILD_NUMBER, "arch": APP_ARCH_LABEL,
        "signing_team": SIGNING_IDENTITY_SHORT, "repo_slug": GITHUB_REPO_SLUG, "releases_url": GITHUB_RELEASES_PAGE_URL,
        "info_tip": if en { "Queries public GitHub Releases (semantic-craft/szu-securelink-lite) over HTTPS without sending campus credentials or logs." }
                    else { "通过 HTTPS 查询公开仓库 semantic-craft/szu-securelink-lite 的 GitHub Releases，不上传校园网账号、配置或隧道日志。" },
        "state": state, "is_checking": is_checking, "has_update": has_update,
        "status_headline": status_headline, "status_detail": status_detail,
        "primary_action_title": if is_checking { if en { "Checking…" } else { "正在检查…" } } else if has_update { if en { "Download Update ↗" } else { "下载更新 ↗" } } else { if en { "Check for Updates" } else { "检查更新" } },
        "download_url": download_url, "changelog": changelog,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_github_release_variants_and_version_page_snapshot() {
        assert_eq!(SettingsTab::from_token("version"), SettingsTab::Version);
        assert_eq!(SettingsTab::from_token("general"), SettingsTab::General);
        assert_eq!(SettingsTab::from_token("other"), SettingsTab::General);

        let same = br#"{"tag_name":"v0.2.2","name":"v0.2.2","draft":false,"prerelease":false,"published_at":"2026-11-09T10:00:00Z","html_url":"https://github.com/semantic-craft/szu-securelink-lite/releases/tag/v0.2.2","body":"Release notes","assets":[{"name":"SZU-SecureLink-v0.2.2-macOS-arm64.zip","size":2936012,"browser_download_url":"https://github.com/semantic-craft/szu-securelink-lite/releases/download/v0.2.2/SZU-SecureLink-v0.2.2-macOS-arm64.zip"}]}"#;
        assert!(matches!(parse_github_latest_release(same, "0.2.2", "12:00"), UpdateCheckResult::UpToDate { remote: Some(_), .. }));

        let newer = br#"{"tag_name":"v0.3.0","name":"v0.3.0","draft":false,"prerelease":false,"published_at":"2026-11-20T08:30:00Z","html_url":"https://github.com/semantic-craft/szu-securelink-lite/releases/tag/v0.3.0","body":"Faster startup\r\nNew version page","assets":[{"name":"SZU-SecureLink-v0.3.0-macOS-arm64.zip","size":3145728,"browser_download_url":"https://github.com/semantic-craft/szu-securelink-lite/releases/download/v0.3.0/SZU-SecureLink-v0.3.0-macOS-arm64.zip"}]}"#;
        let UpdateCheckResult::UpdateAvailable { remote, .. } = parse_github_latest_release(newer, "0.2.2", "12:05") else { panic!("expected UpdateAvailable"); };
        assert_eq!(remote.version, "0.3.0");
        assert_eq!(remote.published_date, "2026-11-20");
        assert_eq!(remote.notes, "Faster startup\nNew version page");

        let pre = br#"{"tag_name":"v0.4.0","prerelease":true,"html_url":"https://github.com/semantic-craft/szu-securelink-lite/releases/tag/v0.4.0"}"#;
        assert!(matches!(parse_github_latest_release(pre, "0.2.2", "12:10"), UpdateCheckResult::UpToDate { remote: None, .. }));

        let evil = br#"{"tag_name":"v0.3.0","html_url":"https://evil.example.com/release"}"#;
        assert!(matches!(parse_github_latest_release(evil, "0.2.2", "12:11"), UpdateCheckResult::Failed { .. }));
        assert!(matches!(parse_github_latest_release(b"{bad", "0.2.2", "12:12"), UpdateCheckResult::Failed { .. }));

        let mut vm = WorkbenchViewModel::new();
        let zh = build_version_page_snapshot(&vm, false);
        assert_eq!(zh["state"], "up_to_date");
        assert_eq!(zh["changelog"][0]["is_installed"], true);
        vm.apply_update_check_result(UpdateCheckResult::UpdateAvailable { checked_at_hm: "12:05".to_string(), remote });
        let en = build_version_page_snapshot(&vm, true);
        assert_eq!(en["state"], "update_available");
        assert_eq!(en["has_update"], true);
        assert_eq!(en["changelog"][0]["is_remote_new"], true);
        assert_eq!(en["changelog"][1]["is_installed"], true);
    }
}
