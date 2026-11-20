//! macOS Dock & Menu Bar presence domain model, Login Item (`SMAppService`), and in-process `tray-icon` controller (`#![forbid(unsafe_code)]`).
//!
//! Models system shell visibility with [`ShellPresence`] so the illegal `(false, false)` state
//! (both Dock and Menu Bar icons hidden, leaving an unreachable background process) is
//! unrepresentable in the type system.

#![forbid(unsafe_code)]

use crate::async_util::Sender;
use crate::gpui_workbench::{ConnectionStatus, UiLocale, UiScheme, WorkbenchViewModel};
use crate::tunnel_actor::SessionEvent;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::{env, fs};
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

const LEGACY_LAUNCH_AGENT_LABEL: &str = "local.szu.securelink.login";

/// Validated macOS shell visibility states for `荔连.app` (at least one entry point is always visible).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShellPresence {
    /// Both the macOS Dock icon and the top-right Menu Bar status icon are visible.
    #[default]
    DockAndMenuBar,
    /// Only the top-right Menu Bar icon is visible (`ActivationPolicy::Accessory`).
    MenuBarOnly,
    /// Only the macOS Dock icon is visible (`ActivationPolicy::Regular`).
    DockOnly,
}

impl ShellPresence {
    /// Returns whether the macOS Dock icon is visible in this state.
    #[must_use]
    pub const fn shows_dock(self) -> bool {
        matches!(self, Self::DockAndMenuBar | Self::DockOnly)
    }

    /// Returns whether the top-right macOS Menu Bar status icon is visible in this state.
    #[must_use]
    pub const fn shows_menu_bar(self) -> bool {
        matches!(self, Self::DockAndMenuBar | Self::MenuBarOnly)
    }

    /// Toggles the macOS Dock icon while preserving at least one visible shell entry point.
    #[must_use]
    pub const fn toggle_dock(self) -> Self {
        match self {
            Self::DockAndMenuBar | Self::DockOnly => Self::MenuBarOnly,
            Self::MenuBarOnly => Self::DockAndMenuBar,
        }
    }

    /// Toggles the macOS Menu Bar icon while preserving at least one visible shell entry point.
    #[must_use]
    pub const fn toggle_menu_bar(self) -> Self {
        match self {
            Self::DockAndMenuBar | Self::MenuBarOnly => Self::DockOnly,
            Self::DockOnly => Self::DockAndMenuBar,
        }
    }

    /// Parses a persisted configuration token into [`ShellPresence`].
    #[must_use]
    pub fn from_token(raw: &str) -> Self {
        match raw.trim() {
            "menubar_only" => Self::MenuBarOnly,
            "dock_only" => Self::DockOnly,
            _ => Self::DockAndMenuBar,
        }
    }

    /// Serializes [`ShellPresence`] into a stable configuration token.
    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::DockAndMenuBar => "dock_and_menubar",
            Self::MenuBarOnly => "menubar_only",
            Self::DockOnly => "dock_only",
        }
    }

    fn config_path() -> Option<PathBuf> {
        Some(PathBuf::from(env::var_os("HOME")?).join("Library/Application Support/szu-securelink/shell-presence.txt"))
    }

    /// Loads the user's persisted [`ShellPresence`] from `~/Library/Application Support/szu-securelink/shell-presence.txt`.
    #[must_use]
    pub fn load_persisted() -> Self {
        Self::config_path().and_then(|p| fs::read_to_string(p).ok()).map_or(Self::DockAndMenuBar, |s| Self::from_token(&s))
    }

    /// Persists [`ShellPresence`] to `~/Library/Application Support/szu-securelink/shell-presence.txt`.
    pub fn save_persisted(self) {
        if let Some(path) = Self::config_path() {
            if let Some(parent) = path.parent() { let _ = fs::create_dir_all(parent); }
            let _ = fs::write(path, format!("{}\n", self.as_token()));
        }
    }
}

/// Persisted low-frequency user preferences managed in the Settings view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppPreferences {
    pub shell_presence: ShellPresence,
    pub launch_at_login: bool,
    pub auto_check_updates: bool,
    pub locale: UiLocale,
    pub scheme: UiScheme,
}

impl Default for AppPreferences {
    fn default() -> Self {
        Self { shell_presence: ShellPresence::DockAndMenuBar, launch_at_login: false, auto_check_updates: true, locale: UiLocale::ZhCn, scheme: UiScheme::CrimsonSplit }
    }
}

impl AppPreferences {
    fn prefs_path() -> Option<PathBuf> {
        Some(PathBuf::from(env::var_os("HOME")?).join("Library/Application Support/szu-securelink/preferences.txt"))
    }

    /// Parses [`AppPreferences`] from key-value lines (`key=value`).
    #[must_use]
    pub fn parse_lines(raw: &str, default_presence: ShellPresence, login_agent_exists: bool) -> Self {
        let mut prefs = Self { shell_presence: default_presence, launch_at_login: login_agent_exists, ..Self::default() };
        for line in raw.lines() {
            if let Some((k, v)) = line.trim().split_once('=') {
                match k.trim() {
                    "shell_presence" => prefs.shell_presence = ShellPresence::from_token(v),
                    "auto_check_updates" => prefs.auto_check_updates = v.trim() != "false",
                    "locale" => prefs.locale = if v.trim() == "en-US" { UiLocale::EnUs } else { UiLocale::ZhCn },
                    "scheme" => prefs.scheme = match v.trim() {
                        "bamboo" => UiScheme::BambooColumn,
                        "indigo" => UiScheme::IndigoTrayFirst,
                        _ => UiScheme::CrimsonSplit,
                    },
                    _ => {}
                }
            }
        }
        prefs
    }

    /// Serializes [`AppPreferences`] to key-value lines.
    #[must_use]
    pub fn to_lines(self) -> String {
        let locale_str = if self.locale == UiLocale::EnUs { "en-US" } else { "zh-CN" };
        let scheme_str = match self.scheme {
            UiScheme::CrimsonSplit => "crimson",
            UiScheme::BambooColumn => "bamboo",
            UiScheme::IndigoTrayFirst => "indigo",
        };
        format!(
            "shell_presence={}\nlaunch_at_login={}\nauto_check_updates={}\nlocale={locale_str}\nscheme={scheme_str}\n",
            self.shell_presence.as_token(), self.launch_at_login, self.auto_check_updates,
        )
    }

    /// Loads persisted preferences from disk and reconciles `launch_at_login` with macOS Login Items (`SMAppService`).
    #[must_use]
    pub fn load_persisted() -> Self {
        let _ = migrate_legacy_launch_agent_if_present();
        let (fallback, login_exists) = (ShellPresence::load_persisted(), is_launch_at_login_enabled());
        Self::prefs_path().and_then(|p| fs::read_to_string(p).ok()).map_or(
            Self { shell_presence: fallback, launch_at_login: login_exists, ..Self::default() },
            |raw| Self::parse_lines(&raw, fallback, login_exists),
        )
    }

    /// Saves preferences to `preferences.txt` and `shell-presence.txt`.
    pub fn save_persisted(self) {
        self.shell_presence.save_persisted();
        if let Some(path) = Self::prefs_path() {
            if let Some(parent) = path.parent() { let _ = fs::create_dir_all(parent); }
            let _ = fs::write(path, self.to_lines());
        }
    }
}

fn legacy_launch_agent_path() -> Option<PathBuf> {
    Some(PathBuf::from(env::var_os("HOME")?).join(format!("Library/LaunchAgents/{LEGACY_LAUNCH_AGENT_LABEL}.plist")))
}

/// Removes a legacy `LaunchAgent` plist at `path` if present, returning `true` when removed.
pub fn remove_legacy_launch_agent_at(path: &Path) -> bool { path.exists() && fs::remove_file(path).is_ok() }

fn cleanup_legacy_launch_agent() -> bool {
    let Some(path) = legacy_launch_agent_path().filter(|p| p.exists()) else { return false };
    if let Ok(out) = Command::new("/usr/bin/id").arg("-u").output() && out.status.success() {
        let uid = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !uid.is_empty() {
            let target = format!("gui/{uid}/{LEGACY_LAUNCH_AGENT_LABEL}");
            let _ = Command::new("/bin/launchctl").args(["bootout", &target])
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status();
        }
    }
    remove_legacy_launch_agent_at(&path)
}

/// Migrates a legacy `LaunchAgent` plist to macOS Login Items (`SMAppService.mainApp`) if present.
pub fn migrate_legacy_launch_agent_if_present() -> bool { cleanup_legacy_launch_agent() && szu_host_macos::set_launch_at_login(true) }

/// Returns whether macOS Launch at Login (`SMAppService.mainApp`) is currently enabled.
#[must_use]
pub fn is_launch_at_login_enabled() -> bool { szu_host_macos::is_launch_at_login_enabled() }

/// Enables or disables macOS Launch at Login via `SMAppService.mainApp` and removes any legacy `LaunchAgent`.
pub fn set_launch_at_login(enabled: bool) -> bool { let _ = cleanup_legacy_launch_agent(); szu_host_macos::set_launch_at_login(enabled) }

/// User actions emitted by the top-right macOS Menu Bar dropdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayAction {
    ShowWindow,
    OpenSettings,
    CheckUpdates,
    ToggleConnect,
    Repair,
    OpenPin(String),
    ToggleDock,
    ToggleMenuBar,
    Quit,
}

impl TrayAction {
    /// Parses a menu item ID or `ACT:...` token into [`TrayAction`].
    #[must_use]
    pub fn parse_line(line: &str) -> Option<Self> {
        let rest = line.trim().strip_prefix("ACT:").unwrap_or_else(|| line.trim());
        match rest {
            "SHOW_WINDOW" => Some(Self::ShowWindow),
            "OPEN_SETTINGS" => Some(Self::OpenSettings),
            "CHECK_UPDATES" => Some(Self::CheckUpdates),
            "TOGGLE_CONNECT" => Some(Self::ToggleConnect),
            "REPAIR" => Some(Self::Repair),
            "TOGGLE_DOCK" => Some(Self::ToggleDock),
            "TOGGLE_MENUBAR" => Some(Self::ToggleMenuBar),
            "QUIT" => Some(Self::Quit),
            _ => rest.strip_prefix("PIN:").filter(|id| !id.is_empty() && id.len() <= 64).map(|id| Self::OpenPin(id.to_string())),
        }
    }
}

/// Rasterizes a 36x36 (@2x of 18x18 pt) macOS template RGBA icon matching the peeking-lychee silhouette.
#[must_use]
pub fn build_lychee_template_icon(connected: bool) -> Icon {
    let (w, h) = (36u32, 36u32);
    let mut rgba = vec![0u8; (w * h * 4) as usize];
    for y in 0..h as i32 {
        for x in 0..w as i32 {
            let (fx, fy) = (x as f32 + 0.5, y as f32 + 0.5);
            let (dx, dy) = ((fx - 18.0) / 11.5, (fy - 17.5) / 8.8);
            let dome = dx * dx + dy * dy;
            let ear_l = ((fx - 9.8).powi(2) + (fy - 11.2).powi(2)).sqrt();
            let ear_r = ((fx - 26.2).powi(2) + (fy - 11.2).powi(2)).sqrt();
            let inside_head = (fy <= 24.5 && dome <= 1.0) || ear_l <= 3.6 || ear_r <= 3.6;
            let eye_l = ((fx - 14.0).powi(2) + (fy - 18.5).powi(2)).sqrt();
            let eye_r = ((fx - 22.0).powi(2) + (fy - 18.5).powi(2)).sqrt();
            let head_hit = if connected {
                inside_head && eye_l > 2.2 && eye_r > 2.2
            } else {
                let on_border = inside_head
                    && ((22.2..=24.5).contains(&fy)
                        || (dome >= 0.72 && fy <= 24.5)
                        || ((2.1..=3.6).contains(&ear_l) && dome > 0.78)
                        || ((2.1..=3.6).contains(&ear_r) && dome > 0.78));
                on_border || eye_l <= 2.1 || eye_r <= 2.1
            };
            let wave_y = 28.5 + 1.4 * ((fx - 6.0) * 0.35).sin();
            if head_hit || ((5.0..=31.0).contains(&fx) && (fy - wave_y).abs() <= 1.25) {
                rgba[((y as u32 * w + x as u32) * 4 + 3) as usize] = 255;
            }
        }
    }
    Icon::from_rgba(rgba, w, h).expect("valid 36x36 RGBA icon")
}

/// In-process macOS `NSStatusItem` controller bound to the main AppKit thread.
#[derive(Clone, Default)]
pub struct MenuBarBridge {
    tray: Rc<RefCell<Option<TrayIcon>>>,
}

impl MenuBarBridge {
    /// Creates the macOS `NSStatusItem` on the main thread and forwards menu clicks into `evt_tx`.
    #[must_use]
    pub fn spawn(evt_tx: Sender<SessionEvent>, initial_vm: &WorkbenchViewModel) -> Self {
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            if let Some(action) = TrayAction::parse_line(event.id.as_ref()) {
                let _ = evt_tx.try_send(SessionEvent::TrayAction(action));
            }
        }));
        let connected = matches!(initial_vm.status, ConnectionStatus::Connected { .. });
        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(build_tray_menu(initial_vm)))
            .with_tooltip("荔连 · SZU SecureLink")
            .with_icon_templated(build_lychee_template_icon(connected))
            .build()
            .ok();
        if let Some(ref t) = tray {
            let _ = t.set_visible(initial_vm.shell_presence.shows_menu_bar());
        }
        Self { tray: Rc::new(RefCell::new(tray)) }
    }

    /// Updates the macOS Menu Bar icon, visibility, and dropdown menu items from `vm`.
    pub fn sync_from_vm(&self, vm: &WorkbenchViewModel) {
        if let Some(tray) = self.tray.borrow().as_ref() {
            let connected = matches!(vm.status, ConnectionStatus::Connected { .. });
            let _ = tray.set_icon_templated(Some(build_lychee_template_icon(connected)));
            let _ = tray.set_visible(vm.shell_presence.shows_menu_bar());
            tray.set_menu(Some(Box::new(build_tray_menu(vm))));
        }
    }

    /// Removes the status item on quit.
    pub fn shutdown(&self) {
        let _ = self.tray.borrow_mut().take();
    }
}

fn build_tray_menu(vm: &WorkbenchViewModel) -> Menu {
    let en = vm.locale == UiLocale::EnUs;
    let (status_title, toggle_title) = match &vm.status {
        ConnectionStatus::Disconnected => (
            if en { "荔连 · Not Connected".to_string() } else { "荔连 · 未连接校园网".to_string() },
            if en { "Connect Campus Network" } else { "立即连接校园网" },
        ),
        ConnectionStatus::Connecting { .. } => (
            if en { "荔连 · Connecting…".to_string() } else { "荔连 · 正在连接中…".to_string() },
            if en { "Cancel Connecting" } else { "取消连接" },
        ),
        ConnectionStatus::Connected { virtual_ipv4, .. } => (
            if en { format!("荔连 · Connected ({virtual_ipv4})") } else { format!("荔连 · 已连接 ({virtual_ipv4})") },
            if en { "Disconnect Campus Network" } else { "断开校园网连接" },
        ),
    };
    let menu = Menu::new();
    let _ = menu.append(&MenuItem::with_id("STATUS", status_title, false, None));
    let _ = menu.append(&MenuItem::with_id("ACT:TOGGLE_CONNECT", toggle_title, true, None));
    let _ = menu.append(&MenuItem::with_id("ACT:REPAIR", if en { "Auto Repair Network" } else { "自动修复网络" }, true, None));
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&MenuItem::with_id("PIN_HDR", if en { "Pinned Campus Services" } else { "常用校内服务直达" }, false, None));
    for (idx, pin) in vm.menu_bar_shortcuts().into_iter().enumerate() {
        let _ = menu.append(&MenuItem::with_id(format!("ACT:PIN:{}", pin.id), format!("{}. {}", idx + 1, pin.name), true, None));
    }
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&MenuItem::with_id("ACT:SHOW_WINDOW", if en { "Open Main Workbench" } else { "打开主工作台窗口" }, true, None));
    let _ = menu.append(&MenuItem::with_id("ACT:OPEN_SETTINGS", if en { "Settings…" } else { "偏好设置…" }, true, None));
    let _ = menu.append(&MenuItem::with_id("ACT:CHECK_UPDATES", if en { "Check for Updates…" } else { "检查更新…" }, true, None));
    let _ = menu.append(&CheckMenuItem::with_id("ACT:TOGGLE_DOCK", if en { "Show Dock Icon" } else { "显示 Dock 栏图标" }, true, vm.shell_presence.shows_dock(), None));
    let _ = menu.append(&CheckMenuItem::with_id("ACT:TOGGLE_MENUBAR", if en { "Show Menu Bar Icon" } else { "显示菜单栏图标" }, true, vm.shell_presence.shows_menu_bar(), None));
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&MenuItem::with_id("ACT:QUIT", if en { "Quit 荔连" } else { "退出 荔连" }, true, None));
    menu
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_presence_and_preferences_roundtrip() {
        for start in [ShellPresence::DockAndMenuBar, ShellPresence::MenuBarOnly, ShellPresence::DockOnly] {
            assert!(start.shows_dock() || start.shows_menu_bar());
            assert!(start.toggle_dock().shows_dock() || start.toggle_dock().shows_menu_bar());
            assert!(start.toggle_menu_bar().shows_dock() || start.toggle_menu_bar().shows_menu_bar());
            assert_eq!(ShellPresence::from_token(start.as_token()), start);
        }
        let prefs = AppPreferences { shell_presence: ShellPresence::MenuBarOnly, launch_at_login: true, auto_check_updates: false, locale: UiLocale::EnUs, scheme: UiScheme::BambooColumn };
        assert_eq!(AppPreferences::parse_lines(&prefs.to_lines(), ShellPresence::DockAndMenuBar, true), prefs);
        for action in ["ACT:SHOW_WINDOW", "ACT:OPEN_SETTINGS", "ACT:CHECK_UPDATES", "ACT:TOGGLE_CONNECT", "ACT:REPAIR", "ACT:TOGGLE_DOCK", "ACT:TOGGLE_MENUBAR", "ACT:QUIT", "ACT:PIN:szu-ehall"] {
            assert!(TrayAction::parse_line(action).is_some());
        }
        assert!(TrayAction::parse_line("INVALID").is_none());
    }

    #[test]
    fn remove_legacy_launch_agent_at_is_idempotent() {
        let dir = env::temp_dir().join(format!("szu-legacy-la-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let plist = dir.join(format!("{LEGACY_LAUNCH_AGENT_LABEL}.plist"));
        fs::write(&plist, "<plist/>").unwrap();
        assert!(remove_legacy_launch_agent_at(&plist));
        assert!(!plist.exists());
        assert!(!remove_legacy_launch_agent_at(&plist));
        let _ = fs::remove_dir_all(&dir);
    }
}
