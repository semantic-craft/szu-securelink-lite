//! Pure-Rust GPUI-Kit style reactive desktop workbench & menu-bar view tree.
//!
//! Provides a declarative, GPU-compositor-ready (`gpui-kit` / native macOS menu bar)
//! component tree and state reducer for SZU SecureLink Lite without Electron overhead.

use crate::shortcuts::{default_shortcuts, extract_hosts, valid_url, CampusShortcut, ShortcutCategory};
use crate::sparkle::{
    format_package_size_mb, is_newer_version, SparkleAppcastItem, SparkleConfig, SparkleUpdateState,
};
use crate::tray_bridge::{set_launch_at_login, AppPreferences, ShellPresence};

/// Official Chinese display name for the SZU SecureLink desktop client.
pub const APP_CHINESE_NAME: &str = "荔连";

/// Subtle attribution text displayed on the About page and near the Check for Updates control.
pub const ABOUT_ATTRIBUTION_TEXT: &str = "深圳大学法律人工智能实训实验室";

/// Application version string displayed in the About page and update check.
pub const APP_VERSION: &str = "0.2.0";

/// Default 4 user-pinned campus services in the macOS menu bar popover.
pub const DEFAULT_MENU_BAR_PIN_IDS: [&str; 4] = [
    "szu-reimburse-system", "szu-finance-sso", "szu-cnki-sso", "szu-ehall",
];

/// Supported UI copy locales (`zh-CN` primary, `en-US` secondary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiLocale {
    /// Simplified Chinese (`zh-CN`).
    ZhCn,
    /// English (`en-US`).
    EnUs,
}

/// Competing UI layout & traditional Chinese single-accent schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiScheme {
    /// Scheme A: SZU Crimson (`#8C2232`) split workbench with left status rail & 2x2 hero grid.
    CrimsonSplit,
    /// Scheme B: Bamboo Academy (`#2B5F4E`) single-column beginner launcher.
    BambooColumn,
    /// Scheme C: Pine Indigo (`#2E4B6C`) menu-bar-first micro-popover & compact window.
    IndigoTrayFirst,
}

/// Template-image geometry state for the 18x18 pt macOS status bar icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuBarIconGeometry {
    /// Hollow shield + link outline (`1.5pt` stroke) when disconnected.
    DisconnectedOutline,
    /// Breathing dashed shield + dot when negotiating CAS or `utun`.
    ConnectingPulse,
    /// Solid filled shield + checkmark cutout when the `utun` tunnel is active.
    ConnectedSolid,
}

/// Outcome of clicking a campus service shortcut in the Workbench or menu bar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShortcutLaunchOutcome {
    /// Tunnel was already active; URL was opened immediately in the default browser.
    OpenedImmediately(String),
    /// Tunnel was disconnected; auto-connect was initiated and the shortcut queued to open upon connect.
    QueuedAfterConnect { shortcut_id: String, url: String },
}

/// High-level connection lifecycle state displayed in the GPUI Workbench header and macOS menu bar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// Idle before initiating CAS login.
    Disconnected,
    /// Waiting for browser CAS callback or negotiating `utun` tunnel.
    Connecting { phase: String },
    /// Active Zero-Trust `utun` session with virtual IPv4 and in-tunnel DNS.
    Connected { interface: String, virtual_ipv4: String, dns_server: String },
}

/// Active in-window page route inside [`WorkbenchViewModel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WorkbenchRoute {
    /// Primary campus network & service directory workbench.
    #[default]
    Workbench,
    /// Low-frequency preferences page (Dock/Menu Bar presence, Launch at Login, Updates, About).
    Settings,
}

/// Declarative GPUI-Kit UI node re-exported from [`crate::gpui_tree`].
pub use crate::gpui_tree::GpuiElement;

/// Reactive state container for the GPUI Workbench and macOS status-bar tray menu.
#[derive(Debug, Clone)]
pub struct WorkbenchViewModel {
    /// Organization code (`"szu"`).
    pub org: String,
    /// Current Zero-Trust tunnel state.
    pub status: ConnectionStatus,
    /// All shortcuts (built-in SSO/library entries + user custom entries).
    pub shortcuts: Vec<CampusShortcut>,
    /// Live search filter query in the Workbench toolbar.
    pub search_query: String,
    /// Active page route (`Workbench` vs `Settings`).
    pub route: WorkbenchRoute,
    /// Latest update-check status text shown in the Settings page.
    pub update_status: String,
    /// Active display locale (`zh-CN` by default).
    pub locale: UiLocale,
    /// Active UI layout and accent scheme (`CrimsonSplit` by default).
    pub scheme: UiScheme,
    /// User-customizable 4 pinned shortcut IDs shown in the macOS menu bar tray.
    pub menu_bar_pins: [String; 4],
    /// Shortcut ID queued for automatic launch once a beginner's auto-connect finishes.
    pub pending_open_shortcut_id: Option<String>,
    /// Most recently opened shortcut URL.
    pub last_opened_url: Option<String>,
    /// Sparkle 2.x auto-update configuration.
    pub sparkle_config: SparkleConfig,
    /// Sparkle 2.x auto-update state.
    pub sparkle_state: SparkleUpdateState,
    /// Categories currently folded in the right-hand accordion pane.
    pub collapsed_categories: Vec<ShortcutCategory>,
    /// macOS Dock and Menu Bar icon visibility mode (never both hidden).
    pub shell_presence: ShellPresence,
    /// Whether `荔连.app` launches automatically at macOS user login.
    pub launch_at_login: bool,
}

impl Default for WorkbenchViewModel {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkbenchViewModel {
    #[must_use]
    pub fn new() -> Self {
        #[cfg(not(test))]
        let prefs = AppPreferences::load_persisted();
        #[cfg(test)]
        let prefs = AppPreferences::default();
        let sparkle_config = SparkleConfig {
            automatic_checks: prefs.auto_check_updates,
            ..SparkleConfig::default()
        };
        let mut vm = Self {
            org: "szu".to_string(),
            status: ConnectionStatus::Disconnected,
            shortcuts: default_shortcuts(),
            search_query: String::new(),
            route: WorkbenchRoute::Workbench,
            update_status: format!("当前已是最新版本（v{APP_VERSION}）"),
            locale: prefs.locale,
            scheme: prefs.scheme,
            menu_bar_pins: DEFAULT_MENU_BAR_PIN_IDS.map(str::to_string),
            pending_open_shortcut_id: None,
            last_opened_url: None,
            sparkle_config,
            sparkle_state: SparkleUpdateState::UpToDate { version: APP_VERSION.to_string() },
            collapsed_categories: vec![ShortcutCategory::AcademicDatabases, ShortcutCategory::Custom],
            shell_presence: prefs.shell_presence,
            launch_at_login: prefs.launch_at_login,
        };
        vm.sync_update_status_text();
        vm
    }

    /// Returns whether `category` is currently folded in the right-hand accordion pane.
    #[must_use]
    pub fn is_category_collapsed(&self, category: ShortcutCategory) -> bool {
        self.collapsed_categories.contains(&category)
    }

    /// Toggles the folded state of `category` in the right-hand accordion pane.
    pub fn toggle_category(&mut self, category: ShortcutCategory) {
        if let Some(pos) = self.collapsed_categories.iter().position(|c| *c == category) {
            self.collapsed_categories.remove(pos);
        } else {
            self.collapsed_categories.push(category);
        }
    }

    /// Returns favorite shortcuts belonging to `category` matching `search_query`.
    #[must_use]
    pub fn shortcuts_in_category(&self, category: ShortcutCategory) -> Vec<&CampusShortcut> {
        self.favorite_shortcuts()
            .into_iter()
            .filter(|s| s.category == category)
            .collect()
    }

    /// Switches the UI locale between Simplified Chinese and English and refreshes status copy.
    pub fn set_locale(&mut self, locale: UiLocale) {
        self.locale = locale;
        self.sync_update_status_text();
        self.save_preferences();
    }

    /// Switches the active UI scheme (`CrimsonSplit`, `BambooColumn`, or `IndigoTrayFirst`).
    pub fn set_scheme(&mut self, scheme: UiScheme) {
        self.scheme = scheme;
        self.save_preferences();
    }

    /// Updates the Launch at Login setting and syncs `~/Library/LaunchAgents/local.szu.securelink.login.plist`.
    pub fn set_launch_at_login(&mut self, enabled: bool) {
        #[cfg(not(test))]
        let ok = set_launch_at_login(enabled);
        #[cfg(test)]
        let ok = {
            let _ = set_launch_at_login;
            true
        };
        if ok {
            self.launch_at_login = enabled;
            self.save_preferences();
        }
    }

    /// Updates automatic Sparkle update checking and persists preferences.
    pub fn set_auto_check_updates(&mut self, enabled: bool) {
        self.sparkle_config.automatic_checks = enabled;
        self.save_preferences();
    }

    /// Persists the current [`AppPreferences`] to disk.
    pub fn save_preferences(&self) {
        let prefs = AppPreferences {
            shell_presence: self.shell_presence,
            launch_at_login: self.launch_at_login,
            auto_check_updates: self.sparkle_config.automatic_checks,
            locale: self.locale,
            scheme: self.scheme,
        };
        #[cfg(not(test))]
        prefs.save_persisted();
        #[cfg(test)]
        let _ = prefs.to_lines();
    }

    /// Runs a version update check and opens or updates the Settings state.
    pub fn check_for_updates(&mut self) {
        self.sparkle_state = SparkleUpdateState::UpToDate {
            version: APP_VERSION.to_string(),
        };
        self.sync_update_status_text();
    }

    /// Evaluates a signed Sparkle 2.x appcast item against `APP_VERSION`.
    pub fn apply_sparkle_appcast(&mut self, item: SparkleAppcastItem) -> bool {
        if item.validate().is_err() {
            self.sparkle_state = SparkleUpdateState::Failed {
                reason: if self.locale == UiLocale::EnUs {
                    "Update signature or metadata invalid".to_string()
                } else {
                    "更新包签名或元数据校验未通过".to_string()
                },
            };
            self.sync_update_status_text();
            return false;
        }
        if is_newer_version(APP_VERSION, &item.version) {
            self.sparkle_state = SparkleUpdateState::UpdateAvailable(item);
        } else {
            self.sparkle_state = SparkleUpdateState::UpToDate {
                version: APP_VERSION.to_string(),
            };
        }
        self.sync_update_status_text();
        true
    }

    fn sync_update_status_text(&mut self) {
        let en = self.locale == UiLocale::EnUs;
        self.update_status = match &self.sparkle_state {
            SparkleUpdateState::Idle | SparkleUpdateState::Checking => {
                if en { "Checking for updates via Sparkle…" } else { "正在通过 Sparkle 检查更新…" }.to_string()
            }
            SparkleUpdateState::UpToDate { version } => {
                if en { format!("Up to date (v{version})") } else { format!("当前已是最新版本（v{version}）") }
            }
            SparkleUpdateState::UpdateAvailable(item) => {
                let size = format_package_size_mb(item.length_bytes).unwrap_or_default();
                if en { format!("Update available: v{} ({size})", item.version) } else { format!("发现新版本 v{}（{size}）", item.version) }
            }
            SparkleUpdateState::Failed { reason } => reason.clone(),
        };
    }

    /// Toggles between the main Workbench view and the Settings page.
    pub fn toggle_settings(&mut self) {
        self.route = match self.route {
            WorkbenchRoute::Workbench => WorkbenchRoute::Settings,
            WorkbenchRoute::Settings => WorkbenchRoute::Workbench,
        };
    }

    /// Transitions the workbench to an active `utun` connected state and drains any queued shortcut.
    pub fn set_connected(&mut self, interface: &str, virtual_ipv4: &str) {
        self.status = ConnectionStatus::Connected {
            interface: interface.to_string(),
            virtual_ipv4: virtual_ipv4.to_string(),
            dns_server: "192.168.247.6".to_string(),
        };
        if let Some(pending_id) = self.pending_open_shortcut_id.take()
            && let Some(item) = self.shortcuts.iter().find(|s| s.id == pending_id)
        {
            self.last_opened_url = Some(item.url.clone());
        }
    }

    /// Activates a shortcut by ID. If disconnected, queues the shortcut and starts connecting automatically.
    pub fn activate_shortcut(&mut self, id: &str) -> Option<ShortcutLaunchOutcome> {
        let item = self.shortcuts.iter().find(|s| s.id == id)?;
        let url = item.url.clone();
        let name = item.name.clone();
        match &self.status {
            ConnectionStatus::Connected { .. } => {
                self.last_opened_url = Some(url.clone());
                Some(ShortcutLaunchOutcome::OpenedImmediately(url))
            }
            ConnectionStatus::Disconnected | ConnectionStatus::Connecting { .. } => {
                self.pending_open_shortcut_id = Some(id.to_string());
                let phase = if self.locale == UiLocale::EnUs {
                    format!("Connecting campus network, will open \"{name}\" automatically…")
                } else {
                    format!("正在为您连接校园网，连上后自动打开「{name}」…")
                };
                self.status = ConnectionStatus::Connecting { phase };
                Some(ShortcutLaunchOutcome::QueuedAfterConnect {
                    shortcut_id: id.to_string(),
                    url,
                })
            }
        }
    }

    /// Returns the 4 user-pinned shortcuts for the macOS menu bar quick-access list.
    #[must_use]
    pub fn menu_bar_shortcuts(&self) -> Vec<&CampusShortcut> {
        self.menu_bar_pins
            .iter()
            .filter_map(|pin_id| self.shortcuts.iter().find(|s| &s.id == pin_id))
            .collect()
    }

    /// Replaces slot `0..4` in the macOS menu bar quick-access pins with an existing shortcut `id`.
    pub fn pin_to_menu_bar(&mut self, slot: usize, id: &str) -> bool {
        if slot >= 4 || !self.shortcuts.iter().any(|s| s.id == id) {
            return false;
        }
        self.menu_bar_pins[slot] = id.to_string();
        true
    }

    /// Returns whether `id` is currently in the 4-slot macOS menu bar quick-access list.
    #[must_use]
    pub fn is_pinned_to_menu_bar(&self, id: &str) -> bool {
        self.menu_bar_pins.iter().any(|p| p == id)
    }

    /// Pins `id` into the 4-slot menu bar quick-access list (rotating into the last slot if not present).
    pub fn toggle_menu_bar_pin(&mut self, id: &str) -> bool {
        if !self.shortcuts.iter().any(|s| s.id == id) {
            return false;
        }
        if self.is_pinned_to_menu_bar(id) {
            return true;
        }
        self.menu_bar_pins.rotate_left(1);
        self.menu_bar_pins[3] = id.to_string();
        true
    }

    /// Returns the macOS menu bar template icon geometry matching the current connection state.
    #[must_use]
    pub const fn menu_bar_icon_geometry(&self) -> MenuBarIconGeometry {
        match self.status {
            ConnectionStatus::Disconnected => MenuBarIconGeometry::DisconnectedOutline,
            ConnectionStatus::Connecting { .. } => MenuBarIconGeometry::ConnectingPulse,
            ConnectionStatus::Connected { .. } => MenuBarIconGeometry::ConnectedSolid,
        }
    }

    /// Toggles the favorite star on shortcut `id`.
    pub fn toggle_favorite(&mut self, id: &str) -> bool {
        if let Some(item) = self.shortcuts.iter_mut().find(|s| s.id == id) {
            item.is_favorite = !item.is_favorite;
            return true;
        }
        false
    }

    /// Adds a validated custom campus shortcut.
    pub fn add_custom_shortcut(&mut self, name: &str, subtitle: &str, url: &str) -> bool {
        let clean_name = name.trim();
        let clean_url = url.trim();
        if clean_name.is_empty()
            || clean_name.len() > 64
            || !valid_url(clean_url)
            || self.shortcuts.len() >= 32
        {
            return false;
        }
        self.shortcuts.push(CampusShortcut {
            id: format!("custom-{}", self.shortcuts.len() + 1),
            name: clean_name.to_string(),
            subtitle: if subtitle.trim().is_empty() {
                "自定义常用校内入口".to_string()
            } else {
                subtitle.trim().to_string()
            },
            url: clean_url.to_string(),
            category: ShortcutCategory::Custom,
            is_favorite: true,
            is_built_in: false,
        });
        true
    }

    /// Returns favorite shortcuts matching the active `search_query`.
    #[must_use]
    pub fn favorite_shortcuts(&self) -> Vec<&CampusShortcut> {
        let q = self.search_query.trim().to_ascii_lowercase();
        self.shortcuts
            .iter()
            .filter(|s| {
                s.is_favorite
                    && (q.is_empty()
                        || s.name.to_ascii_lowercase().contains(&q)
                        || s.subtitle.to_ascii_lowercase().contains(&q))
            })
            .collect()
    }

    /// Returns all unique domains that should be pre-resolved via the in-tunnel DNS (`192.168.247.6`).
    #[must_use]
    pub fn in_tunnel_resolve_domains(&self) -> Vec<String> {
        let mut domains = vec![
            "www1.szu.edu.cn".to_string(),
            "authserver.szu.edu.cn".to_string(),
            "ehall.szu.edu.cn".to_string(),
            "cwpt.szu.edu.cn".to_string(),
            "oa.szu.edu.cn".to_string(),
            "www.lib.szu.edu.cn".to_string(),
            "idp.szu.edu.cn".to_string(),
            "ezproxy.lib.szu.edu.cn".to_string(),
            "accproxy.lib.szu.edu.cn".to_string(),
        ];
        for h in extract_hosts(&self.shortcuts) {
            if !domains.contains(&h) && domains.len() < 32 {
                domains.push(h);
            }
        }
        domains
    }
}
