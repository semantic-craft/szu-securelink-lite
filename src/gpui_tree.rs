//! Declarative GPUI-Kit element tree inspection for `WorkbenchViewModel`.

#![forbid(unsafe_code)]

use crate::gpui_workbench::{
    ConnectionStatus, UiLocale, WorkbenchRoute, WorkbenchViewModel, ABOUT_ATTRIBUTION_TEXT,
    APP_CHINESE_NAME, APP_VERSION,
};

/// Declarative GPUI-Kit UI node representing the rendered Workbench view hierarchy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuiElement {
    /// Element tag (`"Window"`, `"TitleBar"`, `"StatusBadge"`, `"ShortcutGrid"`, `"Card"`, `"TrayMenu"`).
    pub kind: &'static str,
    /// Primary text label.
    pub label: String,
    /// Secondary caption or URL action target.
    pub detail: String,
    /// Child elements inside this layout container.
    pub children: Vec<GpuiElement>,
}

impl WorkbenchViewModel {
    /// Renders the macOS status-bar tray menu tree (1-click connect + 4 user-pinned services).
    #[must_use]
    pub fn render_tray_menu_tree(&self) -> GpuiElement {
        let en = self.locale == UiLocale::EnUs;
        let toggle_label = match &self.status {
            ConnectionStatus::Disconnected => {
                if en { "Connect" } else { "连接" }
            }
            ConnectionStatus::Connecting { .. } => {
                if en { "Connecting…" } else { "正在连接…" }
            }
            ConnectionStatus::Connected { .. } => {
                if en { "Disconnect" } else { "断开" }
            }
        };
        let mut children = vec![GpuiElement {
            kind: "TrayToggle",
            label: toggle_label.to_string(),
            detail: format!("{:?}", self.menu_bar_icon_geometry()),
            children: Vec::new(),
        }];
        for item in self.menu_bar_shortcuts() {
            children.push(GpuiElement {
                kind: "TrayPinItem",
                label: item.name.clone(),
                detail: item.url.clone(),
                children: Vec::new(),
            });
        }
        GpuiElement {
            kind: "TrayMenu",
            label: if en {
                "SZU SecureLink Menu Bar".to_string()
            } else {
                "深大校园网菜单栏快捷入口".to_string()
            },
            detail: format!(
                "pins={}, scheme={:?}",
                self.menu_bar_shortcuts().len(),
                self.scheme
            ),
            children,
        }
    }

    /// Renders the declarative GPUI-Kit element tree for the main window and menu-bar tray.
    #[must_use]
    pub fn render_gpui_tree(&self) -> GpuiElement {
        let en = self.locale == UiLocale::EnUs;
        let status_badge = match &self.status {
            ConnectionStatus::Disconnected => GpuiElement {
                kind: "StatusBadge",
                label: if en {
                    "Not Connected".to_string()
                } else {
                    "未连接校园网".to_string()
                },
                detail: if en {
                    "Click Connect or any service below to sign in automatically".to_string()
                } else {
                    "点击连接或直接点任意校内服务自动登录".to_string()
                },
                children: Vec::new(),
            },
            ConnectionStatus::Connecting { phase } => GpuiElement {
                kind: "StatusBadge",
                label: if en {
                    "Connecting".to_string()
                } else {
                    "正在连接".to_string()
                },
                detail: phase.clone(),
                children: Vec::new(),
            },
            ConnectionStatus::Connected {
                interface,
                virtual_ipv4,
                dns_server,
            } => GpuiElement {
                kind: "StatusBadge",
                label: if en {
                    "Connected to Campus Network".to_string()
                } else {
                    "校园网已连接".to_string()
                },
                detail: if en {
                    format!(
                        "Interface {interface}, Virtual IP {virtual_ipv4}, Campus DNS {dns_server}"
                    )
                } else {
                    format!("接口 {interface}，虚拟IP {virtual_ipv4}，内网DNS {dns_server}")
                },
                children: Vec::new(),
            },
        };

        let cards: Vec<GpuiElement> = self
            .favorite_shortcuts()
            .into_iter()
            .map(|item| GpuiElement {
                kind: "Card",
                label: item.name.clone(),
                detail: item.url.clone(),
                children: Vec::new(),
            })
            .collect();

        let footer = GpuiElement {
            kind: "AboutFooter",
            label: if en {
                format!("Check for Updates ({})", self.update_status)
            } else {
                format!("检查更新（{}）", self.update_status)
            },
            detail: ABOUT_ATTRIBUTION_TEXT.to_string(),
            children: Vec::new(),
        };

        let mut children = vec![
            status_badge,
            GpuiElement {
                kind: "ShortcutGrid",
                label: if en {
                    "Pinned Campus Services".to_string()
                } else {
                    "常用校内服务".to_string()
                },
                detail: format!("{} items", cards.len()),
                children: cards,
            },
            footer,
        ];

        if self.route == WorkbenchRoute::Settings {
            children.push(GpuiElement {
                kind: "SettingsPage",
                label: format!("{APP_CHINESE_NAME} · SZU SecureLink v{APP_VERSION}"),
                detail: ABOUT_ATTRIBUTION_TEXT.to_string(),
                children: vec![GpuiElement {
                    kind: "UpdateRow",
                    label: if en {
                        "Check for Updates".to_string()
                    } else {
                        "检查更新".to_string()
                    },
                    detail: self.update_status.clone(),
                    children: Vec::new(),
                }],
            });
        }

        GpuiElement {
            kind: "Window",
            label: format!("{APP_CHINESE_NAME} · SZU SecureLink (GPUI-Kit Native)"),
            detail: format!(
                "org={}, favorites={}, scheme={:?}, locale={:?}",
                self.org,
                self.favorite_shortcuts().len(),
                self.scheme,
                self.locale
            ),
            children,
        }
    }
}
