//! Native GPUI-Kit desktop window for `SZU SecureLink.app` (`#![forbid(unsafe_code)]`).

#![forbid(unsafe_code)]

use crate::gpui_workbench::{
    ConnectionStatus, ShortcutLaunchOutcome, UiLocale, UiScheme, WorkbenchRoute,
    WorkbenchViewModel, ABOUT_ATTRIBUTION_TEXT, APP_CHINESE_NAME, APP_VERSION,
};
use crate::shortcuts::ShortcutCategory;
use crate::sparkle::format_route_count;
use crate::tray_bridge::{MenuBarBridge, ShellPresence, TrayAction};
use crate::tunnel_actor::{
    GenerationId, SessionCommand, SessionEvent, TunnelHandle, validate_securelink_callback_url,
};
use gpui_kit::base::async_util::{self, Receiver};
use gpui_kit::component::Sizable;
use gpui_kit::component::button::*;
use gpui_kit::*;
use std::sync::Arc;

actions!(securelink, [OpenSettings, CheckUpdates, Quit, ToggleConnectAction]);

const GUIDE_URL: &str = "https://www1.szu.edu.cn/nc/view.asp?id=631";
const MASCOT_PNG: &[u8] = include_bytes!("../assets/mascot-icon.png");

/// Stateful GPUI desktop workbench view backed by [`WorkbenchViewModel`] and [`TunnelHandle`].
pub struct WorkbenchWindow {
    /// Underlying pure-Rust workbench state machine.
    pub vm: WorkbenchViewModel,
    /// Handle to the background Zero-Trust tunnel supervisor actor.
    pub actor: TunnelHandle,
    /// Bridge to the top-right macOS Menu Bar status item (`NSStatusItem`).
    pub tray_bridge: MenuBarBridge,
    /// Highest session generation applied to `vm`.
    pub generation: GenerationId,
    /// Whether the collapsible raw network details (`utun4`, IPv4, DNS, routes) are expanded.
    pub show_network_details: bool,
    /// Cached peeking-lychee mascot image (`assets/mascot-icon.png`).
    pub mascot: Arc<Image>,
}

impl WorkbenchWindow {
    /// Creates a new [`WorkbenchWindow`] bound to `actor`.
    #[must_use]
    pub fn new(actor: TunnelHandle) -> Self {
        Self::with_bridge(actor, MenuBarBridge::default())
    }

    /// Creates a new [`WorkbenchWindow`] bound to `actor` and `tray_bridge`.
    #[must_use]
    pub fn with_bridge(actor: TunnelHandle, tray_bridge: MenuBarBridge) -> Self {
        Self {
            vm: WorkbenchViewModel::new(),
            actor,
            tray_bridge,
            generation: GenerationId(0),
            show_network_details: false,
            mascot: Arc::new(Image::from_bytes(ImageFormat::Png, MASCOT_PNG.to_vec())),
        }
    }

    /// Applies a [`SessionEvent`] from the tunnel supervisor if its generation is current.
    pub fn apply_session_event(&mut self, event: SessionEvent) {
        match event {
            SessionEvent::ConnectingPhase { generation, phase }
                if generation > self.generation
                    || (generation == self.generation
                        && matches!(self.vm.status, ConnectionStatus::Connecting { .. })) =>
            {
                self.generation = generation;
                self.vm.status = ConnectionStatus::Connecting { phase };
            }
            SessionEvent::TunnelActive { generation, notice } => {
                self.generation = self.generation.max(generation);
                self.vm.set_connected(&notice.interface, &notice.virtual_ipv4);
                if let Some(url) = self.vm.last_opened_url.take() {
                    self.actor.send(SessionCommand::OpenBrowserUrl(url));
                }
            }
            SessionEvent::Disconnected { generation, .. } if generation >= self.generation => {
                self.generation = generation;
                self.vm.status = ConnectionStatus::Disconnected;
            }
            SessionEvent::TrayAction(action) => match action {
                TrayAction::ToggleConnect => { self.actor.send(SessionCommand::ToggleConnect); }
                TrayAction::Repair => { self.actor.send(SessionCommand::Repair); }
                TrayAction::OpenPin(id) => self.on_shortcut_clicked(&id),
                TrayAction::OpenSettings => { self.vm.route = WorkbenchRoute::Settings; }
                TrayAction::ToggleDock => {
                    self.vm.shell_presence = self.vm.shell_presence.toggle_dock();
                    self.vm.save_preferences();
                }
                TrayAction::ToggleMenuBar => {
                    self.vm.shell_presence = self.vm.shell_presence.toggle_menu_bar();
                    self.vm.save_preferences();
                }
                TrayAction::ShowWindow | TrayAction::Quit => {}
            },
            _ => {}
        }
        self.tray_bridge.sync_from_vm(&self.vm);
    }

    /// Handles clicking a campus shortcut card or menu-bar pin.
    pub fn on_shortcut_clicked(&mut self, id: &str) {
        let already_connecting = matches!(self.vm.status, ConnectionStatus::Connecting { .. });
        if let Some(outcome) = self.vm.activate_shortcut(id) {
            match outcome {
                ShortcutLaunchOutcome::OpenedImmediately(url) => {
                    self.actor.send(SessionCommand::OpenBrowserUrl(url));
                }
                ShortcutLaunchOutcome::QueuedAfterConnect { .. } if !already_connecting => {
                    let resolve_domains = self.vm.in_tunnel_resolve_domains();
                    self.actor.send(SessionCommand::Connect { resolve_domains });
                }
                ShortcutLaunchOutcome::QueuedAfterConnect { .. } => {}
            }
            self.tray_bridge.sync_from_vm(&self.vm);
        }
    }

    fn apply_presence(&mut self, next: ShellPresence, cx: &mut Context<Self>) {
        self.vm.shell_presence = next;
        self.vm.save_preferences();
        apply_dock_policy(next, cx);
        self.tray_bridge.sync_from_vm(&self.vm);
        cx.notify();
    }

    fn accent_rgb(&self) -> u32 {
        match self.vm.scheme {
            UiScheme::CrimsonSplit => 0x8c2232,
            UiScheme::BambooColumn => 0x2b5f4e,
            UiScheme::IndigoTrayFirst => 0x2e4b6c,
        }
    }

    fn render_settings_body(&mut self, en: bool, accent_hex: u32, cx: &mut Context<Self>) -> AnyElement {
        let accent = rgb(accent_hex);
        let cur_p = self.vm.shell_presence;
        let modes = [
            (ShellPresence::DockAndMenuBar, if en { "Dock & Menu Bar (Recommended)" } else { "同时显示程序坞与菜单栏图标（推荐）" }),
            (ShellPresence::MenuBarOnly, if en { "Menu Bar Icon Only (Hide Dock)" } else { "仅保留右上角菜单栏图标（隐藏 Dock）" }),
            (ShellPresence::DockOnly, if en { "Dock Icon Only (Hide Menu Bar)" } else { "仅保留底部程序坞图标（隐藏菜单栏）" }),
        ];
        let mut presence_list = div().w_full().min_w_0().flex().flex_col().gap_1p5();
        for (idx, (mode, label)) in modes.into_iter().enumerate() {
            let active = cur_p == mode;
            let (bd, bg, fg, mark) = if active { (accent_hex, 0xf6eaec, accent_hex, "●") } else { (0xe4dfd7, 0xf5f2ec, 0x1f1e1c, "○") };
            presence_list = presence_list.child(
                div().id(SharedString::from(format!("presence-mode-{idx}"))).w_full().min_w_0().h(px(30.0)).px_2p5().rounded_md().border_1().border_color(rgb(bd)).bg(rgb(bg)).flex().items_center().justify_between().cursor_pointer()
                    .child(div().text_xs().font_weight(if active { FontWeight::SEMIBOLD } else { FontWeight::NORMAL }).text_color(rgb(fg)).child(label))
                    .child(div().text_xs().font_weight(FontWeight::BOLD).text_color(rgb(fg)).child(mark))
                    .on_click(cx.listener(move |this, _, _, cx| { this.apply_presence(mode, cx); })),
            );
        }

        let login_on = self.vm.launch_at_login;
        let (lg_bd, lg_bg, lg_fg) = if login_on { (accent_hex, 0xf6eaec, accent_hex) } else { (0xe4dfd7, 0xf5f2ec, 0x5c5852) };
        let login_row = div().id("toggle-launch-login").w_full().min_w_0().h(px(32.0)).px_2p5().rounded_md().border_1().border_color(rgb(lg_bd)).bg(rgb(lg_bg)).flex().items_center().justify_between().cursor_pointer()
            .child(div().text_xs().font_weight(FontWeight::MEDIUM).text_color(rgb(0x1f1e1c)).child(if en { "Launch at macOS Login" } else { "开机自动启动荔连" }))
            .child(div().text_xs().font_weight(FontWeight::BOLD).text_color(rgb(lg_fg)).child(if login_on { if en { "✓ Enabled" } else { "✓ 已开启" } } else if en { "Off" } else { "未开启" }))
            .on_click(cx.listener(|this, _, _, cx| { this.vm.set_launch_at_login(!this.vm.launch_at_login); cx.notify(); }));

        let presence_card = div().w_full().min_w_0().p_3p5().rounded_lg().bg(rgb(0xfcfbf9)).border_1().border_color(rgb(0xe4dfd7)).flex().flex_col().gap_2().overflow_hidden()
            .child(div().text_xs().font_weight(FontWeight::SEMIBOLD).text_color(accent).child(if en { "System Presence & Startup" } else { "系统常驻与开机启动" }))
            .child(presence_list)
            .child(div().w_full().text_xs().text_color(rgb(0x8c8782)).child(if en { "At least one icon stays visible; reopening restores the window." } else { "至少保留一处入口；窗口关闭后再次打开应用自动唤起工作台。" }))
            .child(div().w_full().pt_1().border_t_1().border_color(rgb(0xe4dfd7)).child(login_row));

        let zh_active = self.vm.locale == UiLocale::ZhCn;
        let lang_row = div().w_full().min_w_0().flex().items_center().gap_2()
            .child(div().id("lang-zh").flex_1().min_w_0().h(px(28.0)).rounded_sm().border_1().border_color(rgb(if zh_active { accent_hex } else { 0xe4dfd7 })).bg(rgb(if zh_active { 0xf6eaec } else { 0xf5f2ec })).text_color(rgb(if zh_active { accent_hex } else { 0x5c5852 })).text_xs().font_weight(FontWeight::MEDIUM).flex().items_center().justify_center().cursor_pointer().child("简体中文").on_click(cx.listener(|this, _, _, cx| { this.vm.set_locale(UiLocale::ZhCn); this.tray_bridge.sync_from_vm(&this.vm); cx.notify(); })))
            .child(div().id("lang-en").flex_1().min_w_0().h(px(28.0)).rounded_sm().border_1().border_color(rgb(if !zh_active { accent_hex } else { 0xe4dfd7 })).bg(rgb(if !zh_active { 0xf6eaec } else { 0xf5f2ec })).text_color(rgb(if !zh_active { accent_hex } else { 0x5c5852 })).text_xs().font_weight(FontWeight::MEDIUM).flex().items_center().justify_center().cursor_pointer().child("English").on_click(cx.listener(|this, _, _, cx| { this.vm.set_locale(UiLocale::EnUs); this.tray_bridge.sync_from_vm(&this.vm); cx.notify(); })));

        let schemes = [
            (UiScheme::CrimsonSplit, 0x8c2232u32, if en { "Crimson" } else { "深大荔枝红" }),
            (UiScheme::BambooColumn, 0x2b5f4e, if en { "Bamboo" } else { "竹院青" }),
            (UiScheme::IndigoTrayFirst, 0x2e4b6c, if en { "Indigo" } else { "松烟靛" }),
        ];
        let mut scheme_row = div().w_full().min_w_0().flex().items_center().gap_2();
        for (idx, (sc, hex, name)) in schemes.into_iter().enumerate() {
            let active = self.vm.scheme == sc;
            scheme_row = scheme_row.child(
                div().id(SharedString::from(format!("scheme-{idx}"))).flex_1().min_w_0().h(px(28.0)).rounded_sm().border_1().border_color(rgb(if active { hex } else { 0xe4dfd7 })).bg(rgb(if active { 0xf6eaec } else { 0xf5f2ec })).text_color(rgb(if active { hex } else { 0x5c5852 })).text_xs().font_weight(FontWeight::MEDIUM).flex().items_center().justify_center().cursor_pointer().child(name)
                    .on_click(cx.listener(move |this, _, _, cx| { this.vm.set_scheme(sc); cx.notify(); })),
            );
        }

        let appearance_card = div().flex_1().w_full().min_w_0().p_3p5().rounded_lg().bg(rgb(0xfcfbf9)).border_1().border_color(rgb(0xe4dfd7)).flex().flex_col().justify_between().overflow_hidden()
            .child(div().text_xs().font_weight(FontWeight::SEMIBOLD).text_color(accent).child(if en { "Language & Theme Accent" } else { "界面语言与主题配色" }))
            .child(lang_row)
            .child(scheme_row);

        let left_col = div().w(px(320.0)).min_w_0().h_full().flex().flex_col().gap_3().child(presence_card).child(appearance_card);

        let auto_upd = self.vm.sparkle_config.automatic_checks;
        let (au_bd, au_bg, au_fg) = if auto_upd { (accent_hex, 0xf6eaec, accent_hex) } else { (0xe4dfd7, 0xf5f2ec, 0x5c5852) };
        let routes = format_route_count(133, en).unwrap_or_default();
        let right_col = div().flex_1().min_w_0().h_full().p_3p5().rounded_lg().bg(rgb(0xfcfbf9)).border_1().border_color(rgb(0xe4dfd7)).flex().flex_col().justify_between().overflow_hidden()
            .child(
                div().w_full().min_w_0().flex().flex_col().gap_2p5()
                    .child(div().text_xs().font_weight(FontWeight::SEMIBOLD).text_color(accent).child(if en { "Updates, Diagnostics & About" } else { "版本更新、网络排障与关于" }))
                    .child(
                        div().w_full().min_w_0().p_3().rounded_md().bg(rgb(0xfaf3f4)).border_1().border_color(rgb(0xe4dfd7)).flex().items_center().gap_3().overflow_hidden()
                            .child(img(self.mascot.clone()).w(px(40.0)).h(px(40.0)).rounded_lg())
                            .child(div().flex_1().min_w_0().flex().flex_col().gap_0p5().child(div().text_sm().font_weight(FontWeight::BOLD).text_color(rgb(0x1f1e1c)).child(format!("{APP_CHINESE_NAME} · SZU SecureLink v{APP_VERSION}"))).child(div().text_xs().text_color(rgb(0x5c5852)).child(self.vm.update_status.clone())).child(div().text_xs().text_color(rgb(0x8c8782)).child(ABOUT_ATTRIBUTION_TEXT))),
                    )
                    .child(
                        div().w_full().min_w_0().flex().items_center().gap_2()
                            .child(div().id("settings-check-upd").flex_1().min_w_0().h(px(32.0)).rounded_md().bg(accent).text_color(rgb(0xffffff)).text_xs().font_weight(FontWeight::SEMIBOLD).flex().items_center().justify_center().cursor_pointer().child(if en { "Check Updates" } else { "立即检查更新" }).on_click(cx.listener(|this, _, _, cx| { this.vm.check_for_updates(); cx.notify(); })))
                            .child(div().id("settings-auto-upd").flex_1().min_w_0().h(px(32.0)).rounded_md().border_1().border_color(rgb(au_bd)).bg(rgb(au_bg)).text_color(rgb(au_fg)).text_xs().font_weight(FontWeight::MEDIUM).flex().items_center().justify_center().cursor_pointer().child(if auto_upd { if en { "✓ Auto Update" } else { "✓ 自动检查更新" } } else if en { "○ Auto Update" } else { "○ 自动检查更新" }).on_click(cx.listener(|this, _, _, cx| { this.vm.set_auto_check_updates(!this.vm.sparkle_config.automatic_checks); cx.notify(); }))),
                    ),
            )
            .child(
                div().w_full().min_w_0().pt_2p5().border_t_1().border_color(rgb(0xe4dfd7)).flex().flex_col().gap_2()
                    .child(div().text_xs().font_weight(FontWeight::SEMIBOLD).text_color(rgb(0x1f1e1c)).child(if en { "Zero-Trust Tunnel & Privileged Helper" } else { "零信任隧道与特权路由助手" }))
                    .child(
                        div().w_full().min_w_0().p_2p5().rounded_md().bg(rgb(0xf5f2ec)).flex().flex_col().gap_1().overflow_hidden()
                            .child(div().text_xs().font_weight(FontWeight::MEDIUM).text_color(rgb(0x1f1e1c)).child(if en { format!("Campus DNS 192.168.247.6 · {routes}") } else { format!("内网 DNS 192.168.247.6 · {routes}") }))
                            .child(div().text_xs().text_color(rgb(0x5c5852)).child(if en { "Privileged helper ready · 100% Safe Rust" } else { "特权路由助手已就绪 · 100% Safe Rust 原生构建" })),
                    )
                    .child(
                        div().w_full().min_w_0().flex().items_center().gap_2()
                            .child(div().id("settings-repair-btn").flex_1().min_w_0().h(px(32.0)).rounded_md().bg(rgb(0x1f1e1c)).text_color(rgb(0xffffff)).text_xs().font_weight(FontWeight::MEDIUM).flex().items_center().justify_center().cursor_pointer().child(if en { "↻ Reset Routes & DNS" } else { "↻ 重置路由与 DNS" }).on_click(cx.listener(|this, _, _, _| { this.actor.send(SessionCommand::Repair); })))
                            .child(div().id("settings-guide-btn").flex_1().min_w_0().h(px(32.0)).rounded_md().border_1().border_color(rgb(0xe4dfd7)).bg(rgb(0xf5f2ec)).text_color(rgb(0x1f1e1c)).text_xs().font_weight(FontWeight::MEDIUM).flex().items_center().justify_center().cursor_pointer().child(if en { "Campus Guide" } else { "学校使用指南" }).on_click(cx.listener(|this, _, _, _| { this.actor.send(SessionCommand::OpenBrowserUrl(GUIDE_URL.to_string())); }))),
                    ),
            );

        div().w_full().min_w_0().flex_1().min_h_0().my_3().flex().gap_3p5().child(left_col).child(right_col).into_any_element()
    }
}

fn apply_dock_policy(presence: ShellPresence, cx: &mut App) {
    if presence.shows_dock() {
        cx.set_activation_policy(ActivationPolicy::Regular);
        cx.activate(true);
    } else {
        cx.set_activation_policy(ActivationPolicy::Accessory);
    }
}

impl Render for WorkbenchWindow {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let en = self.vm.locale == UiLocale::EnUs;
        let accent_hex = self.accent_rgb();
        let accent = rgb(accent_hex);
        let is_connecting = matches!(self.vm.status, ConnectionStatus::Connecting { .. });
        let in_settings = self.vm.route == WorkbenchRoute::Settings;
        let (title_rgb, pill_bg, banner_bg, btn_bg, status_badge, status_title, status_detail, primary_btn_label, tech_summary) =
            match &self.vm.status {
                ConnectionStatus::Disconnected => (
                    accent_hex, 0xf6eaec, 0xfaf3f4, accent_hex,
                    if en { "● DISCONNECTED" } else { "● 当前未连接" }.to_string(),
                    if en { "Not Connected" } else { "未连接深圳大学校园网" }.to_string(),
                    if en { "Click Connect below or any campus service on the right to sign in." } else { "点击下方大按钮或右侧任意校内服务，登录深大 CAS 后自动接入内网。" }.to_string(),
                    if en { "Connect Campus Network" } else { "立即连接校园网" },
                    None,
                ),
                ConnectionStatus::Connecting { phase } => (
                    0xb45309, 0xfef3c7, 0xfffbeb, 0xb45309,
                    if en { "● CONNECTING…" } else { "● 正在连接中…" }.to_string(),
                    if en { "Connecting…" } else { "正在建立校园网隧道…" }.to_string(),
                    phase.clone(),
                    if en { "Cancel" } else { "取消连接" },
                    None,
                ),
                ConnectionStatus::Connected { interface, virtual_ipv4, dns_server } => {
                    let routes = format_route_count(129, en).unwrap_or_default();
                    let detail_line = if en {
                        format!("{interface} · {virtual_ipv4} · DNS {dns_server} ({routes})")
                    } else {
                        format!("接口 {interface} · 虚拟IP {virtual_ipv4} · DNS {dns_server}（{routes}）")
                    };
                    (
                        0x1f6b45, 0xe6f4ec, 0xf0faf4, 0x1f6b45,
                        if en { "● CONNECTED" } else { "● 校园网已连接" }.to_string(),
                        if en { "Campus Connected" } else { "已连接深圳大学校园网" }.to_string(),
                        if en { "Zero-trust campus tunnel active. Click any service on the right to open." } else { "零信任内网隧道已就绪，点击右侧任意校内服务或数据库即可直接打开。" }.to_string(),
                        if en { "Disconnect Campus Network" } else { "断开校园网连接" },
                        Some(detail_line),
                    )
                }
            };

        let nav_label = if in_settings {
            if en { "← Workbench" } else { "← 返回工作台" }
        } else if en {
            "⚙ Settings"
        } else {
            "⚙ 设置"
        };

        let header = div().h(px(36.0)).pb_2().border_b_1().border_color(rgb(0xe4dfd7)).flex().items_center().justify_between()
            .child(div().flex().items_center().gap_2p5().child(img(self.mascot.clone()).w(px(28.0)).h(px(28.0)).rounded_md()).child(div().text_base().font_weight(FontWeight::BOLD).text_color(accent).child(if en { "SZU SecureLink · 荔连" } else { "荔连 · SZU SecureLink" })).child(div().h(px(20.0)).px_2().rounded_sm().bg(rgb(0xefeae2)).flex().items_center().text_xs().text_color(accent).child(if en { "Shenzhen University" } else { "深圳大学校园网与常用服务" })))
            .child(
                div().flex().items_center().gap_2()
                    .child(div().h(px(24.0)).px_2p5().rounded_full().bg(rgb(pill_bg)).border_1().border_color(rgb(title_rgb)).flex().items_center().text_xs().font_weight(FontWeight::BOLD).text_color(rgb(title_rgb)).child(status_badge.clone()))
                    .child(Button::new("settings-toggle").secondary().small().label(nav_label).on_click(cx.listener(|this, _, _, cx| {
                        this.vm.toggle_settings();
                        cx.notify();
                    }))),
            );

        let body = if in_settings {
            self.render_settings_body(en, accent_hex, cx)
        } else {
            let toggle_label = if self.show_network_details { if en { "▾ Details" } else { "▾ 收起详情" } } else if en { "▸ Details" } else { "▸ 网络详情" };
            let action_area = if is_connecting {
                div().w_full().flex().gap_2()
                    .child(div().id("repair-connecting-btn").flex_1().h(px(38.0)).rounded_md().bg(accent).text_color(rgb(0xffffff)).text_sm().font_weight(FontWeight::BOLD).flex().items_center().justify_center().cursor_pointer().child(if en { "Auto Repair" } else { "自动修复" }).on_click(cx.listener(|this, _, _, _| { this.actor.send(SessionCommand::Repair); })))
                    .child(div().id("cancel-connect-btn").flex_1().h(px(38.0)).rounded_md().bg(rgb(btn_bg)).text_color(rgb(0xffffff)).text_sm().font_weight(FontWeight::BOLD).flex().items_center().justify_center().cursor_pointer().child(primary_btn_label).on_click(cx.listener(|this, _, _, _| { this.actor.send(SessionCommand::Disconnect); })))
                    .into_any_element()
            } else {
                div().id("connect-btn").w_full().h(px(38.0)).rounded_md().bg(rgb(btn_bg)).text_color(rgb(0xffffff)).text_sm().font_weight(FontWeight::BOLD).flex().items_center().justify_center().cursor_pointer().child(primary_btn_label).on_click(cx.listener(|this, _, _, _| { this.actor.send(SessionCommand::ToggleConnect); })).into_any_element()
            };

            let mut hero_card = div().p_3p5().rounded_lg().bg(rgb(0xfcfbf9)).border_2().border_color(rgb(title_rgb)).flex().flex_col().gap_2p5()
                .child(div().p_2p5().rounded_md().bg(rgb(banner_bg)).flex().items_center().gap_2p5().child(img(self.mascot.clone()).w(px(40.0)).h(px(40.0)).rounded_lg()).child(div().flex_1().flex().flex_col().gap_0p5().child(div().text_xs().font_weight(FontWeight::BOLD).text_color(rgb(title_rgb)).child(status_badge)).child(div().text_sm().font_weight(FontWeight::BOLD).text_color(rgb(0x1f1e1c)).child(status_title))))
                .child(div().w_full().text_xs().text_color(rgb(0x5c5852)).child(status_detail))
                .child(action_area)
                .child(div().h(px(20.0)).pt_1p5().border_t_1().border_color(rgb(0xe4dfd7)).flex().items_center().justify_between().child(div().id("toggle-net-details").cursor_pointer().text_xs().text_color(rgb(0x5c5852)).child(toggle_label).on_click(cx.listener(|this, _, _, cx| { this.show_network_details = !this.show_network_details; cx.notify(); }))).child(div().id("hero-repair-link").cursor_pointer().text_xs().font_weight(FontWeight::MEDIUM).text_color(accent).child(if en { "↻ Auto Repair" } else { "↻ 自动修复" }).on_click(cx.listener(|this, _, _, _| { this.actor.send(SessionCommand::Repair); }))).child(div().text_xs().text_color(rgb(0x8c8782)).child(format!("v{APP_VERSION}"))));

            if self.show_network_details {
                let line = tech_summary.unwrap_or_else(|| {
                    let routes = format_route_count(133, en).unwrap_or_default();
                    if en { format!("Not connected · DNS 192.168.247.6 staged ({routes})") } else { format!("当前未建立隧道 · 预置内网 DNS 192.168.247.6（{routes}）") }
                });
                hero_card = hero_card.child(div().p_2().rounded_md().bg(rgb(0xf5f2ec)).text_xs().text_color(rgb(0x5c5852)).child(line));
            }

            let mut pin_strip = div().flex().flex_col().gap_1p5();
            for (idx, pin) in self.vm.menu_bar_shortcuts().into_iter().enumerate() {
                let (sid, pname) = (pin.id.clone(), pin.name.clone());
                pin_strip = pin_strip.child(div().id(SharedString::from(format!("pin-{idx}"))).h(px(28.0)).px_2p5().rounded_md().bg(rgb(0xf5f2ec)).border_1().border_color(rgb(0xe4dfd7)).flex().items_center().justify_between().cursor_pointer().child(div().text_xs().font_weight(FontWeight::MEDIUM).text_color(rgb(0x1f1e1c)).child(pname)).child(div().text_xs().text_color(rgb(0x8c8782)).child(format!("#{}", idx + 1))).on_click(cx.listener(move |this, _, _, cx| { this.on_shortcut_clicked(&sid); cx.notify(); })));
            }

            let tray_card = div().flex_1().p_3p5().rounded_lg().bg(rgb(0xfcfbf9)).border_1().border_color(rgb(0xe4dfd7)).flex().flex_col().justify_between()
                .child(div().flex().flex_col().gap_1p5().child(div().h(px(20.0)).flex().items_center().justify_between().child(div().text_xs().font_weight(FontWeight::SEMIBOLD).child(if en { "Menu Bar Quick Access" } else { "菜单栏快捷直达" })).child(div().text_xs().text_color(rgb(0x8c8782)).child(if en { "4 / 4 slots" } else { "4 / 4 槽位" }))).child(pin_strip))
                .child(div().text_xs().text_color(rgb(0x8c8782)).child(if en { "Click \"Pin\" on the right to replace a slot" } else { "点击右侧「固定」可替换槽位" }));

            let left_rail = div().w(px(256.0)).h_full().flex().flex_col().gap_3().child(hero_card).child(tray_card);
            let mut accordion = div().id("cat-scroll").flex_1().min_h_0().flex().flex_col().gap_2().overflow_y_scroll();
            for (cat_idx, cat) in ShortcutCategory::ALL.into_iter().enumerate() {
                let collapsed = self.vm.is_category_collapsed(cat);
                let rows: Vec<_> = self.vm.shortcuts_in_category(cat).into_iter().map(|s| (s.id.clone(), s.name.clone(), self.vm.is_pinned_to_menu_bar(&s.id))).collect();
                let count = rows.len();
                let badge_text = if count == 0 { if en { "Extensible" } else { "可扩展" }.to_string() } else if collapsed { if en { format!("{count} · Expand") } else { format!("{count} 项 · 点击展开") } } else if en { format!("{count} items") } else { format!("{count} 项") };

                let hdr = div().id(SharedString::from(format!("cat-hdr-{cat_idx}"))).h(px(32.0)).px_3().bg(rgb(0xf5f2ec)).flex().items_center().justify_between().cursor_pointer()
                    .child(div().flex().items_center().gap_2().child(div().text_xs().font_weight(FontWeight::BOLD).text_color(accent).child(if collapsed { "▸" } else { "▾" })).child(div().text_xs().font_weight(FontWeight::SEMIBOLD).child(cat.title(en))))
                    .child(div().px_2().py_0p5().rounded_sm().bg(rgb(0xfcfbf9)).border_1().border_color(rgb(0xe4dfd7)).text_xs().text_color(rgb(0x5c5852)).child(badge_text))
                    .on_click(cx.listener(move |this, _, _, cx| { this.vm.toggle_category(cat); cx.notify(); }));

                let mut group = div().rounded_md().border_1().border_color(rgb(0xe4dfd7)).bg(rgb(0xfcfbf9)).overflow_hidden().child(hdr);
                if !collapsed {
                    let mut body = div().p_1p5().flex().flex_col().gap_1p5().bg(rgb(0xfcfbf9));
                    if rows.is_empty() {
                        body = body.child(div().h(px(36.0)).px_2p5().rounded_sm().bg(rgb(0xf6f4f0)).flex().items_center().text_xs().text_color(rgb(0x6e6a64)).child(if en { "Supports adding custom college, lab, or intranet portals." } else { "支持后续扩展更多学院、教务科研或内网系统分类。" }));
                    }
                    for (r_idx, (sid, name, is_pinned)) in rows.into_iter().enumerate() {
                        let (open_id, pin_id) = (sid.clone(), sid);
                        let pin_label = if is_pinned { if en { "Pinned" } else { "已固定" } } else if en { "Pin" } else { "固定" };
                        let (pin_border, pin_bg, pin_fg) = if is_pinned { (accent_hex, 0xf6eaec, accent_hex) } else { (0xe4dfd7, 0xfcfbf9, 0x5c5852) };
                        body = body.child(
                            div().h(px(34.0)).px_3().rounded_sm().bg(rgb(0xf5f2ec)).border_1().border_color(rgb(0xe4dfd7)).flex().items_center().gap_2()
                                .child(div().flex_1().min_w_0().overflow_hidden().text_xs().font_weight(FontWeight::MEDIUM).text_color(rgb(0x1f1e1c)).child(name))
                                .child(div().id(SharedString::from(format!("pin-{cat_idx}-{r_idx}"))).w(px(56.0)).h(px(24.0)).rounded_sm().border_1().border_color(rgb(pin_border)).bg(rgb(pin_bg)).text_color(rgb(pin_fg)).text_xs().flex().items_center().justify_center().cursor_pointer().child(pin_label).on_click(cx.listener(move |this, _, _, cx| { this.vm.toggle_menu_bar_pin(&pin_id); this.tray_bridge.sync_from_vm(&this.vm); cx.notify(); })))
                                .child(div().id(SharedString::from(format!("open-{cat_idx}-{r_idx}"))).w(px(48.0)).h(px(24.0)).rounded_sm().bg(rgb(0x1f1e1c)).text_color(rgb(0xffffff)).text_xs().font_weight(FontWeight::MEDIUM).flex().items_center().justify_center().cursor_pointer().child(if en { "Open" } else { "打开" }).on_click(cx.listener(move |this, _, _, cx| { this.on_shortcut_clicked(&open_id); cx.notify(); }))),
                        );
                    }
                    group = group.child(body);
                }
                accordion = accordion.child(group);
            }

            let right_rail = div().flex_1().h_full().p_3p5().rounded_lg().bg(rgb(0xfcfbf9)).border_1().border_color(rgb(0xe4dfd7)).flex().flex_col().gap_2().overflow_hidden()
                .child(div().h(px(20.0)).flex().items_center().justify_between().child(div().text_xs().font_weight(FontWeight::SEMIBOLD).child(if en { "Campus Services (Collapsible Categories)" } else { "校内常用服务（点击分类折叠展开）" })).child(div().text_xs().text_color(rgb(0x8c8782)).child(if en { "3 categories · 13 items" } else { "共 3 类 · 13 项" })))
                .child(accordion);

            div().flex_1().min_h_0().my_3().flex().gap_3p5().child(left_rail).child(right_rail).into_any_element()
        };

        let footer = div().h(px(26.0)).pt_2().border_t_1().border_color(rgb(0xe4dfd7)).flex().items_center().justify_between()
            .child(div().flex().items_center().gap_4().child(div().id("guide-link").cursor_pointer().text_xs().text_color(rgb(0x5c5852)).child(if en { "Campus Guide" } else { "学校使用指南" }).on_click(cx.listener(|this, _, _, _| { this.actor.send(SessionCommand::OpenBrowserUrl(GUIDE_URL.to_string())); }))).child(div().id("footer-repair-btn").cursor_pointer().text_xs().font_weight(FontWeight::MEDIUM).text_color(accent).child(if en { "Auto Repair" } else { "自动修复" }).on_click(cx.listener(|this, _, _, _| { this.actor.send(SessionCommand::Repair); }))).child(div().id("footer-settings-btn").cursor_pointer().text_xs().text_color(rgb(0x5c5852)).child(if in_settings { if en { "Back to Workbench" } else { "返回工作台" } } else if en { "Settings" } else { "偏好设置" }).on_click(cx.listener(|this, _, _, cx| { this.vm.toggle_settings(); cx.notify(); }))))
            .child(div().text_xs().text_color(rgb(0x8c8782)).child(ABOUT_ATTRIBUTION_TEXT));

        div().size_full().flex().flex_col().px_5().py_4().bg(rgb(0xf6f4f0)).text_color(rgb(0x1f1e1c)).child(header).child(body).child(footer)
    }
}

/// Launches the native GPUI-Kit desktop application and binds `securelink://` URL events.
pub fn run_desktop_app(actor: TunnelHandle, events: Receiver<SessionEvent>) {
    let app = gpui_kit::application();
    let (ui_tx, ui_rx) = async_util::unbounded::<SessionEvent>();
    let reopen_tx = ui_tx.clone();
    app.on_reopen(move |cx: &mut App| {
        cx.activate(true);
        let _ = reopen_tx.try_send(SessionEvent::TrayAction(TrayAction::ShowWindow));
    });
    let url_actor = actor.clone();
    app.on_open_urls(move |urls| {
        for raw in urls {
            if let Some(valid) = validate_securelink_callback_url(&raw) {
                url_actor.send(SessionCommand::HandleCallbackUrl(valid));
            }
        }
    });

    app.run(move |cx: &mut App| {
        gpui_kit::init(cx);
        let fwd_tx = ui_tx.clone();
        std::thread::spawn(move || {
            while let Ok(evt) = events.recv_blocking() {
                let _ = fwd_tx.try_send(evt);
            }
        });
        let initial_vm = WorkbenchViewModel::new();
        apply_dock_policy(initial_vm.shell_presence, cx);
        let bridge = MenuBarBridge::spawn(ui_tx.clone(), &initial_vm);
        let (quit_actor, quit_bridge) = (actor.clone(), bridge.clone());
        cx.on_action(move |_: &Quit, cx: &mut App| {
            quit_bridge.shutdown();
            quit_actor.send(SessionCommand::Shutdown);
            cx.quit();
        });
        let settings_tx = ui_tx.clone();
        cx.on_action(move |_: &OpenSettings, _: &mut App| {
            let _ = settings_tx.try_send(SessionEvent::TrayAction(TrayAction::OpenSettings));
        });
        let upd_tx = ui_tx;
        cx.on_action(move |_: &CheckUpdates, _: &mut App| {
            let _ = upd_tx.try_send(SessionEvent::TrayAction(TrayAction::OpenSettings));
        });
        cx.set_menus(vec![Menu {
            name: APP_CHINESE_NAME.into(),
            items: vec![
                MenuItem::action("偏好设置…", OpenSettings),
                MenuItem::action("检查更新…", CheckUpdates),
                MenuItem::separator(),
                MenuItem::action("退出 荔连", Quit),
            ],
            disabled: false,
        }]);

        let window_opts = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(Bounds::centered(None, size(px(740.0), px(540.0)), cx))),
            ..WindowOptions::default()
        };
        let (win_actor, win_bridge) = (actor.clone(), bridge.clone());
        let (_, view) = gpui_kit::open_window(window_opts, cx, |_, cx| cx.new(|_| WorkbenchWindow::with_bridge(win_actor, win_bridge)))
            .expect("failed to open SZU SecureLink GPUI window");

        cx.spawn(async move |cx: &mut AsyncApp| {
            while let Ok(evt) = ui_rx.recv().await {
                if matches!(evt, SessionEvent::TrayAction(TrayAction::Quit)) {
                    bridge.shutdown();
                    actor.send(SessionCommand::Shutdown);
                    cx.update(|cx| cx.quit());
                    break;
                }
                let is_show = matches!(evt, SessionEvent::TrayAction(TrayAction::ShowWindow | TrayAction::OpenSettings));
                let is_presence = matches!(evt, SessionEvent::TrayAction(TrayAction::ToggleDock | TrayAction::ToggleMenuBar));
                let view_for_reopen = view.clone();
                view.update(cx, |this: &mut WorkbenchWindow, cx| {
                    this.apply_session_event(evt);
                    if is_presence {
                        apply_dock_policy(this.vm.shell_presence, cx);
                    }
                    if is_show {
                        if cx.windows().is_empty() {
                            let opts = WindowOptions {
                                window_bounds: Some(WindowBounds::Windowed(Bounds::centered(None, size(px(740.0), px(540.0)), cx))),
                                ..WindowOptions::default()
                            };
                            let _ = gpui_kit::open_window(opts, cx, move |_, _| view_for_reopen);
                        }
                        cx.activate(true);
                    }
                    cx.notify();
                });
            }
        })
        .detach();
    });
}
