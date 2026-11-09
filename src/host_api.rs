//! Versioned JSON host contract between the pure-Rust core and native platform UI (`#![forbid(unsafe_code)]`).
//!
//! Mirrors `metasequoiaime/msime`'s `crates/host-api` boundary:
//! - Requests are bounded UTF-8 JSON objects (`{"op":"..."}`) up to [`MAX_HOST_REQUEST_BYTES`].
//! - Responses use a uniform envelope: `{"ok":true,"value":...}` or `{"ok":false,"error":"..."}`.
//! - Static explanatory descriptions live in `info_tip` (rendered behind a `?` popover button in AppKit),
//!   whereas `inline_detail` is reserved strictly for live runtime status, current values, or errors.

#![forbid(unsafe_code)]

use crate::gpui_window::{GUIDE_URL, WorkbenchWindow};
use crate::gpui_workbench::{
    ABOUT_ATTRIBUTION_TEXT, APP_CHINESE_NAME, APP_VERSION, ConnectionStatus, UiLocale, UiScheme,
    WorkbenchRoute,
};
use crate::shortcuts::ShortcutCategory;
use crate::sparkle::format_route_count;
use crate::tray_bridge::{ShellPresence, TrayAction};
use crate::tunnel_actor::{SessionCommand, SessionEvent, validate_securelink_callback_url};
use serde_json::{Value, json};

/// Version of the `szu-securelink` native host JSON ABI.
pub const HOST_ABI_VERSION: u32 = 1;

/// Maximum UTF-8 byte length accepted for a single host request payload.
pub const MAX_HOST_REQUEST_BYTES: usize = 65_536;

/// Wraps a JSON value in a successful `{"ok":true,"value":...}` envelope.
#[must_use]
pub fn ok_envelope(value: Value) -> String {
    json!({ "ok": true, "value": value }).to_string()
}

/// Wraps an error message in a failed `{"ok":false,"error":"..."}` envelope.
#[must_use]
pub fn err_envelope(error: &str) -> String {
    json!({ "ok": false, "error": error }).to_string()
}

fn build_status_snapshot(win: &WorkbenchWindow, en: bool) -> Value {
    let tip = if en {
        "Uses Shenzhen University CAS pre-authentication and an isolated utun data session with 133 campus routes and in-tunnel DNS 192.168.247.6."
    } else {
        "采用深大 CAS 统一身份预认证与独立 utun 零信任隧道，自动装载 133 条校内路由与内网 DNS 192.168.247.6，不劫持校外公网流量。"
    };
    match &win.vm.status {
        ConnectionStatus::Disconnected => {
            let r = format_route_count(133, en).unwrap_or_default();
            json!({
                "kind": "disconnected", "badge": if en { "Not Connected" } else { "当前未连接" },
                "title": if en { "Not Connected to Campus Network" } else { "未连接深圳大学校园网" },
                "inline_detail": if en { format!("Ready · Campus DNS 192.168.247.6 staged ({r})") } else { format!("就绪 · 预置内网 DNS 192.168.247.6（{r}）") },
                "info_tip": tip, "primary_button": if en { "Connect Campus Network" } else { "立即连接校园网" },
                "interface": Value::Null, "virtual_ipv4": Value::Null, "dns_server": "192.168.247.6",
            })
        }
        ConnectionStatus::Connecting { phase } => json!({
            "kind": "connecting", "badge": if en { "Connecting…" } else { "正在连接中…" },
            "title": if en { "Establishing Campus Tunnel…" } else { "正在建立校园网隧道…" },
            "inline_detail": phase, "info_tip": tip, "primary_button": if en { "Cancel" } else { "取消连接" },
            "interface": Value::Null, "virtual_ipv4": Value::Null, "dns_server": "192.168.247.6",
        }),
        ConnectionStatus::Connected { interface, virtual_ipv4, dns_server } => {
            let r = format_route_count(129, en).unwrap_or_default();
            json!({
                "kind": "connected", "badge": if en { "Connected" } else { "校园网已连接" },
                "title": if en { "Campus Network Connected" } else { "已连接深圳大学校园网" },
                "inline_detail": if en { format!("{interface} · {virtual_ipv4} · DNS {dns_server} ({r})") } else { format!("接口 {interface} · 虚拟IP {virtual_ipv4} · DNS {dns_server}（{r}）") },
                "info_tip": tip, "primary_button": if en { "Disconnect Campus Network" } else { "断开校园网连接" },
                "interface": interface, "virtual_ipv4": virtual_ipv4, "dns_server": dns_server,
            })
        }
    }
}

fn build_settings_rows(win: &WorkbenchWindow, en: bool) -> Value {
    let helper_routes = format_route_count(133, en).unwrap_or_default();
    let row = |key: &str, title: &str, inline: Option<String>, tip: &str| {
        json!({ "key": key, "title": title, "inline_detail": inline, "info_tip": tip })
    };
    json!([
        row(
            "shell_presence",
            if en { "System Presence Mode" } else { "系统常驻图标模式" },
            None,
            if en {
                "Controls Dock and Menu Bar icon visibility. At least one entry point stays visible so closing the window never strands the background process."
            } else {
                "控制程序坞（Dock）与右上角菜单栏图标的显示方式；系统强制至少保留一处可见入口，关闭窗口后点击图标即可重新唤起工作台。"
            },
        ),
        row(
            "launch_at_login",
            if en { "Launch at macOS Login" } else { "开机自动启动荔连" },
            None,
            if en {
                "Installs or removes ~/Library/LaunchAgents/local.szu.securelink.login.plist for the current macOS user."
            } else {
                "在当前用户目录写入或移除 ~/Library/LaunchAgents/local.szu.securelink.login.plist，登录 macOS 时自动在后台就绪。"
            },
        ),
        row(
            "locale",
            if en { "Interface Language" } else { "界面显示语言" },
            None,
            if en {
                "Switches all native workbench, settings, and menu bar labels between Simplified Chinese and English immediately."
            } else {
                "立即切换主工作台、偏好设置与菜单栏托盘的中英文界面文案。"
            },
        ),
        row(
            "scheme",
            if en { "Accent Color Theme" } else { "主题强调色" },
            None,
            if en {
                "Selects the traditional Chinese single-accent tint (SZU Lychee Crimson, Bamboo Academy Green, or Pine Indigo) while respecting macOS Aqua and Dark Aqua appearance."
            } else {
                "选择中国传统单色强调色（深大荔枝红、竹院青、松烟靛），同时自动跟随 macOS 浅色（Aqua）与深色（Dark Aqua）外观。"
            },
        ),
        row(
            "auto_check_updates",
            if en { "Automatic Update Checks" } else { "自动检查版本更新" },
            None,
            if en {
                "Periodically checks the Ed25519-signed Sparkle 2.x appcast feed in the background."
            } else {
                "后台定期向 Ed25519 签名校验的 Sparkle 2.x 更新源查询新版本。"
            },
        ),
        row(
            "update_status",
            if en { "Software Version & Sparkle Status" } else { "当前版本与更新状态" },
            Some(win.vm.update_status.clone()),
            if en {
                "All update packages require Sparkle Ed25519 signature verification and HTTPS transport before installation."
            } else {
                "所有更新包均须通过 Sparkle Ed25519 数字签名与 HTTPS 传输校验后方可安装。"
            },
        ),
        row(
            "tunnel_helper",
            if en { "Zero-Trust Tunnel & Route Helper" } else { "零信任隧道与特权路由助手" },
            Some(if en {
                format!("DNS 192.168.247.6 · {helper_routes} · Safe Rust Core")
            } else {
                format!("内网 DNS 192.168.247.6 · {helper_routes} · 100% Safe Rust 内核")
            }),
            if en {
                "Resets stale utun routes and scoped campus DNS resolvers if campus portals fail to load after sleep/wake."
            } else {
                "当休眠唤醒或网络切换导致校内域名无法解析时，可一键清理残留路由并重建零信任隧道。"
            },
        ),
    ])
}

/// Builds the complete native AppKit view-state snapshot from [`WorkbenchWindow`].
#[must_use]
pub fn build_native_snapshot(win: &WorkbenchWindow) -> Value {
    let vm = &win.vm;
    let en = vm.locale == UiLocale::EnUs;
    let route_str = if vm.route == WorkbenchRoute::Settings { "settings" } else { "workbench" };
    let locale_str = if en { "en-US" } else { "zh-CN" };
    let (scheme_str, accent_hex) = match vm.scheme {
        UiScheme::CrimsonSplit => ("crimson", 0x8c2232u32),
        UiScheme::BambooColumn => ("bamboo", 0x2b5f4e),
        UiScheme::IndigoTrayFirst => ("indigo", 0x2e4b6c),
    };
    let pins: Vec<Value> = vm
        .menu_bar_shortcuts()
        .into_iter()
        .enumerate()
        .map(|(slot, s)| json!({ "slot": slot, "id": s.id, "name": s.name, "subtitle": s.subtitle, "url": s.url }))
        .collect();
    let categories: Vec<Value> = ShortcutCategory::ALL
        .into_iter()
        .enumerate()
        .map(|(cat_idx, cat)| {
            let items: Vec<Value> = vm
                .shortcuts_in_category(cat)
                .into_iter()
                .map(|s| json!({
                    "id": s.id, "name": s.name, "subtitle": s.subtitle, "url": s.url,
                    "is_pinned": vm.is_pinned_to_menu_bar(&s.id), "is_favorite": s.is_favorite, "is_built_in": s.is_built_in,
                }))
                .collect();
            let cat_tip = match cat {
                ShortcutCategory::CampusAffairs => if en {
                    "High-frequency SZU intranet portals. Clicking any item while disconnected automatically connects first."
                } else {
                    "深大高频校内办事与财务报账入口；未连接校园网时直接点击任意服务，会自动唤起连接并在隧道就绪后打开。"
                },
                ShortcutCategory::AcademicDatabases => if en {
                    "Law and academic databases routed through SZU campus CARSI / EZProxy."
                } else {
                    "经由深大校园网 CARSI / EZProxy 访问的法学与综合学术数据库。"
                },
                ShortcutCategory::Custom => if en { "User-added intranet URLs." } else { "用户自定义的学院、实验室或内网直达入口。" },
            };
            json!({ "index": cat_idx, "title": cat.title(en), "info_tip": cat_tip, "collapsed": vm.is_category_collapsed(cat), "item_count": items.len(), "items": items })
        })
        .collect();

    json!({
        "abi_version": HOST_ABI_VERSION, "route": route_str, "locale": locale_str,
        "scheme": scheme_str, "accent_hex": accent_hex,
        "shell_presence": vm.shell_presence.as_token(),
        "shows_dock": vm.shell_presence.shows_dock(), "shows_menu_bar": vm.shell_presence.shows_menu_bar(),
        "launch_at_login": vm.launch_at_login, "auto_check_updates": vm.sparkle_config.automatic_checks,
        "update_status": vm.update_status, "app_version": APP_VERSION,
        "app_chinese_name": APP_CHINESE_NAME, "attribution": ABOUT_ATTRIBUTION_TEXT,
        "guide_url": GUIDE_URL, "show_network_details": win.show_network_details,
        "search_query": vm.search_query,
        "pins_info_tip": if en {
            "Pin up to 4 frequent campus portals to the top-right macOS menu bar for 1-click access."
        } else {
            "可在右上角 macOS 菜单栏固定 4 个最常用的校内服务槽位，点击右侧服务行的「固定」即可轮换槽位。"
        },
        "status": build_status_snapshot(win, en),
        "menu_bar_pins": pins, "categories": categories, "settings_rows": build_settings_rows(win, en),
    })
}

/// Dispatches a bounded UTF-8 JSON request against [`WorkbenchWindow`] and returns a JSON envelope.
#[must_use]
pub fn dispatch_window_request(win: &mut WorkbenchWindow, request_bytes: &[u8]) -> String {
    if request_bytes.is_empty() || request_bytes.len() > MAX_HOST_REQUEST_BYTES {
        return err_envelope("request payload size out of bounds");
    }
    let Ok(req) = serde_json::from_slice::<Value>(request_bytes) else {
        return err_envelope("invalid JSON request");
    };
    let Some(op) = req.get("op").and_then(Value::as_str) else {
        return err_envelope("missing 'op' field");
    };
    let str_arg = |k: &str| req.get(k).and_then(Value::as_str);

    match op {
        "snapshot" => {}
        "toggle_connect" => { win.actor.send(SessionCommand::ToggleConnect); }
        "repair" => { win.actor.send(SessionCommand::Repair); }
        "disconnect" => { win.actor.send(SessionCommand::Disconnect); }
        "toggle_network_details" => win.show_network_details = !win.show_network_details,
        "toggle_settings" => win.vm.toggle_settings(),
        "set_route" => {
            let Some(r) = str_arg("route") else { return err_envelope("missing 'route'"); };
            win.vm.route = if r == "settings" { WorkbenchRoute::Settings } else { WorkbenchRoute::Workbench };
        }
        "activate_shortcut" => {
            let Some(id) = str_arg("id") else { return err_envelope("missing 'id'"); };
            win.on_shortcut_clicked(id);
        }
        "toggle_pin" => {
            let Some(id) = str_arg("id") else { return err_envelope("missing 'id'"); };
            if !win.vm.toggle_menu_bar_pin(id) { return err_envelope("unknown shortcut id"); }
            win.tray_bridge.sync_from_vm(&win.vm);
        }
        "toggle_category" => {
            let Some(idx) = req.get("index").and_then(Value::as_u64) else { return err_envelope("missing 'index'"); };
            let Some(&cat) = ShortcutCategory::ALL.get(idx as usize) else { return err_envelope("category index out of range"); };
            win.vm.toggle_category(cat);
        }
        "set_search_query" => {
            win.vm.search_query = str_arg("query").unwrap_or_default().chars().take(64).collect();
        }
        "add_custom_shortcut" => {
            if !win.vm.add_custom_shortcut(str_arg("name").unwrap_or_default(), str_arg("subtitle").unwrap_or_default(), str_arg("url").unwrap_or_default()) {
                return err_envelope("invalid custom shortcut name or URL");
            }
        }
        "set_shell_presence" => {
            let Some(token) = str_arg("mode") else { return err_envelope("missing 'mode'"); };
            win.vm.shell_presence = ShellPresence::from_token(token);
            win.vm.save_preferences();
            win.tray_bridge.sync_from_vm(&win.vm);
        }
        "toggle_dock" => win.apply_session_event(SessionEvent::TrayAction(TrayAction::ToggleDock)),
        "toggle_menu_bar" => win.apply_session_event(SessionEvent::TrayAction(TrayAction::ToggleMenuBar)),
        "set_launch_at_login" => {
            let Some(on) = req.get("enabled").and_then(Value::as_bool) else { return err_envelope("missing 'enabled'"); };
            win.vm.set_launch_at_login(on);
        }
        "set_auto_check_updates" => {
            let Some(on) = req.get("enabled").and_then(Value::as_bool) else { return err_envelope("missing 'enabled'"); };
            win.vm.set_auto_check_updates(on);
        }
        "check_for_updates" => win.vm.check_for_updates(),
        "set_locale" => {
            let Some(loc) = str_arg("locale") else { return err_envelope("missing 'locale'"); };
            win.vm.set_locale(if loc == "en-US" { UiLocale::EnUs } else { UiLocale::ZhCn });
            win.tray_bridge.sync_from_vm(&win.vm);
        }
        "set_scheme" => {
            let Some(sc) = str_arg("scheme") else { return err_envelope("missing 'scheme'"); };
            win.vm.set_scheme(match sc {
                "bamboo" => UiScheme::BambooColumn,
                "indigo" => UiScheme::IndigoTrayFirst,
                _ => UiScheme::CrimsonSplit,
            });
        }
        "open_guide" => { win.actor.send(SessionCommand::OpenBrowserUrl(GUIDE_URL.to_string())); }
        "handle_callback_url" => {
            let Some(raw) = str_arg("url") else { return err_envelope("missing 'url'"); };
            let Some(valid) = validate_securelink_callback_url(raw) else { return err_envelope("invalid securelink callback URL"); };
            win.actor.send(SessionCommand::HandleCallbackUrl(valid));
        }
        _ => return err_envelope("unsupported host operation"),
    }
    ok_envelope(build_native_snapshot(win))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel_actor::TunnelHandle;
    use szu_host_macos::{CLIENT_ABI_VERSION, NativeHostCallbacks, c_abi_roundtrip_for_test};

    #[test]
    fn host_api_enforces_info_tip_separation_and_c_abi_roundtrip() {
        let (handle, _rx) = TunnelHandle::channel();
        let mut win = WorkbenchWindow::new(handle);
        let snap = build_native_snapshot(&win);
        assert_eq!(snap["abi_version"], HOST_ABI_VERSION);
        let rows = snap["settings_rows"].as_array().expect("settings_rows array");
        for row in rows {
            let key = row["key"].as_str().unwrap_or_default();
            let tip = row["info_tip"].as_str().unwrap_or_default();
            assert!(!tip.is_empty(), "every settings row must provide an info_tip for the ? popover");
            match key {
                "update_status" | "tunnel_helper" => {
                    assert!(row["inline_detail"].as_str().is_some_and(|s| !s.is_empty()));
                }
                _ => {
                    assert!(row["inline_detail"].is_null(), "static description for {key} must stay behind ?, not inline");
                }
            }
        }

        let r1: Value = serde_json::from_str(&dispatch_window_request(&mut win, br#"{"op":"set_locale","locale":"en-US"}"#)).unwrap();
        assert_eq!(r1["ok"], true);
        assert_eq!(r1["value"]["locale"], "en-US");

        let r2: Value = serde_json::from_str(&dispatch_window_request(&mut win, br#"{"op":"set_shell_presence","mode":"menubar_only"}"#)).unwrap();
        assert_eq!(r2["ok"], true);
        assert_eq!(r2["value"]["shows_dock"], false);
        assert_eq!(r2["value"]["shows_menu_bar"], true);

        let err: Value = serde_json::from_str(&dispatch_window_request(&mut win, br#"{"op":"unknown_op"}"#)).unwrap();
        assert_eq!(err["ok"], false);

        let (h2, _rx2) = TunnelHandle::channel();
        let mut abi_win = WorkbenchWindow::new(h2);
        let init_snap = ok_envelope(build_native_snapshot(&abi_win));
        let callbacks = NativeHostCallbacks {
            init_on_main_thread: Box::new(move || init_snap.clone()),
            dispatch: Box::new(move |req| dispatch_window_request(&mut abi_win, req)),
            poll_events: Box::new(|| None),
            shutdown: Box::new(|| {}),
        };
        let (ver, init_out, disp_out) = c_abi_roundtrip_for_test(callbacks, br#"{"op":"set_route","route":"settings"}"#);
        assert_eq!(ver, CLIENT_ABI_VERSION);
        let parsed_init: Value = serde_json::from_str(&init_out).unwrap();
        assert_eq!(parsed_init["ok"], true);
        let parsed_disp: Value = serde_json::from_str(&disp_out).unwrap();
        assert_eq!(parsed_disp["ok"], true);
        assert_eq!(parsed_disp["value"]["route"], "settings");
    }
}
