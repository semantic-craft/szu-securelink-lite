//! Unit and property-based verification tests for `szu-securelink-rs`.

use crate::confusion::{
    encode_standard_frame, encode_standard_frame_into, CodecError, StreamDecoder, MAX_PAYLOAD,
};
use crate::ctrl::{exact_domain, parse_addresses, parse_options, CtrlFailure, Effects, PacketDecision};
use crate::dns::{lifetime, normalize_domain, parse_reply, Question, TYPE_A, TYPE_AAAA};
use crate::gpui_workbench::{
    ConnectionStatus, MenuBarIconGeometry, ShortcutLaunchOutcome, UiLocale, UiScheme,
    WorkbenchViewModel, ABOUT_ATTRIBUTION_TEXT, APP_CHINESE_NAME, APP_VERSION,
    DEFAULT_MENU_BAR_PIN_IDS,
};
use crate::ip_math::{classify, mask_bytes, network_contains, parse_ipv4, rejected_for_assignment};
use crate::shaper::{effective_limit, is_count_exempt, Action, Packet, WindowQueue};
use crate::shortcuts::{default_shortcuts, extract_hosts, valid_url};
use crate::sparkle::{
    format_duration_human, format_latency_ms, format_package_size_mb, format_route_count,
    is_newer_version, validate_ed25519_signature, SparkleAppcastItem, SparkleConfig, SparkleError,
    SparkleUpdateState,
};
use crate::tunnel_actor::{
    parse_engine_active_line, validate_securelink_callback_url, EngineActiveNotice,
};
use crate::{run_seed_safe, run_seed_soa, SplitMix64};

#[test]
fn test_confusion_encode_decode_roundtrip_and_bounds() {
    assert_eq!(encode_standard_frame(&[0x00]), Err(CodecError::InvalidLength));
    assert_eq!(encode_standard_frame(&[0x00, 0x05, 1, 2]), Err(CodecError::HeaderMismatch));

    let payload = [0x00, 0x04, 0xde, 0xad, 0xbe, 0xef];
    let wire = encode_standard_frame(&payload).unwrap();
    assert_eq!(wire, vec![0x00, 0x06, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef]);

    let mut decoder = StreamDecoder::new();
    for &b in &wire[..wire.len() - 1] {
        assert!(decoder.feed(&[b]).unwrap().is_empty());
    }
    assert_eq!(decoder.pending_bytes(), wire.len() - 1);
    let out = decoder.feed(&wire[wire.len() - 1..]).unwrap();
    assert_eq!(out, payload);
    assert_eq!(decoder.pending_bytes(), 0);

    // Malformed wire frame (< 2 outer length) resets decoder state.
    assert_eq!(decoder.feed(&[0x00, 0x01]), Err(CodecError::HeaderMismatch));
    assert_eq!(decoder.pending_bytes(), 0);
}

#[test]
fn test_confusion_property_fuzz_1000_frames() {
    let mut rng = SplitMix64::new(0x1234_5678);
    let mut decoder = StreamDecoder::new();
    let mut wire = Vec::new();
    let mut out1 = Vec::new();
    let mut out2 = Vec::new();
    for _ in 0..500 {
        let len = (rng.next_u64() as usize) % (MAX_PAYLOAD.min(512));
        let mut frame = vec![0u8; len + 2];
        frame[0] = ((len >> 8) & 0xff) as u8;
        frame[1] = (len & 0xff) as u8;
        for b in &mut frame[2..] {
            *b = rng.next_u64() as u8;
        }
        encode_standard_frame_into(&frame, &mut wire).unwrap();
        let split = 1 + (rng.next_u64() as usize % (wire.len() - 1));
        decoder.feed_into(&wire[..split], &mut out1).unwrap();
        decoder.feed_into(&wire[split..], &mut out2).unwrap();
        assert!(out1.is_empty());
        assert_eq!(out2, frame);
    }
}

#[test]
fn test_shaper_window_queue_and_probe_exemption() {
    assert_eq!(effective_limit(0), 0);
    assert_eq!(effective_limit(-5), 100);
    assert_eq!(effective_limit(2048), 2048);
    assert!(WindowQueue::new(1000, 0, 0, 1024).is_err());

    let mut q = WindowQueue::new(1000, 100, 4, 4096).unwrap();
    let pkt = |id, bytes| Packet { id, bytes, count_exempt: false };
    assert_eq!(q.submit(pkt(1, 0), 100).action, Action::DropInvalidPacket);
    assert_eq!(q.submit(pkt(2, 600), 100).action, Action::Send);
    assert_eq!(q.submit(pkt(3, 600), 110).action, Action::Queued);
    assert!(q.deadline().is_some());
    assert!(q.poll(120).is_empty());
    let released = q.poll(2000);
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].action, Action::Send);

    let cancelled = q.cancel();
    assert!(cancelled.is_empty());
    assert_eq!(q.submit(pkt(4, 100), 2010).action, Action::DropStopped);
    q.restart(2020).unwrap();

    let mut probe = vec![0u8; 50];
    probe[4 + 2] = 0;
    probe[4 + 3] = 46;
    probe[4 + 9] = 1;
    probe[4 + 20] = 8;
    probe[4 + 36..4 + 46].copy_from_slice(b"Securelink");
    assert!(is_count_exempt(&probe, true));
    assert!(!is_count_exempt(&probe[..10], true));
}

#[test]
fn test_dns_wire_parser_cname_edns_and_rejections() {
    assert_eq!(normalize_domain("Lib.SZU.edu.cn.").unwrap(), "lib.szu.edu.cn");
    assert!(normalize_domain("").is_err());
    assert_eq!(lifetime(120), 120);
    assert_eq!(lifetime(0x8000_0000), 0);

    // Multi-record packet: Question (a.szu.edu.cn) -> CNAME (b.szu.edu.cn, TTL 100) -> A (192.168.240.9, TTL 300)
    let pkt: Vec<u8> = vec![
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        // Question at offset 12: 1 'a' 3 "szu" 3 "edu" 2 "cn" 0 (14 bytes -> ends at 26)
        1, b'a', 3, b's', b'z', b'u', 3, b'e', b'd', b'u', 2, b'c', b'n', 0,
        0x00, 0x01, 0x00, 0x01, // QTYPE=A, QCLASS=IN (ends at 30)
        // Answer 1: owner = ptr 12 (0xc00c), TYPE=CNAME (5), CLASS=IN (1), TTL=100, RDLEN=4, RDATA: 1 'b' ptr 14 (0xc00e)
        0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 100, 0x00, 0x04,
        1, b'b', 0xc0, 0x0e, // RDATA starts at offset 42
        // Answer 2: owner = ptr 42 (0xc02a -> b.szu.edu.cn), TYPE=A (1), CLASS=IN (1), TTL=300, RDLEN=4, RDATA=192.168.240.9
        0xc0, 42, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04,
        192, 168, 240, 9,
    ];
    let reply = parse_reply(
        &pkt,
        &Question {
            id: 0x1234,
            name: "A.SZU.EDU.CN",
            qtype: TYPE_A,
        },
    )
    .unwrap();
    assert_eq!(reply.addresses.len(), 1);
    assert_eq!(&reply.addresses[0].bytes[..4], &[192, 168, 240, 9]);
    assert_eq!(reply.addresses[0].ttl, 100); // clamped to CNAME TTL

    // Wrong ID or type rejected
    assert!(parse_reply(
        &pkt,
        &Question {
            id: 0x9999,
            name: "a.szu.edu.cn",
            qtype: TYPE_A
        }
    )
    .is_err());
    assert!(parse_reply(
        &pkt,
        &Question {
            id: 0x1234,
            name: "a.szu.edu.cn",
            qtype: TYPE_AAAA
        }
    )
    .is_err());
}

#[test]
fn test_ctrl_policy_and_effects_classifier() {
    assert!(exact_domain("cwpt.szu.edu.cn"));
    assert!(!exact_domain("cwpt-.szu.edu.cn"));
    assert_eq!(
        parse_addresses("192.168.240.166;172.31.7.46").unwrap(),
        vec!["192.168.240.166", "172.31.7.46"]
    );
    assert_eq!(parse_addresses(""), Err(CtrlFailure::UnsupportedAddress));
    assert_eq!(parse_addresses("127.0.0.1"), Err(CtrlFailure::UnsupportedAddress));
    assert_eq!(parse_addresses("0.0.0.0"), Err(CtrlFailure::UnsupportedAddress));

    let opts = vec![
        vec!["ctrl", "domain:cwpt.szu.edu.cn sourceIp:192.168.240.166;172.31.7.46"],
        vec!["ctrl", "domain:cwpt.szu.edu.cn sourceIp:192.168.240.166"],
    ];
    let snap = parse_options(&opts).unwrap();
    assert_eq!(snap.mappings.len(), 1);
    assert_eq!(snap.duplicate_domains, 1);

    let mut effects = Effects::new();
    effects.replace(&opts).unwrap();
    assert_eq!(effects.initial_routes().len(), 2);

    let allowed_pkt: [u8; 20] = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 1, 1, 105, 34, 192, 168, 240, 166,
    ];
    let blocked_pkt: [u8; 20] = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 1, 1, 105, 34, 8, 8, 8, 8,
    ];
    assert_eq!(effects.classify(&allowed_pkt), PacketDecision::DestinationAllowed);
    assert_eq!(effects.classify(&blocked_pkt), PacketDecision::NotCovered);
    assert_eq!(effects.classify(&[0x60]), PacketDecision::UnsupportedFamily);
    assert_eq!(effects.classify(&[]), PacketDecision::InvalidIpv4);
}

#[test]
fn test_ip_math_and_shortcuts_and_gpui_workbench() {
    let ip = parse_ipv4("192.168.247.6").unwrap();
    assert!(!rejected_for_assignment(&ip));
    assert!(classify(&parse_ipv4("127.0.0.1").unwrap()).loopback);
    assert!(parse_ipv4("192.168.01.1").is_none());

    let net = parse_ipv4("192.168.240.0").unwrap();
    assert!(network_contains(&net.bytes, 20, &ip.bytes));
    assert_eq!(mask_bytes(&ip.bytes, -5), [0u8; 16]);

    let shortcuts = default_shortcuts();
    assert_eq!(shortcuts.len(), 13);
    assert!(shortcuts.iter().any(|s| s.id == "szu-reimburse-system"
        && s.url == "http://172.31.134.31/wsyy/frame_container.aspx"
        && s.is_favorite));
    for s in &shortcuts {
        assert!(valid_url(&s.url));
    }
    let hosts = extract_hosts(&shortcuts);
    for required in [
        "authserver.szu.edu.cn", "cwpt.szu.edu.cn", "fsso.cnki.net", "idp.szu.edu.cn",
        "heinonline.org", "oup-sp.sams-sigma.com", "www.cambridge.org", "ezproxy.lib.szu.edu.cn",
        "www.pkulaw.com", "accproxy.lib.szu.edu.cn", "www.webofscience.com",
        "signon.thomsonreuters.com", "www.westlaw.com",
    ] {
        assert!(hosts.contains(&required.to_string()), "missing {required}");
    }

    let mut vm = WorkbenchViewModel::new();
    vm.set_connected("utun4", "1.1.105.34");
    assert!(matches!(vm.status, ConnectionStatus::Connected { .. }));
    assert!(vm.toggle_favorite("szu-westlaw"));
    assert!(vm.add_custom_shortcut("教务部", "", "https://jwb.szu.edu.cn/"));
    assert!(vm.in_tunnel_resolve_domains().len() <= 32);
    let tree = vm.render_gpui_tree();
    assert_eq!(tree.kind, "Window");
    assert!(tree.label.contains("荔连"));
    assert_eq!(APP_CHINESE_NAME, "荔连");
    assert_eq!(tree.children.len(), 3);
    assert_eq!(tree.children[2].kind, "AboutFooter");
    assert_eq!(tree.children[2].detail, "深圳大学法律人工智能实训实验室");
    assert_eq!(ABOUT_ATTRIBUTION_TEXT, "深圳大学法律人工智能实训实验室");
    assert_eq!(APP_VERSION, "0.2.1");

    vm.check_for_updates();
    vm.toggle_settings();
    let tree_with_settings = vm.render_gpui_tree();
    assert_eq!(tree_with_settings.children.len(), 4);
    assert_eq!(tree_with_settings.children[3].kind, "SettingsPage");
    assert_eq!(tree_with_settings.children[3].detail, "深圳大学法律人工智能实训实验室");

    // Verify safe and SoA kernels produce identical results across 10 seeds
    for s in 0..10 {
        let a = run_seed_safe(s, 200);
        let b = run_seed_soa(s, 200);
        assert!((a - b).abs() < 1e-12);
    }
}

#[test]
fn test_beginner_auto_connect_tray_pins_and_sparkle() {
    let mut vm = WorkbenchViewModel::new();
    assert_eq!(vm.menu_bar_icon_geometry(), MenuBarIconGeometry::DisconnectedOutline);
    assert_eq!(vm.menu_bar_shortcuts().len(), 4);
    assert_eq!(vm.menu_bar_pins[0], DEFAULT_MENU_BAR_PIN_IDS[0]);

    let outcome = vm.activate_shortcut("szu-reimburse-system").unwrap();
    assert_eq!(
        outcome,
        ShortcutLaunchOutcome::QueuedAfterConnect {
            shortcut_id: "szu-reimburse-system".to_string(),
            url: "http://172.31.134.31/wsyy/frame_container.aspx".to_string(),
        }
    );
    assert_eq!(vm.menu_bar_icon_geometry(), MenuBarIconGeometry::ConnectingPulse);
    assert_eq!(vm.pending_open_shortcut_id.as_deref(), Some("szu-reimburse-system"));
    assert!(vm.last_opened_url.is_none());

    vm.set_connected("utun4", "1.1.105.34");
    assert_eq!(vm.menu_bar_icon_geometry(), MenuBarIconGeometry::ConnectedSolid);
    assert!(vm.pending_open_shortcut_id.is_none());
    assert_eq!(
        vm.last_opened_url.as_deref(),
        Some("http://172.31.134.31/wsyy/frame_container.aspx")
    );

    let direct = vm.activate_shortcut("szu-finance-sso").unwrap();
    assert!(matches!(direct, ShortcutLaunchOutcome::OpenedImmediately(_)));

    assert!(vm.pin_to_menu_bar(3, "szu-westlaw"));
    assert!(!vm.pin_to_menu_bar(4, "szu-westlaw"));
    assert!(!vm.pin_to_menu_bar(0, "nonexistent-id"));
    let tray = vm.render_tray_menu_tree();
    assert_eq!(tray.kind, "TrayMenu");
    assert_eq!(tray.children.len(), 5);
    assert_eq!(tray.children[4].label, "Westlaw");

    vm.set_locale(UiLocale::EnUs);
    vm.set_scheme(UiScheme::BambooColumn);
    let en_tree = vm.render_gpui_tree();
    assert!(en_tree.children[0].label.contains("Connected"));
    vm.set_scheme(UiScheme::IndigoTrayFirst);
    assert!(vm.render_tray_menu_tree().label.contains("Menu Bar"));

    assert!(SparkleConfig::default().validate().is_ok());
    let valid_sig = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGHIJKLMNOPQRSTUV==";
    assert!(validate_ed25519_signature(valid_sig));
    assert!(!validate_ed25519_signature("short=="));
    assert!(is_newer_version("0.2.0", "0.3.0"));
    assert!(!is_newer_version("0.2.0", "0.2.0"));
    assert!(!is_newer_version("0.2.0", "0.1.9"));

    assert_eq!(format_package_size_mb(14_889_779).as_deref(), Some("14.2 MB"));
    assert!(format_package_size_mb(0).is_none());
    assert!(format_package_size_mb(600_000_000).is_none());
    assert_eq!(format_latency_ms(18).as_deref(), Some("18 ms"));
    assert!(format_latency_ms(0).is_none());
    assert!(format_latency_ms(60_001).is_none());
    assert_eq!(format_duration_human(2520, false), "42 分钟");
    assert_eq!(format_duration_human(4500, false), "1 小时 15 分钟");
    assert_eq!(format_duration_human(4500, true), "1 hr 15 min");
    assert_eq!(format_route_count(129, false).as_deref(), Some("129 条校内路由"));
    assert_eq!(format_route_count(129, true).as_deref(), Some("129 campus routes"));
    assert!(format_route_count(0, false).is_none());
    assert!(format_route_count(513, true).is_none());

    let item = SparkleAppcastItem {
        version: "0.3.0".to_string(),
        build_number: 300,
        download_url: "https://securelink.szu.edu.cn/updates/SZU-SecureLink-0.3.0.dmg".to_string(),
        ed_signature: valid_sig.to_string(),
        length_bytes: 14_889_779,
        release_notes_zh: "新增菜单栏一键直达与自动连接队列".to_string(),
        release_notes_en: "Added menu bar 1-click access and auto-connect queue".to_string(),
    };
    assert!(vm.apply_sparkle_appcast(item));
    assert!(matches!(vm.sparkle_state, SparkleUpdateState::UpdateAvailable(_)));
    let bad = SparkleAppcastItem {
        version: "bad".to_string(), build_number: 0,
        download_url: "https://securelink.szu.edu.cn/a.dmg".to_string(),
        ed_signature: valid_sig.to_string(), length_bytes: 1024,
        release_notes_zh: String::new(), release_notes_en: String::new(),
    };
    assert_eq!(bad.validate(), Err(SparkleError::InvalidVersion));
    assert_eq!(
        parse_engine_active_line("engine: active on utun7 vip=1.1.105.34"),
        Some(EngineActiveNotice {
            interface: "utun7".to_string(),
            virtual_ipv4: "1.1.105.34".to_string(),
            dns_server: "192.168.247.6".to_string(),
        })
    );
    assert!(validate_securelink_callback_url("securelink://callback?ticket=ST-1").is_some());
    assert!(validate_securelink_callback_url("https://szu.edu.cn").is_none());

    let (handle, rx) = crate::tunnel_actor::TunnelHandle::channel();
    let mut win = crate::gpui_window::WorkbenchWindow::new(handle);
    win.on_shortcut_clicked("szu-reimburse-system");
    let notice = EngineActiveNotice {
        interface: "utun4".to_string(),
        virtual_ipv4: "1.1.105.34".to_string(),
        dns_server: "192.168.247.6".to_string(),
    };
    win.apply_session_event(crate::tunnel_actor::SessionEvent::ConnectingPhase {
        generation: crate::tunnel_actor::GenerationId(2),
        phase: "正在建立零信任网络隧道...".to_string(),
    });
    win.apply_session_event(crate::tunnel_actor::SessionEvent::TunnelActive {
        generation: crate::tunnel_actor::GenerationId(1),
        notice: notice.clone(),
    });
    assert!(matches!(win.vm.status, ConnectionStatus::Connected { .. }));
    win.apply_session_event(crate::tunnel_actor::SessionEvent::TunnelActive {
        generation: crate::tunnel_actor::GenerationId(2),
        notice,
    });
    let mut opened = 0;
    while let Ok(cmd) = rx.try_recv() {
        if matches!(cmd, crate::tunnel_actor::SessionCommand::OpenBrowserUrl(_)) {
            opened += 1;
        }
    }
    assert_eq!(opened, 1);
    let mut actor_state = crate::tunnel_actor::ActorTunnelState::Connecting { watchdog_spawned: true };
    assert!(crate::tunnel_actor::step_watchdog_tick(&mut actor_state, crate::tunnel_actor::GenerationId(2), crate::tunnel_actor::GenerationId(2), None).is_none());
    assert_eq!(actor_state, crate::tunnel_actor::ActorTunnelState::Connecting { watchdog_spawned: true });
    let sample_ifconfig = "utun4: flags=8051<UP,POINTOPOINT,RUNNING>\n\tinet 1.1.105.34 --> 1.1.96.1 netmask 0xff000000\n";
    let probed = crate::tunnel_actor::parse_ifconfig_campus_utun(sample_ifconfig);
    assert!(matches!(
        crate::tunnel_actor::step_watchdog_tick(&mut actor_state, crate::tunnel_actor::GenerationId(2), crate::tunnel_actor::GenerationId(2), probed),
        Some(crate::tunnel_actor::SessionEvent::TunnelActive { .. })
    ));
    win.apply_session_event(crate::tunnel_actor::SessionEvent::Disconnected {
        generation: crate::tunnel_actor::GenerationId(2),
        reason: "已断开".to_string(),
    });
    win.apply_session_event(crate::tunnel_actor::SessionEvent::ConnectingPhase {
        generation: crate::tunnel_actor::GenerationId(2),
        phase: "stale phase after disconnect".to_string(),
    });
    assert_eq!(win.vm.status, ConnectionStatus::Disconnected);
}
