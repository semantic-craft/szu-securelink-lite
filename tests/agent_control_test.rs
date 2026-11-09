#![forbid(unsafe_code)]

use szu_securelink_rs::async_util;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use szu_securelink_rs::agent_control::{
    CliInvocation, ControlBroker, ControlCommand, ControlResponse, TunnelPhase, TunnelSnapshot,
    apply_event_to_snapshot, parse_cli_args, reconcile_utun_probe, send_socket_request,
    spawn_control_daemon_at,
};
use szu_securelink_rs::tunnel_actor::{
    EngineActiveNotice, GenerationId, SessionCommand, SessionEvent, TunnelHandle,
};

fn vec_args(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

#[test]
fn cli_argument_parsing_covers_subcommands_and_flags() {
    assert_eq!(parse_cli_args(&vec_args(&[])), Ok(CliInvocation::Gui));
    assert_eq!(parse_cli_args(&vec_args(&["-psn_0_12345"])), Ok(CliInvocation::Gui));
    assert_eq!(
        parse_cli_args(&vec_args(&["status", "--json"])),
        Ok(CliInvocation::Cli {
            command: ControlCommand::Status,
            json: true,
        })
    );
    assert_eq!(
        parse_cli_args(&vec_args(&["ensure", "--timeout", "15", "--json"])),
        Ok(CliInvocation::Cli {
            command: ControlCommand::Ensure { timeout_secs: 15 },
            json: true,
        })
    );
    assert_eq!(
        parse_cli_args(&vec_args(&["open-sso", "library", "--json"])),
        Ok(CliInvocation::Cli {
            command: ControlCommand::OpenSso {
                shortcut_id: "library".to_string(),
                timeout_secs: 20,
            },
            json: true,
        })
    );
    assert_eq!(
        parse_cli_args(&vec_args(&["shortcuts", "--json"])),
        Ok(CliInvocation::Cli {
            command: ControlCommand::Shortcuts,
            json: true,
        })
    );
    assert_eq!(
        parse_cli_args(&vec_args(&["callback", "securelink://callback?ticket=ST-1"])),
        Ok(CliInvocation::Callback {
            raw_url: "securelink://callback?ticket=ST-1".to_string(),
        })
    );
    assert!(parse_cli_args(&vec_args(&["status", "--unknown-flag"])).is_err());
}

#[test]
fn snapshot_reducer_and_reconcile_preserve_connected_state() {
    let mut snap = TunnelSnapshot::default();
    apply_event_to_snapshot(
        &mut snap,
        &SessionEvent::ConnectingPhase {
            generation: GenerationId(1),
            phase: "negotiating".to_string(),
        },
        100,
    );
    assert_eq!(snap.phase, TunnelPhase::Connecting);
    assert!(!snap.connected);

    let notice = EngineActiveNotice {
        interface: "utun4".to_string(),
        virtual_ipv4: "1.1.105.34".to_string(),
        dns_server: "192.168.247.6".to_string(),
    };
    apply_event_to_snapshot(
        &mut snap,
        &SessionEvent::TunnelActive {
            generation: GenerationId(1),
            notice,
        },
        105,
    );
    assert_eq!(snap.phase, TunnelPhase::Connected);
    assert!(snap.connected);
    assert!(snap.route_ready);
    assert_eq!(snap.active_since_epoch_secs, Some(105));

    apply_event_to_snapshot(
        &mut snap,
        &SessionEvent::ConnectingPhase {
            generation: GenerationId(1),
            phase: "late connecting line".to_string(),
        },
        106,
    );
    assert_eq!(snap.phase, TunnelPhase::Connected);
    assert!(snap.connected);

    reconcile_utun_probe(&mut snap, None, 110);
    assert_eq!(snap.phase, TunnelPhase::Disconnected);
    assert!(!snap.connected);
    assert!(!snap.route_ready);

    reconcile_utun_probe(&mut snap, Some(("utun6".to_string(), "1.1.105.99".to_string())), 120);
    assert_eq!(snap.phase, TunnelPhase::Connected);
    assert!(snap.connected);
    assert_eq!(snap.interface.as_deref(), Some("utun6"));
}

#[test]
fn concurrent_ensure_coalesces_into_single_actor_connect() {
    let (handle, rx) = TunnelHandle::channel();
    let broker = ControlBroker::with_opener(handle, Arc::new(|_| Ok(())));

    let b1 = broker.clone();
    let t1 = thread::spawn(move || b1.handle_command(ControlCommand::Ensure { timeout_secs: 5 }));
    let b2 = broker.clone();
    let t2 = thread::spawn(move || b2.handle_command(ControlCommand::Ensure { timeout_secs: 5 }));

    thread::sleep(Duration::from_millis(40));
    broker.ingest_event(&SessionEvent::ConnectingPhase {
        generation: GenerationId(1),
        phase: "connecting".to_string(),
    });
    broker.ingest_event(&SessionEvent::TunnelActive {
        generation: GenerationId(1),
        notice: EngineActiveNotice {
            interface: "utun4".to_string(),
            virtual_ipv4: "1.1.105.34".to_string(),
            dns_server: "192.168.247.6".to_string(),
        },
    });

    let r1 = t1.join().unwrap();
    let r2 = t2.join().unwrap();
    assert!(r1.ok && r1.snapshot.connected);
    assert!(r2.ok && r2.snapshot.connected);

    let mut connect_count = 0;
    while let Ok(cmd) = rx.try_recv() {
        if matches!(cmd, SessionCommand::Connect { .. }) {
            connect_count += 1;
        }
    }
    assert_eq!(connect_count, 1);
}

#[test]
fn open_sso_waits_for_tunnel_and_opens_target_once() {
    let (handle, _rx) = TunnelHandle::channel();
    let opened_urls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let urls_ref = opened_urls.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_ref = calls.clone();

    let broker = ControlBroker::with_opener(
        handle,
        Arc::new(move |url| {
            calls_ref.fetch_add(1, Ordering::SeqCst);
            urls_ref.lock().unwrap().push(url.to_string());
            Ok(())
        }),
    );

    let b_open = broker.clone();
    let waiter = thread::spawn(move || {
        b_open.handle_command(ControlCommand::OpenSso {
            shortcut_id: "library".to_string(),
            timeout_secs: 5,
        })
    });

    thread::sleep(Duration::from_millis(30));
    broker.ingest_event(&SessionEvent::TunnelActive {
        generation: GenerationId(1),
        notice: EngineActiveNotice {
            interface: "utun4".to_string(),
            virtual_ipv4: "1.1.105.34".to_string(),
            dns_server: "192.168.247.6".to_string(),
        },
    });

    let resp = waiter.join().unwrap();
    assert!(resp.ok);
    assert_eq!(resp.target_url.as_deref(), Some("https://www.lib.szu.edu.cn"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let reimb = broker.handle_command(ControlCommand::OpenSso {
        shortcut_id: "reimbursement".to_string(),
        timeout_secs: 5,
    });
    assert!(reimb.ok);
    assert_eq!(
        reimb.target_url.as_deref(),
        Some("https://ehall.szu.edu.cn/new/index.html")
    );
    assert_eq!(
        *opened_urls.lock().unwrap(),
        vec![
            "https://www.lib.szu.edu.cn".to_string(),
            "https://ehall.szu.edu.cn/new/index.html".to_string(),
        ]
    );

    let bad = broker.handle_command(ControlCommand::OpenSso {
        shortcut_id: "no-such-shortcut".to_string(),
        timeout_secs: 5,
    });
    assert!(!bad.ok);
    assert_eq!(bad.error_code.as_deref(), Some("unknown_shortcut"));
}

#[test]
fn unix_socket_roundtrip_and_permissions() {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("szu-sl-sock-{nanos}"));
    let sock = dir.join("control.sock");

    let (handle, _cmd_rx) = TunnelHandle::channel();
    let (evt_tx, evt_rx) = async_util::unbounded::<SessionEvent>();
    let _ui_rx = spawn_control_daemon_at(handle, evt_rx, sock.clone());

    for _ in 0..30 {
        if sock.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(sock.exists());
    let mode = fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    let _ = evt_tx.try_send(SessionEvent::TunnelActive {
        generation: GenerationId(1),
        notice: EngineActiveNotice {
            interface: "utun5".to_string(),
            virtual_ipv4: "1.1.105.88".to_string(),
            dns_server: "192.168.247.6".to_string(),
        },
    });
    thread::sleep(Duration::from_millis(20));

    let resp = send_socket_request(&sock, &ControlCommand::Status).unwrap();
    assert!(resp.ok);
    assert_eq!(resp.action, "status");
    assert!(resp.snapshot.connected);
    let roundtrip = ControlResponse::from_json_line(&resp.to_json()).unwrap();
    assert_eq!(roundtrip, resp);

    let _ = fs::remove_dir_all(&dir);
}
