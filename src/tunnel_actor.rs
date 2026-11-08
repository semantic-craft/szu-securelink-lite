//! Background Zero-Trust tunnel supervisor actor with automatic self-repair (`#![forbid(unsafe_code)]`).

#![forbid(unsafe_code)]

use crate::ip_math::{parse_ipv4, rejected_for_assignment};
use crate::shortcuts::valid_url;
use crate::tray_bridge::TrayAction;
use gpui_kit::base::async_util::{self, Receiver, Sender};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::thread;
use std::time::Duration;

/// Monotonic session generation token used to discard stale tunnel events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GenerationId(pub u64);

/// Parsed tunnel activation notice emitted by `executor-engine` or live `utun` probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineActiveNotice {
    /// Active macOS `utun` interface name (e.g. `"utun4"`).
    pub interface: String,
    /// Assigned virtual IPv4 address inside the campus tunnel.
    pub virtual_ipv4: String,
    /// In-tunnel campus DNS server IPv4 address.
    pub dns_server: String,
}

/// Commands accepted by [`TunnelActor`] from the GPUI main window, URL handler, or watchdog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionCommand {
    /// Toggles between connected/connecting and disconnected states.
    ToggleConnect,
    /// Starts a campus tunnel connection and pre-resolves `resolve_domains`.
    Connect { resolve_domains: Vec<String> },
    /// Runs one-click self-repair: adopts live `utun` or cleans stale state and reconnects.
    Repair,
    /// Watchdog check triggered during `Connecting` to adopt a newly configured `utun`.
    WatchdogTick { generation: GenerationId, elapsed_secs: u64 },
    /// Terminates any active tunnel process and resets to disconnected.
    Disconnect,
    /// Processes an incoming `securelink://` CAS callback URL.
    HandleCallbackUrl(String),
    /// Opens a validated `http://` or `https://` URL in the default browser.
    OpenBrowserUrl(String),
    /// Stops the actor loop and terminates any active child process.
    Shutdown,
}

/// Events emitted by [`TunnelActor`] back to the GPUI window entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// Tunnel negotiation or self-repair is in progress for `generation`.
    ConnectingPhase { generation: GenerationId, phase: String },
    /// Tunnel `utun` interface became active for `generation`.
    TunnelActive { generation: GenerationId, notice: EngineActiveNotice },
    /// Tunnel session ended or was disconnected for `generation`.
    Disconnected { generation: GenerationId, reason: String },
    /// User interacted with the top-right macOS Menu Bar status item.
    TrayAction(TrayAction),
}

/// Sibling executable paths inside `SZU SecureLink.app/Contents/MacOS`.
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    /// Optional path to `executor-engine` or `szu-openvpn3-data-engine`.
    pub engine_bin: Option<PathBuf>,
    /// Optional path to `szu-securelink-diagnostic` helper binary.
    pub diagnostic_bin: Option<PathBuf>,
}

impl TunnelConfig {
    /// Resolves sibling binaries relative to `std::env::current_exe()`.
    #[must_use]
    pub fn from_bundle_env() -> Self {
        let dir = env::current_exe().ok().and_then(|p| p.parent().map(PathBuf::from));
        let find_exec = |name: &str| dir.as_ref()?.join(name).is_file().then(|| dir.as_ref().unwrap().join(name));
        Self {
            engine_bin: find_exec("executor-engine").or_else(|| find_exec("szu-openvpn3-data-engine")),
            diagnostic_bin: find_exec("szu-securelink-diagnostic"),
        }
    }
}

/// Cloneable command handle for communicating with the background [`TunnelActor`].
#[derive(Clone, Debug)]
pub struct TunnelHandle {
    tx: Sender<SessionCommand>,
}

impl TunnelHandle {
    /// Creates an in-memory command handle and receiver pair for testing or custom supervisors.
    #[must_use]
    pub fn channel() -> (Self, Receiver<SessionCommand>) {
        let (tx, rx) = async_util::unbounded();
        (Self { tx }, rx)
    }

    /// Sends a [`SessionCommand`] to the background actor without blocking the UI thread.
    pub fn send(&self, cmd: SessionCommand) -> bool {
        self.tx.try_send(cmd).is_ok()
    }
}

/// Parses an engine readiness line of the form `engine: active on utun<N> [vip=<IPv4>]`.
#[must_use]
pub fn parse_engine_active_line(line: &str) -> Option<EngineActiveNotice> {
    let rest = line.trim().strip_prefix("engine: active on ")?;
    let mut parts = rest.split_whitespace();
    let iface = parts.next()?;
    let digits = iface.strip_prefix("utun")?;
    if digits.is_empty() || digits.len() > 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut vip = "192.168.240.1".to_string();
    for token in parts {
        if let Some(raw_ip) = token.strip_prefix("vip=") {
            parse_ipv4(raw_ip).filter(|ip| !rejected_for_assignment(ip))?;
            vip = raw_ip.to_string();
        }
    }
    Some(EngineActiveNotice { interface: iface.to_string(), virtual_ipv4: vip, dns_server: "192.168.247.6".to_string() })
}

/// Parses `/sbin/ifconfig` output to detect an active SZU campus `utun` tunnel interface.
#[must_use]
pub fn parse_ifconfig_campus_utun(ifconfig_text: &str) -> Option<EngineActiveNotice> {
    let mut current_utun: Option<&str> = None;
    for line in ifconfig_text.lines() {
        if !line.starts_with([' ', '\t']) {
            current_utun = line.split(':').next().filter(|name| {
                name.strip_prefix("utun").is_some_and(|d| !d.is_empty() && d.len() <= 4 && d.bytes().all(|b| b.is_ascii_digit()))
            });
            continue;
        }
        let Some(iface) = current_utun else { continue };
        let mut parts = line.split_whitespace();
        if parts.next() == Some("inet")
            && let Some(vip) = parts.next()
            && parse_ipv4(vip).is_some_and(|ip| !rejected_for_assignment(&ip))
        {
            let peer = if parts.next() == Some("-->") { parts.next().unwrap_or("") } else { "" };
            if peer == "1.1.96.1" || vip.starts_with("1.1.") || vip.starts_with("192.168.240.") {
                return Some(EngineActiveNotice { interface: iface.to_string(), virtual_ipv4: vip.to_string(), dns_server: "192.168.247.6".to_string() });
            }
        }
    }
    None
}

/// Validates an incoming `securelink://` CAS callback URL at the IPC boundary.
#[must_use]
pub fn validate_securelink_callback_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.len() <= "securelink://".len() || trimmed.len() > 2048 || !trimmed.starts_with("securelink://") || !trimmed.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return None;
    }
    Some(trimmed.to_string())
}

/// Explicit lifecycle state of [`TunnelActor`], separating in-flight negotiation from active `utun`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActorTunnelState {
    /// No active tunnel or worker process.
    Disconnected,
    /// Negotiating CAS login or waiting for `executor-engine` to attach `utun`.
    Connecting {
        /// Whether the post-callback `utun` polling watchdog has already been spawned.
        watchdog_spawned: bool,
    },
    /// Verified campus `utun` interface is active.
    Connected(EngineActiveNotice),
}

/// Pure state transition for a [`SessionCommand::WatchdogTick`].
#[must_use]
pub fn step_watchdog_tick(state: &mut ActorTunnelState, tick_gen: GenerationId, current_gen: GenerationId, probed: Option<EngineActiveNotice>) -> Option<SessionEvent> {
    if tick_gen == current_gen && matches!(state, ActorTunnelState::Connecting { .. }) && let Some(notice) = probed {
        *state = ActorTunnelState::Connected(notice.clone());
        return Some(SessionEvent::TunnelActive { generation: current_gen, notice });
    }
    None
}

/// Probes whether a live campus `utun` interface is up and reachable on macOS.
#[must_use]
pub fn probe_live_campus_utun() -> Option<EngineActiveNotice> {
    let out = Command::new("/sbin/ifconfig").output().ok()?;
    let notice = parse_ifconfig_campus_utun(&String::from_utf8_lossy(&out.stdout))?;
    Command::new("/sbin/ping").args(["-c", "1", "-t", "1", "1.1.96.1"]).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success()).then_some(notice)
}

/// Probes whether `executor-engine` has attached a campus `utun` (`1.1.x.x`) during route setup.
#[must_use]
pub fn probe_connecting_campus_utun() -> Option<EngineActiveNotice> {
    let out = Command::new("/sbin/ifconfig").output().ok()?;
    let notice = parse_ifconfig_campus_utun(&String::from_utf8_lossy(&out.stdout))?;
    if Command::new("/usr/bin/pgrep").args(["-f", "executor-engine --data-session"]).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success()) {
        return Some(notice);
    }
    probe_live_campus_utun()
}

/// Background actor supervising the Zero-Trust tunnel child process and self-repair watchdog.
pub struct TunnelActor;

impl TunnelActor {
    /// Spawns the background supervisor thread and returns a command handle plus event receiver.
    #[must_use]
    pub fn spawn(config: TunnelConfig) -> (TunnelHandle, Receiver<SessionEvent>) {
        let (cmd_tx, cmd_rx) = async_util::unbounded::<SessionCommand>();
        let (evt_tx, evt_rx) = async_util::unbounded::<SessionEvent>();
        let actor_cmd_tx = cmd_tx.clone();
        thread::spawn(move || {
            let mut generation = GenerationId(0);
            let mut state = ActorTunnelState::Disconnected;
            let mut active_child: Option<Child> = None;
            let mut active_stdin: Option<ChildStdin> = None;

            if let Some(notice) = probe_live_campus_utun() {
                generation = GenerationId(1);
                state = ActorTunnelState::Connected(notice.clone());
                let _ = evt_tx.try_send(SessionEvent::TunnelActive { generation, notice });
            }

            while let Ok(cmd) = cmd_rx.recv_blocking() {
                match cmd {
                    SessionCommand::OpenBrowserUrl(url) => open_url_reaped(&url),
                    SessionCommand::ToggleConnect => {
                        let child_alive = active_child.as_mut().is_some_and(|c| c.try_wait().ok().flatten().is_none());
                        if !matches!(state, ActorTunnelState::Disconnected) && (child_alive || probe_live_campus_utun().is_some()) {
                            terminate_child(&mut active_child, &mut active_stdin);
                            state = ActorTunnelState::Disconnected;
                            let _ = evt_tx.try_send(SessionEvent::Disconnected { generation, reason: "已断开校园网隧道".to_string() });
                        } else {
                            generation = GenerationId(generation.0 + 1);
                            start_connection(&config, generation, &mut active_child, &mut active_stdin, &mut state, &evt_tx, &actor_cmd_tx);
                        }
                    }
                    SessionCommand::Connect { .. } => {
                        generation = GenerationId(generation.0 + 1);
                        start_connection(&config, generation, &mut active_child, &mut active_stdin, &mut state, &evt_tx, &actor_cmd_tx);
                    }
                    SessionCommand::Repair => {
                        generation = GenerationId(generation.0 + 1);
                        run_auto_repair(&config, generation, &mut active_child, &mut active_stdin, &mut state, &evt_tx, &actor_cmd_tx);
                    }
                    SessionCommand::WatchdogTick { generation: tick_gen, .. } => {
                        if tick_gen == generation && matches!(state, ActorTunnelState::Connecting { .. }) {
                            let probed = probe_connecting_campus_utun();
                            if let Some(evt) = step_watchdog_tick(&mut state, tick_gen, generation, probed) {
                                let _ = evt_tx.try_send(evt);
                            }
                        }
                    }
                    SessionCommand::HandleCallbackUrl(raw) => {
                        if let Some(valid_cb) = validate_securelink_callback_url(&raw) {
                            if let Some(stdin) = active_stdin.as_mut() {
                                let _ = writeln!(stdin, "CALLBACK {valid_cb}");
                                let _ = stdin.flush();
                                let _ = evt_tx.try_send(SessionEvent::ConnectingPhase { generation, phase: "已收到深大 CAS 登录回跳，正在协商零信任隧道…".to_string() });
                                if matches!(state, ActorTunnelState::Connecting { watchdog_spawned: false }) {
                                    state = ActorTunnelState::Connecting { watchdog_spawned: true };
                                    spawn_watchdog(generation, actor_cmd_tx.clone());
                                }
                            } else if let Some(notice) = probe_connecting_campus_utun() {
                                generation = GenerationId(generation.0 + 1);
                                state = ActorTunnelState::Connected(notice.clone());
                                let _ = evt_tx.try_send(SessionEvent::TunnelActive { generation, notice });
                            }
                        }
                    }
                    SessionCommand::Disconnect => {
                        terminate_child(&mut active_child, &mut active_stdin);
                        state = ActorTunnelState::Disconnected;
                        let _ = evt_tx.try_send(SessionEvent::Disconnected { generation, reason: "已断开校园网隧道".to_string() });
                    }
                    SessionCommand::Shutdown => {
                        terminate_child(&mut active_child, &mut active_stdin);
                        break;
                    }
                }
            }
        });
        (TunnelHandle { tx: cmd_tx }, evt_rx)
    }
}

fn open_url_reaped(url: &str) {
    if valid_url(url) {
        let owned = url.to_string();
        thread::spawn(move || {
            let _ = Command::new("/usr/bin/open").arg(&owned).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status();
        });
    }
}

fn spawn_watchdog(generation: GenerationId, cmd_tx: Sender<SessionCommand>) {
    thread::spawn(move || {
        for step in 1..=15 {
            thread::sleep(Duration::from_secs(1));
            if cmd_tx.try_send(SessionCommand::WatchdogTick { generation, elapsed_secs: step }).is_err() {
                break;
            }
        }
    });
}

fn terminate_child(slot: &mut Option<Child>, stdin_slot: &mut Option<ChildStdin>) {
    if let Some(mut stdin) = stdin_slot.take() {
        let _ = writeln!(stdin, "DISCONNECT");
        let _ = stdin.flush();
    }
    thread::sleep(Duration::from_millis(120));
    if let Some(mut child) = slot.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = Command::new("/usr/bin/pkill").args(["-TERM", "-f", "executor-engine --data-session"]).status();
    let _ = Command::new("/usr/bin/pkill").args(["-TERM", "-f", "szu-securelink-diagnostic --headless-tunnel-worker"]).status();
}

fn run_auto_repair(
    config: &TunnelConfig,
    generation: GenerationId,
    active_child: &mut Option<Child>,
    active_stdin: &mut Option<ChildStdin>,
    state: &mut ActorTunnelState,
    evt_tx: &Sender<SessionEvent>,
    cmd_tx: &Sender<SessionCommand>,
) {
    let phase = "正在自动修复：检测隧道接口、清理残留进程与重置协议注册…".to_string();
    let _ = evt_tx.try_send(SessionEvent::ConnectingPhase { generation, phase });
    let _ = Command::new("/usr/bin/dscacheutil").arg("-flushcache").status();
    if let Some(notice) = probe_live_campus_utun() {
        *state = ActorTunnelState::Connected(notice.clone());
        let _ = evt_tx.try_send(SessionEvent::TunnelActive { generation, notice });
        return;
    }
    terminate_child(active_child, active_stdin);
    thread::sleep(Duration::from_millis(200));
    start_connection(config, generation, active_child, active_stdin, state, evt_tx, cmd_tx);
}

fn start_connection(config: &TunnelConfig, generation: GenerationId, active_child: &mut Option<Child>, active_stdin: &mut Option<ChildStdin>, state: &mut ActorTunnelState, evt_tx: &Sender<SessionEvent>, cmd_tx: &Sender<SessionCommand>) {
    if let Some(notice) = probe_live_campus_utun() {
        *state = ActorTunnelState::Connected(notice.clone());
        let _ = evt_tx.try_send(SessionEvent::TunnelActive { generation, notice });
        return;
    }
    terminate_child(active_child, active_stdin);
    *state = ActorTunnelState::Connecting { watchdog_spawned: false };
    let _ = evt_tx.try_send(SessionEvent::ConnectingPhase { generation, phase: "正在发起深大 CAS 零信任认证与隧道协商…".to_string() });
    if let Some(diag_bin) = &config.diagnostic_bin
        && let Ok(mut child) = Command::new(diag_bin).arg("--headless-tunnel-worker").stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn()
    {
        *active_stdin = child.stdin.take();
        if let Some(stderr) = child.stderr.take() {
            let (tx, w_tx) = (evt_tx.clone(), cmd_tx.clone());
            thread::spawn(move || {
                let (mut ended, mut watchdog_started) = (false, false);
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    if let Some(notice) = parse_engine_active_line(&line) {
                        let _ = tx.try_send(SessionEvent::TunnelActive { generation, notice });
                        let _ = w_tx.try_send(SessionCommand::WatchdogTick { generation, elapsed_secs: 0 });
                    } else if let Some(url) = line.trim().strip_prefix("OPEN_URL: ") {
                        open_url_reaped(url);
                    } else if let Some(phase) = line.trim().strip_prefix("PHASE: ") {
                        if !watchdog_started && phase.contains("正在建立零信任网络隧道") {
                            watchdog_started = true;
                            spawn_watchdog(generation, w_tx.clone());
                        }
                        let _ = tx.try_send(SessionEvent::ConnectingPhase { generation, phase: phase.to_string() });
                    } else if let Some(reason) = line.trim().strip_prefix("DISCONNECTED: ") {
                        ended = true;
                        let evt = probe_live_campus_utun().map_or_else(|| SessionEvent::Disconnected { generation, reason: reason.to_string() }, |notice| SessionEvent::TunnelActive { generation, notice });
                        let _ = tx.try_send(evt);
                    }
                }
                if !ended {
                    let evt = probe_live_campus_utun().map_or_else(|| SessionEvent::Disconnected { generation, reason: "校园网连接会话已结束".to_string() }, |notice| SessionEvent::TunnelActive { generation, notice });
                    let _ = tx.try_send(evt);
                }
            });
        }
        *active_child = Some(child);
        return;
    }
    *state = ActorTunnelState::Disconnected;
    let _ = evt_tx.try_send(SessionEvent::Disconnected { generation, reason: "未能启动零信任隧道工作进程".to_string() });
}
