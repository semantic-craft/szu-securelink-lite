#![forbid(unsafe_code)]

#[rustfmt::skip]
mod inner {
use crate::gpui_workbench::WorkbenchViewModel;
use crate::shortcuts::{default_shortcuts, valid_url};
use crate::tunnel_actor::{probe_connecting_campus_utun, validate_securelink_callback_url, SessionCommand, SessionEvent, TunnelActor, TunnelConfig, TunnelHandle};
use crate::async_util::{self, Receiver};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{env, fs, thread};

pub type TunnelActorHandle = TunnelHandle;
pub type ActorCommand = SessionCommand;
pub type UrlOpener = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlCommand { Status, Ensure { timeout_secs: u64 }, OpenSso { shortcut_id: String, timeout_secs: u64 }, Repair { timeout_secs: u64 }, Disconnect, Shortcuts, Callback { raw_url: String } }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliInvocation { Gui, Callback { raw_url: String }, Cli { command: ControlCommand, json: bool } }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelPhase { Disconnected, Connecting, Connected, AttentionRequired }

impl TunnelPhase {
    #[must_use] pub const fn as_str(self) -> &'static str { match self { Self::Disconnected => "disconnected", Self::Connecting => "connecting", Self::Connected => "connected", Self::AttentionRequired => "attention_required" } }
    #[must_use] pub fn from_name(raw: &str) -> Self { match raw { "connecting" => Self::Connecting, "connected" => Self::Connected, "attention_required" => Self::AttentionRequired, _ => Self::Disconnected } }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelSnapshot { pub phase: TunnelPhase, pub connected: bool, pub status_line: String, pub detail: Option<String>, pub interface: Option<String>, pub route_ready: bool, pub active_since_epoch_secs: Option<u64> }

impl Default for TunnelSnapshot {
    fn default() -> Self { Self { phase: TunnelPhase::Disconnected, connected: false, status_line: "校园网未连接".to_string(), detail: None, interface: None, route_ready: false, active_since_epoch_secs: None } }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlResponse { pub ok: bool, pub action: String, pub snapshot: TunnelSnapshot, pub target_url: Option<String>, pub shortcut_id: Option<String>, pub error_code: Option<String>, pub message: String }

impl ControlResponse {
    fn new(ok: bool, action: &str, snap: TunnelSnapshot, err: Option<&str>, msg: String) -> Self {
        Self { ok, action: action.to_string(), snapshot: snap, target_url: None, shortcut_id: None, error_code: err.map(str::to_string), message: msg }
    }
    #[must_use] pub fn to_json(&self) -> String {
        json!({
            "ok": self.ok, "action": self.action, "phase": self.snapshot.phase.as_str(), "connected": self.snapshot.connected,
            "status_line": self.snapshot.status_line, "detail": self.snapshot.detail, "interface": self.snapshot.interface,
            "route_ready": self.snapshot.route_ready, "active_since_epoch_secs": self.snapshot.active_since_epoch_secs,
            "target_url": self.target_url, "shortcut_id": self.shortcut_id, "error_code": self.error_code, "message": self.message,
        }).to_string()
    }
    #[must_use] pub fn to_human(&self) -> String {
        format!("[{}] {} ({}) - {}", if self.ok { "OK" } else { "ERR" }, self.action, self.snapshot.phase.as_str(), self.message)
    }
    pub fn from_json_line(line: &str) -> Result<Self, String> {
        let v: Value = serde_json::from_str(line.trim()).map_err(|e| e.to_string())?;
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        let b = |k: &str| v.get(k).and_then(Value::as_bool).unwrap_or(false);
        let snapshot = TunnelSnapshot {
            phase: TunnelPhase::from_name(v.get("phase").and_then(Value::as_str).unwrap_or("")),
            connected: b("connected"), status_line: s("status_line").unwrap_or_default(),
            detail: s("detail"), interface: s("interface"), route_ready: b("route_ready"),
            active_since_epoch_secs: v.get("active_since_epoch_secs").and_then(Value::as_u64),
        };
        Ok(Self { ok: b("ok"), action: s("action").unwrap_or_default(), snapshot, target_url: s("target_url"), shortcut_id: s("shortcut_id"), error_code: s("error_code"), message: s("message").unwrap_or_default() })
    }
}

pub fn parse_cli_args(args: &[String]) -> Result<CliInvocation, String> {
    let slice = match args.first().map(String::as_str) {
        Some(f) if !f.starts_with("securelink://") && (f.ends_with("szu-securelink") || f.contains('/')) => &args[1..],
        _ => args,
    };
    if slice.is_empty() || slice[0].starts_with("-psn_") { return Ok(CliInvocation::Gui); }
    if slice.len() == 1 && slice[0].starts_with("securelink://") { return Ok(CliInvocation::Callback { raw_url: slice[0].clone() }); }
    let (mut json, mut timeout_secs, mut pos, mut i) = (false, 20u64, Vec::new(), 0);
    while i < slice.len() {
        let arg = slice[i].as_str();
        if arg == "--json" { json = true; }
        else if arg == "--timeout" {
            i += 1;
            let val = slice.get(i).ok_or_else(|| "missing value for --timeout".to_string())?;
            timeout_secs = val.parse::<u64>().map_err(|_| format!("invalid --timeout: {val}"))?;
        } else if let Some(val) = arg.strip_prefix("--timeout=") {
            timeout_secs = val.parse::<u64>().map_err(|_| format!("invalid --timeout: {val}"))?;
        } else if arg.starts_with('-') { return Err(format!("unknown flag: {arg}")); }
        else { pos.push(slice[i].clone()); }
        i += 1;
    }
    let command = match pos.first().map(String::as_str).ok_or("missing subcommand")? {
        "status" if pos.len() == 1 => ControlCommand::Status, "ensure" if pos.len() == 1 => ControlCommand::Ensure { timeout_secs },
        "repair" if pos.len() == 1 => ControlCommand::Repair { timeout_secs }, "disconnect" if pos.len() == 1 => ControlCommand::Disconnect,
        "shortcuts" if pos.len() == 1 => ControlCommand::Shortcuts, "open-sso" if pos.len() == 2 => ControlCommand::OpenSso { shortcut_id: pos[1].clone(), timeout_secs },
        "callback" if pos.len() == 2 && !json => return Ok(CliInvocation::Callback { raw_url: pos[1].clone() }),
        "callback" if pos.len() == 2 => ControlCommand::Callback { raw_url: pos[1].clone() },
        _ => return Err(format!("invalid command: {}", pos.join(" "))),
    };
    Ok(CliInvocation::Cli { command, json })
}

pub fn apply_event_to_snapshot(snap: &mut TunnelSnapshot, event: &SessionEvent, now_secs: u64) {
    match event {
        SessionEvent::ConnectingPhase { phase, .. } if snap.phase != TunnelPhase::Connected => {
            snap.phase = TunnelPhase::Connecting; snap.connected = false; snap.status_line = phase.clone(); snap.detail = None;
        }
        SessionEvent::TunnelActive { notice, .. } => {
            snap.phase = TunnelPhase::Connected; snap.connected = true; snap.status_line = "校园网已连接".to_string();
            snap.detail = None; snap.interface = Some(notice.interface.clone()); snap.route_ready = true; snap.active_since_epoch_secs.get_or_insert(now_secs);
        }
        SessionEvent::Disconnected { reason, .. } => {
            if let Some(msg) = reason.strip_prefix("ATTENTION:") {
                snap.phase = TunnelPhase::AttentionRequired; snap.status_line = "需要處理連接異常".to_string(); snap.detail = Some(msg.trim().to_string());
            } else {
                snap.phase = TunnelPhase::Disconnected; snap.status_line = reason.clone(); snap.detail = None;
            }
            snap.connected = false; snap.interface = None; snap.route_ready = false; snap.active_since_epoch_secs = None;
        }
        _ => {}
    }
}

pub fn reconcile_utun_probe(snap: &mut TunnelSnapshot, probe: Option<(String, String)>, now_secs: u64) {
    if let Some((iface, detail)) = probe {
        snap.interface = Some(iface); snap.route_ready = true;
        if snap.phase != TunnelPhase::Connected {
            snap.phase = TunnelPhase::Connected; snap.connected = true;
            snap.status_line = format!("校园网已连接 · {detail}"); snap.active_since_epoch_secs.get_or_insert(now_secs);
        }
    } else if snap.phase == TunnelPhase::Connected { *snap = TunnelSnapshot::default(); }
}

fn now_epoch_secs() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) }

fn resolve_shortcut_target(raw_id: &str) -> Option<(String, String)> {
    let q = raw_id.trim();
    match q.to_ascii_lowercase().as_str() {
        "library" => return Some(("library".to_string(), "https://www.lib.szu.edu.cn".to_string())),
        "reimbursement" => return Some(("reimbursement".to_string(), "https://ehall.szu.edu.cn/new/index.html".to_string())),
        _ => {}
    }
    default_shortcuts().into_iter().find(|s| s.id.eq_ignore_ascii_case(q) || s.id.strip_prefix("szu-").is_some_and(|st| st.eq_ignore_ascii_case(q)) || s.name == q).map(|s| (s.id, s.url))
}

pub struct ControlBroker { state: Mutex<TunnelSnapshot>, cv: Condvar, actor: TunnelHandle, url_opener: UrlOpener }

impl ControlBroker {
    #[must_use] pub fn new(actor: TunnelHandle) -> Arc<Self> {
        let opener: UrlOpener = Arc::new(|url: &str| {
            if !valid_url(url) { return Err(format!("invalid url: {url}")); }
            Command::new("/usr/bin/open").arg(url).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().map_err(|e| e.to_string())?;
            Ok(())
        });
        let broker = Self::with_opener(actor, opener);
        if let Ok(mut guard) = broker.state.lock() { reconcile_utun_probe(&mut guard, probe_connecting_campus_utun().map(|n| (n.interface, n.virtual_ipv4)), now_epoch_secs()); }
        broker
    }
    #[must_use] pub fn with_opener(actor: TunnelHandle, url_opener: UrlOpener) -> Arc<Self> {
        Arc::new(Self { state: Mutex::new(TunnelSnapshot::default()), cv: Condvar::new(), actor, url_opener })
    }
    pub fn ingest_event(&self, event: &SessionEvent) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        apply_event_to_snapshot(&mut guard, event, now_epoch_secs()); self.cv.notify_all();
    }
    fn wait_for_connected(&self, mut guard: std::sync::MutexGuard<'_, TunnelSnapshot>, action: &str, timeout_secs: u64) -> ControlResponse {
        let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(1));
        while guard.phase != TunnelPhase::Connected && guard.phase != TunnelPhase::AttentionRequired {
            let Some(rem) = deadline.checked_duration_since(Instant::now()) else { break };
            let (next, res) = self.cv.wait_timeout(guard, rem).unwrap_or_else(|e| e.into_inner());
            guard = next; if res.timed_out() { break; }
        }
        let snap = guard.clone(); let ok = snap.phase == TunnelPhase::Connected;
        let err = (!ok).then_some(if snap.phase == TunnelPhase::AttentionRequired { "attention_required" } else { "connect_timeout" });
        ControlResponse::new(ok, action, snap.clone(), err, snap.status_line)
    }
    #[must_use] pub fn handle_command(&self, cmd: ControlCommand) -> ControlResponse {
        match cmd {
            ControlCommand::Status => {
                let snap = self.state.lock().unwrap_or_else(|e| e.into_inner()).clone();
                ControlResponse::new(true, "status", snap.clone(), None, snap.status_line)
            }
            ControlCommand::Ensure { timeout_secs } => {
                let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if guard.phase == TunnelPhase::Connected { let snap = guard.clone(); return ControlResponse::new(true, "ensure", snap.clone(), None, snap.status_line); }
                if guard.phase != TunnelPhase::Connecting {
                    guard.phase = TunnelPhase::Connecting; guard.connected = false; guard.status_line = "正在建立校园网连接…".to_string(); guard.detail = None;
                    let _ = self.actor.send(SessionCommand::Connect { resolve_domains: WorkbenchViewModel::new().in_tunnel_resolve_domains() });
                }
                self.wait_for_connected(guard, "ensure", timeout_secs)
            }
            ControlCommand::OpenSso { shortcut_id, timeout_secs } => {
                let Some((resolved_id, url)) = resolve_shortcut_target(&shortcut_id) else {
                    let snap = self.state.lock().unwrap_or_else(|e| e.into_inner()).clone();
                    let mut r = ControlResponse::new(false, "open-sso", snap, Some("unknown_shortcut"), format!("unknown shortcut: {shortcut_id}"));
                    r.shortcut_id = Some(shortcut_id); return r;
                };
                let mut ensured = self.handle_command(ControlCommand::Ensure { timeout_secs });
                ensured.action = "open-sso".to_string(); ensured.shortcut_id = Some(resolved_id);
                if !ensured.ok { return ensured; }
                if let Err(err) = (self.url_opener)(&url) { ensured.ok = false; ensured.error_code = Some("open_failed".to_string()); ensured.message = err; return ensured; }
                ensured.target_url = Some(url.clone()); ensured.message = format!("opened {url}"); ensured
            }
            ControlCommand::Repair { timeout_secs } => {
                let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
                guard.phase = TunnelPhase::Connecting; guard.connected = false; guard.status_line = "正在自动修复校园网隧道…".to_string();
                let _ = self.actor.send(SessionCommand::Repair); self.wait_for_connected(guard, "repair", timeout_secs)
            }
            ControlCommand::Disconnect => {
                let _ = self.actor.send(SessionCommand::Disconnect);
                let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
                *guard = TunnelSnapshot { status_line: "已断开校园网隧道".to_string(), ..TunnelSnapshot::default() };
                let snap = guard.clone(); self.cv.notify_all();
                ControlResponse::new(true, "disconnect", snap.clone(), None, snap.status_line)
            }
            ControlCommand::Shortcuts => {
                let snap = self.state.lock().unwrap_or_else(|e| e.into_inner()).clone();
                let summary: Vec<String> = default_shortcuts().into_iter().map(|s| format!("{}:{}", s.id, s.url)).collect();
                ControlResponse::new(true, "shortcuts", snap, None, summary.join(", "))
            }
            ControlCommand::Callback { raw_url } => {
                let snap = self.state.lock().unwrap_or_else(|e| e.into_inner()).clone();
                let Some(valid) = validate_securelink_callback_url(&raw_url) else {
                    return ControlResponse::new(false, "callback", snap, Some("invalid_callback"), "invalid securelink callback URL".to_string());
                };
                let _ = self.actor.send(SessionCommand::HandleCallbackUrl(valid.clone()));
                let mut r = ControlResponse::new(true, "callback", snap, None, "callback forwarded".to_string());
                r.target_url = Some(valid); r
            }
        }
    }
}

#[must_use] pub fn default_control_socket_path() -> PathBuf {
    if let Some(p) = env::var_os("SZU_SECURELINK_CONTROL_SOCKET").filter(|v| !v.is_empty()) { return PathBuf::from(p); }
    env::var_os("HOME").map_or_else(|| env::temp_dir().join("szu-securelink-control.sock"), |h| PathBuf::from(h).join("Library/Application Support/szu-securelink/control.sock"))
}

fn encode_command_line(cmd: &ControlCommand) -> String {
    match cmd {
        ControlCommand::Status => "status".to_string(), ControlCommand::Disconnect => "disconnect".to_string(), ControlCommand::Shortcuts => "shortcuts".to_string(),
        ControlCommand::Ensure { timeout_secs } => format!("ensure --timeout {timeout_secs}"),
        ControlCommand::OpenSso { shortcut_id, timeout_secs } => format!("open-sso {shortcut_id} --timeout {timeout_secs}"),
        ControlCommand::Repair { timeout_secs } => format!("repair --timeout {timeout_secs}"),
        ControlCommand::Callback { raw_url } => format!("callback {raw_url} --json"),
    }
}

pub fn send_socket_request(socket_path: &Path, cmd: &ControlCommand) -> Result<ControlResponse, String> {
    let mut stream = UnixStream::connect(socket_path).map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(65)));
    writeln!(stream, "{}", encode_command_line(cmd)).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).map_err(|e| e.to_string())?;
    ControlResponse::from_json_line(&line)
}

#[must_use] pub fn spawn_control_daemon_at(actor: TunnelHandle, actor_events: Receiver<SessionEvent>, socket_path: PathBuf) -> Receiver<SessionEvent> {
    let (ui_tx, ui_rx) = async_util::unbounded::<SessionEvent>();
    let (broker, tee_broker) = { let b = ControlBroker::new(actor); (b.clone(), b) };
    thread::spawn(move || while let Ok(ev) = actor_events.recv_blocking() { tee_broker.ingest_event(&ev); let _ = ui_tx.try_send(ev); });
    thread::spawn(move || {
        if let Some(parent) = socket_path.parent() { let _ = fs::create_dir_all(parent); let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700)); }
        if socket_path.exists() { if UnixStream::connect(&socket_path).is_ok() { return; } let _ = fs::remove_file(&socket_path); }
        let Ok(listener) = UnixListener::bind(&socket_path) else { return };
        let _ = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600));
        for stream in listener.incoming().flatten() {
            let b = broker.clone();
            thread::spawn(move || {
                let mut line = String::new();
                if BufReader::new(&stream).read_line(&mut line).is_ok() {
                    let tokens: Vec<String> = line.split_whitespace().map(str::to_string).collect();
                    let cmd = match parse_cli_args(&tokens) {
                        Ok(CliInvocation::Cli { command, .. }) => command,
                        Ok(CliInvocation::Callback { raw_url }) => ControlCommand::Callback { raw_url },
                        _ => return,
                    };
                    let mut out = &stream; let _ = writeln!(out, "{}", b.handle_command(cmd).to_json());
                }
            });
        }
    });
    ui_rx
}

#[must_use] pub fn spawn_control_daemon(actor: TunnelHandle, actor_events: Receiver<SessionEvent>) -> Receiver<SessionEvent> {
    spawn_control_daemon_at(actor, actor_events, default_control_socket_path())
}

#[must_use] pub fn execute_cli_command(cmd: ControlCommand, json_mode: bool) -> (i32, String) {
    let resp = send_socket_request(&default_control_socket_path(), &cmd).unwrap_or_else(|_| {
        if matches!(cmd, ControlCommand::Status) {
            let mut snap = TunnelSnapshot::default();
            reconcile_utun_probe(&mut snap, probe_connecting_campus_utun().map(|n| (n.interface, n.virtual_ipv4)), now_epoch_secs());
            return ControlResponse::new(true, "status", snap.clone(), None, snap.status_line);
        }
        let (handle, events) = TunnelActor::spawn(TunnelConfig::from_bundle_env());
        let (broker, tee) = { let b = ControlBroker::new(handle); (b.clone(), b) };
        thread::spawn(move || while let Ok(ev) = events.recv_blocking() { tee.ingest_event(&ev); });
        broker.handle_command(cmd)
    });
    (if resp.ok { 0 } else { 1 }, if json_mode { resp.to_json() } else { resp.to_human() })
}
}
pub use inner::*;
