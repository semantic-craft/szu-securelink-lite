//! Native macOS AppKit window controller state & session coordinator (`#![forbid(unsafe_code)]`).
//!
//! Owns the pure-Rust [`WorkbenchWindow`] state machine (`WorkbenchViewModel`, `TunnelHandle`,
//! `MenuBarBridge`, and monotone `GenerationId`) while delegating view presentation to the
//! native macOS AppKit host (`crates/host-macos` + `platforms/macos/src/SecureLinkNativeApp.mm`)
//! via the versioned JSON envelope contract in [`crate::host_api`].

#![forbid(unsafe_code)]

use crate::async_util::{self, Receiver};
use crate::gpui_workbench::{
    ConnectionStatus, ShortcutLaunchOutcome, WorkbenchRoute, WorkbenchViewModel,
};
use crate::host_api::{build_native_snapshot, dispatch_window_request, ok_envelope};
use crate::tray_bridge::{MenuBarBridge, TrayAction};
use crate::tunnel_actor::{GenerationId, SessionCommand, SessionEvent, TunnelHandle};
use serde_json::json;
use std::cell::RefCell;
use std::rc::Rc;
use szu_host_macos::{NativeHostCallbacks, run_native_macos_app};

/// Campus network user guide URL opened from the workbench and settings footer.
pub const GUIDE_URL: &str = "https://www1.szu.edu.cn/nc/view.asp?id=631";

/// Stateful desktop workbench controller backed by [`WorkbenchViewModel`] and [`TunnelHandle`].
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
                TrayAction::ToggleConnect => {
                    self.actor.send(SessionCommand::ToggleConnect);
                }
                TrayAction::Repair => {
                    self.actor.send(SessionCommand::Repair);
                }
                TrayAction::OpenPin(id) => self.on_shortcut_clicked(&id),
                TrayAction::OpenSettings => {
                    self.vm.route = WorkbenchRoute::Settings;
                }
                TrayAction::ToggleDock => {
                    self.vm.shell_presence = self.vm.shell_presence.toggle_dock();
                    self.vm.save_preferences();
                }
                TrayAction::ToggleMenuBar => {
                    self.vm.shell_presence = self.vm.shell_presence.toggle_menu_bar();
                    self.vm.save_preferences();
                }
                TrayAction::ShowWindow => {
                    self.vm.route = WorkbenchRoute::Workbench;
                }
                TrayAction::Quit => {}
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
}

/// Launches the native macOS AppKit desktop application (`NSApplication` + `NSWindow` + `NSStatusItem`)
/// driven by [`WorkbenchWindow`] and the versioned JSON host contract in [`crate::host_api`].
pub fn run_desktop_app(actor: TunnelHandle, events: Receiver<SessionEvent>) {
    let (ui_tx, ui_rx) = async_util::unbounded::<SessionEvent>();
    let fwd_tx = ui_tx.clone();
    std::thread::spawn(move || {
        while let Ok(evt) = events.recv_blocking() {
            let _ = fwd_tx.try_send(evt);
        }
    });

    let win_cell: Rc<RefCell<Option<WorkbenchWindow>>> = Rc::new(RefCell::new(None));
    let init_cell = Rc::clone(&win_cell);
    let init_actor = actor.clone();
    let init_tx = ui_tx;

    let dispatch_cell = Rc::clone(&win_cell);
    let poll_cell = Rc::clone(&win_cell);
    let shutdown_cell = Rc::clone(&win_cell);

    let callbacks = NativeHostCallbacks {
        init_on_main_thread: Box::new(move || {
            let vm = WorkbenchViewModel::new();
            let bridge = MenuBarBridge::spawn(init_tx.clone(), &vm);
            let mut win = WorkbenchWindow::with_bridge(init_actor.clone(), bridge);
            win.vm = vm;
            let snap = build_native_snapshot(&win);
            *init_cell.borrow_mut() = Some(win);
            ok_envelope(snap)
        }),
        dispatch: Box::new(move |request_bytes| {
            let mut borrow = dispatch_cell.borrow_mut();
            let Some(win) = borrow.as_mut() else {
                return "{\"ok\":false,\"error\":\"WindowNotInitialized\"}".to_string();
            };
            dispatch_window_request(win, request_bytes)
        }),
        poll_events: Box::new(move || {
            let mut borrow = poll_cell.borrow_mut();
            let win = borrow.as_mut()?;
            let mut changed = false;
            let mut show_window = false;
            let mut quit = false;
            while let Ok(evt) = ui_rx.try_recv() {
                changed = true;
                match &evt {
                    SessionEvent::TrayAction(TrayAction::Quit) => {
                        quit = true;
                        break;
                    }
                    SessionEvent::TrayAction(TrayAction::ShowWindow | TrayAction::OpenSettings) => {
                        show_window = true;
                    }
                    _ => {}
                }
                win.apply_session_event(evt);
            }
            if !changed {
                return None;
            }
            Some(
                json!({
                    "ok": true,
                    "quit": quit,
                    "show_window": show_window,
                    "value": build_native_snapshot(win),
                })
                .to_string(),
            )
        }),
        shutdown: Box::new(move || {
            if let Some(win) = shutdown_cell.borrow_mut().take() {
                win.tray_bridge.shutdown();
                win.actor.send(SessionCommand::Shutdown);
            }
        }),
    };

    run_native_macos_app(callbacks);
}
