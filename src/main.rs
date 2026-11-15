//! Native macOS AppKit desktop entry point (`crates/host-macos` + `SecureLinkNativeApp.mm`)
//! and local CLI control plane for `szu-securelink`.

#![forbid(unsafe_code)]

use std::env;
use std::process::{Command, exit};
use szu_securelink_rs::agent_control::{
    CliInvocation, ControlCommand, default_control_socket_path, execute_cli_command,
    parse_cli_args, send_socket_request, spawn_control_daemon,
};
use szu_securelink_rs::gpui_window::run_desktop_app;
use szu_securelink_rs::tunnel_actor::{TunnelActor, TunnelConfig};

fn is_diagnostic_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--cas-connect-test"
            | "--cas-preauthentication-test"
            | "--backend-preauthentication-test"
            | "--backend-configuration-test"
            | "--legacy-ipc-mode"
            | "--finance"
            | "--session-report"
    )
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.iter().skip(1).any(|a| is_diagnostic_flag(a)) {
        let cfg = TunnelConfig::from_bundle_env();
        if let Some(diag) = cfg.diagnostic_bin {
            let status = Command::new(diag)
                .args(&args[1..])
                .status()
                .unwrap_or_else(|_| exit(1));
            exit(status.code().unwrap_or(1));
        }
    }

    match parse_cli_args(&args[1..]) {
        Ok(CliInvocation::Gui) => {
            let (handle, events) = TunnelActor::spawn(TunnelConfig::from_bundle_env());
            let events = spawn_control_daemon(handle.clone(), events);
            run_desktop_app(handle, events);
        }
        Ok(CliInvocation::Callback { raw_url }) => {
            let cmd = ControlCommand::Callback { raw_url };
            if send_socket_request(&default_control_socket_path(), &cmd).is_err() {
                let (code, _) = execute_cli_command(cmd, false);
                exit(code);
            }
        }
        Ok(CliInvocation::Cli { command, json }) => {
            let (code, out) = execute_cli_command(command, json);
            println!("{out}");
            exit(code);
        }
        Err(err) => {
            eprintln!("{err}");
            exit(2);
        }
    }
}
