//! Native GPUI-Kit desktop entry point and CLI inspector for `szu-securelink`.

#![forbid(unsafe_code)]

use std::env;
use std::process::{Command, exit};
use std::time::Instant;
use szu_securelink_rs::agent_control::{
    CliInvocation, ControlCommand, default_control_socket_path, execute_cli_command,
    parse_cli_args, send_socket_request, spawn_control_daemon,
};
use szu_securelink_rs::gpui_window::run_desktop_app;
use szu_securelink_rs::gpui_workbench::WorkbenchViewModel;
use szu_securelink_rs::tunnel_actor::{TunnelActor, TunnelConfig};
use szu_securelink_rs::{run_seed_safe, run_seed_soa};

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

    let mut seed: u64 = 42;
    let mut iterations: usize = 50_000;
    let mut mode = "soa";
    let mut show_workbench = false;
    let mut run_cli_bench = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" if i + 1 < args.len() => {
                seed = args[i + 1].parse().unwrap_or(42);
                run_cli_bench = true;
                i += 2;
            }
            "--iterations" if i + 1 < args.len() => {
                iterations = args[i + 1].parse().unwrap_or(50_000);
                run_cli_bench = true;
                i += 2;
            }
            "--mode" if i + 1 < args.len() => {
                mode = args[i + 1].as_str();
                run_cli_bench = true;
                i += 2;
            }
            "--gpui-workbench" | "--workbench-snapshot" => {
                show_workbench = true;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    if show_workbench {
        let mut vm = WorkbenchViewModel::new();
        vm.set_connected("utun4", "1.1.105.34");
        let tree = vm.render_gpui_tree();
        println!("GPUI_WINDOW={} ({})", tree.label, tree.detail);
        for child in &tree.children {
            println!("  [{}] {} — {}", child.kind, child.label, child.detail);
            for card in &child.children {
                println!("    * {}: {}", card.label, card.detail);
            }
        }
        let tray = vm.render_tray_menu_tree();
        println!("GPUI_TRAY={} ({})", tray.label, tray.detail);
        return;
    }

    if run_cli_bench {
        let t0 = Instant::now();
        let val = if mode == "safe" {
            run_seed_safe(seed, iterations)
        } else {
            run_seed_soa(seed, iterations)
        };
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        println!("SEED={seed} VAL={val:.9} WALL_MS={ms:.3}");
        return;
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
