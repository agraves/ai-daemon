//! ai-daemon — a system inference service for desktop Linux.
//!
//! The problem this exists for is not "run a model". Ollama runs a model. The
//! problem is that every AI integration on a Linux desktop opens the same
//! unauthenticated localhost port, so the machine cannot tell its callers
//! apart, cannot arbitrate VRAM between them, cannot share one copy of the
//! weights, and has nothing to offer a sandboxed app but a hole in its
//! sandbox. macOS and Android both answered this with a privileged userspace
//! service behind a stable IPC contract. This is that, for freedesktop.
//!
//! Layout of the code follows the layout of the design:
//!
//! * [`dbusapi`] — the control plane. Enumeration, sessions, policy, models.
//! * [`session`] — the data plane. One thread and one socket per session.
//! * [`policy`] / [`identity`] / [`polkit`] — who is asking and what they may do.
//! * [`registry`] / [`install`] — one copy of the weights, verified by digest.
//! * [`backend`] — provider plugins, out of process so their crashes stay theirs.
//! * [`sched`] — decode slots and the KV budget.
//! * [`audit`] — what happened, never what was said.

mod audit;
mod backend;
mod config;
mod dbusapi;
mod decode;
mod grammar;
mod identity;
mod install;
pub mod log;
mod policy;
mod polkit;
mod registry;
mod sched;
mod session;
mod state;
mod unblock;

use std::path::PathBuf;

use crate::config::Config;
use crate::state::Daemon;

const DEFAULT_CONFIG: &str = "/etc/ai-daemon/config.toml";

fn main() {
    let mut config_path = PathBuf::from(DEFAULT_CONFIG);
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--version" | "-V" => {
                println!("ai-daemon {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            "--debug" => log::set_debug(true),
            "--config" => match args.next() {
                Some(path) => config_path = PathBuf::from(path),
                None => fatal("--config needs a path"),
            },
            other => fatal(&format!("unknown argument {other:?}; try --help")),
        }
    }
    if std::env::var_os("AI_DAEMON_DEBUG").is_some() {
        log::set_debug(true);
    }

    let config = match Config::load(&config_path) {
        Ok(config) => config,
        Err(e) => fatal(&format!("configuration: {e}")),
    };

    info!(
        "ai-daemon {} starting: state {}, {} backend(s) configured, consent {:?}",
        env!("CARGO_PKG_VERSION"),
        config.daemon.state_dir.display(),
        config.backends.iter().filter(|b| b.enabled).count(),
        config.policy.consent
    );
    if config.backends.iter().all(|b| !b.enabled) {
        warn!("no backend is enabled; every session will fail until one is configured");
    }

    let daemon = Daemon::new(config);
    daemon.spawn_janitor();

    // The blocking builder is right here even though the interface methods are
    // async: zbus runs them on its own executor thread, and `main` has nothing
    // to do afterwards but stay alive so the connection is not dropped.
    let connection = match zbus::blocking::connection::Builder::system()
        .and_then(|b| b.name(dbusapi::BUS_NAME))
        .and_then(|b| {
            b.serve_at(dbusapi::MANAGER_PATH, dbusapi::Manager { daemon: daemon.clone() })
        })
        .and_then(|b| b.build())
    {
        Ok(connection) => connection,
        Err(e) => fatal(&format!(
            "cannot take {} on the system bus: {e}",
            dbusapi::BUS_NAME
        )),
    };

    daemon.policy.attach_bus(connection.clone());
    *daemon.bus.lock().unwrap() = Some(connection.clone());
    info!("listening on the system bus as {}", dbusapi::BUS_NAME);

    // Nothing to poll: zbus drives its own executor. Park until something
    // signals us, and let the janitor decide when idleness means exit.
    loop {
        std::thread::park();
    }
}

fn print_help() {
    println!(
        "ai-daemon {} — a system inference service for desktop Linux

usage: ai-daemon [--config PATH] [--debug]

  --config PATH   configuration file (default {DEFAULT_CONFIG})
  --debug         log at debug priority; also AI_DAEMON_DEBUG=1
  --version       print the version and exit

The daemon takes {} on the system bus and is normally started by bus
activation rather than by hand. Inspect a running one with `aidctl status`.",
        env!("CARGO_PKG_VERSION"),
        dbusapi::BUS_NAME
    );
}

fn fatal(message: &str) -> ! {
    error!("{message}");
    std::process::exit(1)
}
