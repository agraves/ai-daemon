// SPDX-License-Identifier: Apache-2.0

//! ai-run — give a program inference and take away everything else.
//!
//! The argument this whole project rests on is that an application should not
//! need a provider credential or a route to the internet in order to think.
//! Every other piece here makes that *possible*; this is the piece that makes
//! it one command, and a claim somebody can check in a terminal:
//!
//! ```text
//! $ ai-run -- curl -s https://api.anthropic.com/v1/messages
//! curl: (6) Could not resolve host: api.anthropic.com
//!
//! $ ai-run -- curl -s --unix-socket $AI_DAEMON_SHIM_SOCKET http://localhost/v1/models
//! {"object":"list","data":[...]}
//! ```
//!
//! Same process, same user, no keys anywhere in it.
//!
//! ## What it actually does
//!
//! Two jobs, each the default of the invocation that wants it, either
//! overridable with `--confine-network` / `--permit-network`:
//!
//! **Bare `ai-run` confines.** It unshares the network namespace, so the
//! child gets a fresh one containing only a loopback interface that is
//! *down*. There is no route off the machine, no DNS, and nothing
//! listening — `127.0.0.1` in there is not the `127.0.0.1` the shim is on,
//! which is exactly why the shim grew a Unix socket: a socket is a
//! filesystem object and survives the namespace, where a port does not.
//!
//! **`ai-run --as NAME` identifies.** The program runs in a transient scope
//! the daemon keys back to exactly NAME, so a terminal-launched agent gets a
//! standing identity and one `[[identity]]` rule holds across every launch —
//! see the comment at the wrapper in `main`. The network is left alone by
//! default here, because the agents worth naming need their git remotes and
//! package registries; what they come for is the identity and the socket.
//!
//! Then it execs the program. It does not stay resident, does not proxy
//! anything, and holds nothing open: whatever the child can reach afterwards,
//! it reached through a descriptor or a path that was there before the exec.
//!
//! ## What it does not do
//!
//! It does not stop the child acting badly on what the model says. Nothing at
//! this layer can: if a program asks for text and then runs it, that is the
//! program's bug. What this removes is the *credential* and the *egress*, so a
//! program that has been talked into doing something regrettable cannot phone
//! it anywhere and cannot spend anyone's money doing it — and the daemon has a
//! record of the conversation's shape either way.
//!
//! It is also not a container. Filesystem, pids, and everything else are
//! unchanged and deliberately so: this is one capability removed, not a
//! sandbox pretending to be complete. Compose it with `systemd-run` or
//! `bwrap` if you want the rest.

use std::ffi::CString;

const SOCKET: &str = "/run/ai-daemon-shim/shim.sock";

fn main() {
    let mut socket = std::env::var("AI_DAEMON_SHIM_SOCKET").unwrap_or_else(|_| SOCKET.to_string());
    // None means "whichever default the invocation implies": a bare ai-run
    // exists to confine, an --as launch exists to identify — see below.
    let mut confine: Option<bool> = None;
    let mut as_name: Option<String> = None;
    let mut program: Vec<String> = Vec::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => socket = args.next().unwrap_or(socket),
            "--confine-network" | "--permit-network" => {
                let this = arg == "--confine-network";
                if confine.is_some_and(|earlier| earlier != this) {
                    eprintln!("ai-run: --confine-network and --permit-network contradict each other");
                    std::process::exit(2);
                }
                confine = Some(this);
            }
            "--as" => {
                let Some(name) = args.next() else {
                    eprintln!("ai-run: --as needs a name; try --help");
                    std::process::exit(2);
                };
                if name.is_empty()
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
                {
                    // The name becomes part of a systemd unit name and of the
                    // policy key an administrator writes; a character set this
                    // small means neither ever needs escaping.
                    eprintln!(
                        "ai-run: --as takes letters, digits, '-', '.' and '_'; {name:?} is not that"
                    );
                    std::process::exit(2);
                }
                as_name = Some(name);
            }
            "--version" | "-V" => {
                println!("ai-run {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            "--" => {
                program.extend(args);
                break;
            }
            other if other.starts_with('-') => {
                eprintln!("ai-run: unknown option {other:?}; try --help");
                std::process::exit(2);
            }
            other => {
                program.push(other.to_string());
                program.extend(args);
                break;
            }
        }
    }

    if program.is_empty() {
        eprintln!("ai-run: nothing to run; try --help");
        std::process::exit(2);
    }

    // The default follows the invocation. A bare ai-run exists to confine —
    // the name means "run with inference and nothing else", and the demo the
    // project leads with is that the network is really gone. An --as launch
    // exists to identify: the agents it names (Claude Code, codex) need their
    // git remotes and package registries, and what they come here for is the
    // standing identity and the socket. Either flag overrides either default,
    // so both modes stay one word away.
    let confining = confine.unwrap_or(as_name.is_none());

    let socket_exists = std::path::Path::new(&socket).exists();
    if confining {
        // Checked before the namespace, not after: inside there is no way to
        // fix it and the failure would look like the program's. Only when
        // confining, because only then is the socket the one door left — an
        // identified launch with the network intact may be a native D-Bus
        // client that never wanted the shim.
        if !socket_exists {
            eprintln!(
                "ai-run: {socket} does not exist, so a confined program would have no way to \
                 reach the daemon at all. Is ai-daemon-shim running?"
            );
            std::process::exit(1);
        }
        if let Err(e) = drop_network() {
            eprintln!("ai-run: {e}");
            std::process::exit(1);
        }
    }

    if socket_exists {
        // Told, not guessed: a program should not have to know this path, and
        // one that does should get it from somewhere that stays true under
        // --socket. Not set when there is no socket to point at — an
        // environment variable naming a file that is not there is a lie a
        // program will act on.
        std::env::set_var("AI_DAEMON_SHIM_SOCKET", &socket);
        // The base URL an HTTP client wants, in the form curl and most
        // libraries accept for a Unix socket.
        std::env::set_var("AI_DAEMON_SHIM_URL", "http://localhost");
    }

    // A standing identity, so a standing policy has something to attach to.
    //
    // The daemon identifies a native or socket caller by its systemd unit, and
    // a terminal-launched process has none worth keying on — a terminal tab is
    // deliberately not an app identity — so every such caller collapses to
    // `uid:<n>` and per-app policy has nothing to grip. `--as <name>` wraps
    // the program in a transient scope, `app-airun-<name>-<pid>.scope`, which
    // the daemon normalises back to exactly <name>. An administrator then
    // writes one `[[identity]]` rule against `unit:<name>@<uid>` (or
    // `shim:unit:<name>@<uid>` for an HTTP caller) and it holds across every
    // launch. The name is the caller's own claim, as every user-scope name is;
    // the uid in the key is what keeps it honest.
    //
    // Via systemd-run rather than D-Bus from here: creating the scope is the
    // user manager's job either way, and the shell-out keeps this binary free
    // of a bus stack. The scope survives the namespace because the manager's
    // socket is a filesystem object — the same reason the shim socket works.
    // If systemd-run cannot deliver the scope it exits without running the
    // program, which is the right failure: a program that ran anyway would
    // carry the anonymous identity the flag existed to replace.
    let program = match &as_name {
        Some(name) => {
            let mut wrapped = vec![
                "systemd-run".to_string(),
                "--user".to_string(),
                "--scope".to_string(),
                "--quiet".to_string(),
                "--collect".to_string(),
                format!("--unit=app-airun-{name}-{}", std::process::id()),
                "--".to_string(),
            ];
            wrapped.extend(program);
            wrapped
        }
        None => program,
    };

    let error = exec(&program);
    eprintln!("ai-run: cannot run {}: {error}", program[0]);
    std::process::exit(127);
}

/// Put this process in a network namespace of its own, containing nothing.
///
/// `unshare(CLONE_NEWNET)` needs privilege, so it is paired with
/// `CLONE_NEWUSER`: in a fresh user namespace this process is root *there* and
/// nowhere else, which is enough to own a network namespace and is not enough
/// to do anything on the host. That is the standard unprivileged path and is
/// what `bwrap` and friends use.
///
/// The new namespace has one interface, `lo`, and it is down. Nothing is
/// configured up, deliberately: a program that finds a working loopback may
/// conclude a local service is reachable, and in here none is.
///
/// The uid and gid are mapped to themselves. Without a map, `getuid()` in the
/// new namespace answers the overflow uid (65534), and anything that sends
/// credentials fails: D-Bus's EXTERNAL auth could not say who it is, so the
/// native control plane — itself a Unix socket, and so otherwise reachable
/// from in here — would be lost along with the network. The first program run
/// under this on a real machine hit exactly that. Peers on the other side of
/// a socket are unaffected either way: `SO_PEERCRED` translates into the
/// *reader's* namespace, so the daemon sees the real uid regardless.
fn drop_network() -> Result<(), String> {
    // Read before the namespace changes what the answers mean.
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    // SAFETY: unshare with two well-known flags and no arguments to get wrong.
    let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!(
            "could not take away the network ({err}). Unprivileged user namespaces may be \
             disabled on this kernel — check /proc/sys/kernel/unprivileged_userns_clone and \
             /proc/sys/user/max_user_namespaces. Running the program without confinement \
             would be worse than not running it, so this stops here; --permit-network says \
             you meant it."
        ));
    }
    // "deny" first, which is what lets an unprivileged process write gid_map
    // at all. The supplementary groups themselves are untouched: they were
    // granted outside and nothing in here can grow them.
    write_map("/proc/self/setgroups", "deny")?;
    write_map("/proc/self/uid_map", &format!("{uid} {uid} 1"))?;
    write_map("/proc/self/gid_map", &format!("{gid} {gid} 1"))?;
    Ok(())
}

/// One of the three identity files a fresh user namespace needs written.
///
/// A failure is fatal rather than shrugged at: a namespace with no map leaves
/// the program running as the overflow uid, which is confinement plus a
/// broken identity — and the breakage would surface as the program's own
/// mysterious auth failures, nowhere near the cause.
fn write_map(path: &str, content: &str) -> Result<(), String> {
    std::fs::write(path, content)
        .map_err(|e| format!("could not write {path} ({e}), so the program would run as the \
             overflow uid and anything that says who it is would fail; stopping instead"))
}

fn exec(program: &[String]) -> std::io::Error {
    let mut argv: Vec<CString> = Vec::with_capacity(program.len() + 1);
    for part in program {
        match CString::new(part.as_bytes()) {
            Ok(s) => argv.push(s),
            Err(_) => {
                return std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "an argument contains a NUL byte",
                )
            }
        }
    }
    let mut raw: Vec<*const libc::c_char> = argv.iter().map(|s| s.as_ptr()).collect();
    raw.push(std::ptr::null());
    // SAFETY: a NUL-terminated argv of NUL-terminated strings, all owned by
    // `argv` which outlives the call. execvp only returns on failure.
    unsafe { libc::execvp(raw[0], raw.as_ptr()) };
    std::io::Error::last_os_error()
}

fn print_help() {
    println!(
        "ai-run {} — run a program with inference and nothing else

usage: ai-run [options] -- PROGRAM [ARGS...]

  --socket PATH    the shim socket to leave reachable
                   (default {SOCKET}, or $AI_DAEMON_SHIM_SOCKET)
  --as NAME        run the program under a standing identity: the daemon sees
                   it as exactly NAME (unit:NAME@uid, or shim:unit:NAME@uid
                   over the socket) on every launch, so one [[identity]] rule
                   in /etc/ai-daemon/config.toml — models, rate, spend — holds
                   for good. Without this a terminal-launched program is just
                   its uid. The name is your claim, scoped to your uid; it
                   needs a systemd user session, and refuses rather than
                   running anonymously without one.
  --confine-network
                   take the network away, whatever else is asked.
  --permit-network
                   leave it alone, ditto. One of these is already the
                   default: a bare ai-run confines — the point of the bare
                   form is a program with inference and nothing else — and
                   an --as launch permits, because the agents worth naming
                   need their git remotes and package registries and come
                   here for the identity and the socket. The flags exist so
                   either choice is explicit when it matters, and so a
                   confined *and* named launch is one word:
                   ai-run --as backfill --confine-network -- ...

Confined, the program runs in a network namespace containing only a loopback
interface that is down: no route off the machine, no DNS, nothing listening.
It reaches the daemon through the shim's Unix socket, which is a filesystem
object and so survives the namespace where a port does not.

Either way, the program is told where that is:

  AI_DAEMON_SHIM_SOCKET   the socket path
  AI_DAEMON_SHIM_URL      the base URL to use with it

    curl --unix-socket \"$AI_DAEMON_SHIM_SOCKET\" \\
         \"$AI_DAEMON_SHIM_URL/v1/chat/completions\" -d '...'

What this removes is the credential and the egress. It does not stop a program
acting badly on what a model says — if it asks for text and runs it, that is
its own bug — and it is not a container: filesystem and pids are untouched,
deliberately. Compose it with systemd-run or bwrap for the rest.",
        env!("CARGO_PKG_VERSION")
    );
}
