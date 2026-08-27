//! aidctl — look at what the daemon is doing, and tell it to do things.
//!
//! Two jobs, and the split matters:
//!
//! * **Administration** — install and remove models, set aliases, grant and
//!   revoke. Every one of these goes through the same D-Bus methods any other
//!   client would use and is subject to the same polkit action, so `aidctl` is
//!   convenient rather than privileged. Running it as root does not skip a
//!   check; it satisfies one.
//! * **Inspection** — status, sessions, grants, and `generate`, which opens a
//!   real session and streams a real answer. That last one exists because
//!   "the daemon is running" and "the daemon works" are different claims, and
//!   only the second one is worth making.

use std::collections::HashMap;
use std::io::{BufReader, IsTerminal, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;

use ai_daemon_proto::frame::{
    self, Event, Frame, MediaKind, Message, Params, Request, ToolResultItem, ToolSchema,
};
use ai_daemon_proto::DATA_PROTO;
use zbus::blocking::Connection;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

const BUS_NAME: &str = "io.github.agraves.AIDaemon1";
const MANAGER_PATH: &str = "/io/github/agraves/AIDaemon1/Manager";
const MANAGER_IFACE: &str = "io.github.agraves.AIDaemon1.Manager";
const SESSION_IFACE: &str = "io.github.agraves.AIDaemon1.Session";
// The portal, on the session bus. An interim name until
// org.freedesktop.portal.AI is accepted into xdg-desktop-portal, at which
// point an app changes this string and nothing else.
const PORTAL_NAME: &str = "io.github.agraves.AIPortal1";
const PORTAL_PATH: &str = "/io/github/agraves/AIPortal1";
const PORTAL_IFACE: &str = "org.freedesktop.portal.AI";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("help");
    let rest = &args[1.min(args.len())..];

    let result = match command {
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        "--version" | "-V" | "version" => {
            println!("aidctl {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "status" => status(),
        "models" => models(),
        "aliases" => aliases(),
        "resolve" => resolve(rest),
        "sessions" => sessions(),
        "grants" => grants(),
        "grant" => grant(rest, true),
        "deny" => grant(rest, false),
        "revoke" => revoke(rest),
        "install" => install(rest),
        "portal" => portal(rest),
        "spend" => spend(),
        "audit" => audit(rest),
        "remove" => remove(rest),
        "alias" => set_alias(rest),
        "pin" => pin(rest, true),
        "unpin" => pin(rest, false),
        "generate" => generate(rest),
        "generate-media" => generate_media(rest),
        "embed" => embed(rest),
        "tokenize" => tokenize(rest),
        other => Err(format!("unknown command {other:?}; try `aidctl help`")),
    };

    if let Err(e) = result {
        eprintln!("aidctl: {e}");
        std::process::exit(1);
    }
}

fn connect() -> Result<Connection, String> {
    Connection::system().map_err(|e| {
        format!("cannot reach the system bus: {e}\nIs dbus running, and is ai-daemon installed?")
    })
}

fn call<B, R>(method: &str, body: &B) -> Result<R, String>
where
    B: serde::ser::Serialize + zbus::zvariant::DynamicType,
    R: for<'d> zbus::zvariant::DynamicDeserialize<'d>,
{
    let connection = connect()?;
    let reply = connection
        .call_method(Some(BUS_NAME), MANAGER_PATH, Some(MANAGER_IFACE), method, body)
        .map_err(|e| format!("{method}: {e}"))?;
    reply.body().deserialize().map_err(|e| format!("{method} reply: {e}"))
}

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

fn status() -> Result<(), String> {
    let info: HashMap<String, OwnedValue> = call("Status", &())?;
    let get = |key: &str| info.get(key).map(render).unwrap_or_else(|| "-".into());
    println!("ai-daemon {}", get("version"));
    println!("  bus name        {BUS_NAME}");
    println!("  uptime          {}s (idle {}s)", get("uptime_seconds"), get("idle_seconds"));
    println!("  consent mode    {}", get("consent_mode"));
    println!("  sessions        {}", get("sessions"));
    println!(
        "  kv cache        {} of {} bytes",
        get("kv_used_bytes"),
        get("kv_budget_bytes")
    );
    println!("  audit log       {}", get("audit_log"));
    println!("  backends        {}", get("backends"));
    println!("  running         {}", get("running"));
    Ok(())
}

fn models() -> Result<(), String> {
    let models: Vec<HashMap<String, OwnedValue>> = call("ListModels", &())?;
    if models.is_empty() {
        println!("no models installed; try `aidctl install --help`");
        return Ok(());
    }
    let (name, format, quant, store, size, digest) =
        ("NAME", "FORMAT", "QUANT", "STORE", "SIZE", "DIGEST");
    println!("{name:<28} {format:<8} {quant:<10} {store:<8} {size:<12} {digest}");
    for model in models {
        let get = |key: &str| model.get(key).map(render).unwrap_or_default();
        let bytes: u64 = model
            .get("weights_bytes")
            .and_then(|v| u64::try_from(v.clone()).ok())
            .unwrap_or(0);
        println!(
            "{:<28} {:<8} {:<10} {:<8} {:<12} {}{}",
            get("name"),
            get("format"),
            if get("quantization").is_empty() { "-".to_string() } else { get("quantization") },
            get("store"),
            human_bytes(bytes),
            get("digest"),
            // Worth a word in the one place a person lists what is installed.
            // The format column already says `remote`, but that is jargon and
            // "not local" is the fact.
            match (get("format") == "remote", get("pinned") == "true") {
                (true, true) => "  (not local, pinned)",
                (true, false) => "  (not local)",
                (false, true) => "  (pinned)",
                (false, false) => "",
            }
        );
    }
    Ok(())
}

fn aliases() -> Result<(), String> {
    let aliases: HashMap<String, String> = call("ListAliases", &())?;
    if aliases.is_empty() {
        println!("no aliases; apps asking for `default` will not resolve");
        return Ok(());
    }
    let mut sorted: Vec<_> = aliases.into_iter().collect();
    sorted.sort();
    for (alias, target) in sorted {
        println!("{alias:<12} -> {target}");
    }
    Ok(())
}

fn resolve(args: &[String]) -> Result<(), String> {
    let alias = args.first().ok_or("usage: aidctl resolve ALIAS")?;
    let name: String = call("Resolve", &(alias.as_str(),))?;
    println!("{name}");
    Ok(())
}

fn sessions() -> Result<(), String> {
    let sessions: Vec<HashMap<String, OwnedValue>> = call("ListSessions", &())?;
    if sessions.is_empty() {
        println!("no open sessions");
        return Ok(());
    }
    let (id, identity, model, priority, state, tokens) =
        ("ID", "IDENTITY", "MODEL", "PRIORITY", "STATE", "TOKENS(p/c)");
    println!("{id:<6} {identity:<34} {model:<20} {priority:<12} {state:<12} {tokens}");
    for session in sessions {
        let get = |key: &str| session.get(key).map(render).unwrap_or_default();
        println!(
            "{:<6} {:<34} {:<20} {:<12} {:<12} {}/{}",
            get("id"),
            get("identity"),
            get("model"),
            get("priority"),
            get("state"),
            get("prompt_tokens"),
            get("completion_tokens")
        );
    }
    Ok(())
}

/// What has been spent in the rolling day, and against what ceiling.
fn spend() -> Result<(), String> {
    let rows: Vec<(String, String, String)> = call("Spend", &())?;
    if rows.is_empty() {
        println!("nothing spent, and no ceiling set");
        println!();
        println!("Prices are an administrator's table in config.toml. A model with no");
        println!("entry costs nothing, which is right for a local one — so this stays");
        println!("empty on a machine that never configured a remote provider.");
        return Ok(());
    }
    println!("{:<38} {:>12} {:>12}", "IDENTITY", "SPENT", "PER DAY");
    for (identity, spent, ceiling) in rows {
        println!("{identity:<38} {spent:>12} {ceiling:>12}");
    }
    println!();
    println!("A rolling 24 hours, not a calendar day: the oldest requests age out.");
    Ok(())
}

/// Check the audit log's hash chain.
///
/// Reads the file directly rather than asking the daemon: a log you can only
/// verify by asking the process that wrote it is not evidence of anything.
/// Point it at a copy, on another machine, with the daemon stopped — that is
/// the case this is for.
fn audit(args: &[String]) -> Result<(), String> {
    let mut path = std::path::PathBuf::from("/var/lib/ai-daemon/audit.jsonl");
    let mut iter = args.iter();
    let mut verify = false;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--verify" => verify = true,
            "--file" => path = iter.next().map(std::path::PathBuf::from).unwrap_or(path),
            "--help" => {
                println!(
                    "usage: aidctl audit --verify [--file PATH]

Walks the hash chain and reports the first break: which line, and whether
something was changed, removed or reordered. Each record carries the hash
of the line before it, so an edit after the fact cannot leave the file
consistent without rewriting everything after it.

Tamper-evident, not tamper-proof. Somebody who owns the file can rewrite
the chain from the point of an edit; what this costs them is the whole
remainder rather than one line, and it makes a truncated tail visible."
                );
                return Ok(());
            }
            other => return Err(format!("unknown option {other:?}")),
        }
    }
    if !verify {
        return Err("say what to do: --verify".into());
    }
    match ai_daemon_audit_verify(&path) {
        Ok(n) => {
            println!("{} record(s) checked, chain intact", n);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// The verifier, inlined rather than linked.
///
/// `aidctl` does not depend on the daemon crate — deliberately, so the client
/// cannot accidentally pull the policy engine into a user-run binary — so the
/// twenty lines that read a chain live in both places. They are duplicated on
/// purpose and the format is the contract: a record's `prev` is the sha256 of
/// the previous line, verbatim, which `sha256sum` will also tell you.
fn ai_daemon_audit_verify(path: &std::path::Path) -> Result<u64, String> {
    use sha2::{Digest, Sha256};
    let hash_line = |line: &str| {
        let mut hasher = Sha256::new();
        hasher.update(line.as_bytes());
        format!("{:x}", hasher.finalize())
    };
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("reading {}: {e}", path.display()))?;
    let mut expected: Option<String> = None;
    let mut checked = 0u64;
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        if line.trim().is_empty() {
            continue;
        }
        let record: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| format!("line {number} is not a record: {e}"))?;
        let carried = record.get("prev").and_then(|p| p.as_str());
        match (&expected, carried) {
            (None, None) => {}
            (None, Some(p)) => {
                return Err(format!(
                    "line {number} claims to follow {} but it is the first record in this \
                     file — everything before it is missing",
                    &p[..16.min(p.len())]
                ))
            }
            (Some(_), None) => {
                return Err(format!(
                    "line {number} carries no link, so the chain restarts here — a record \
                     written by something that did not know about the chain, or a splice"
                ))
            }
            (Some(want), Some(got)) if want != got => {
                return Err(format!(
                    "line {number} follows {} but the record before it hashes to {} — \
                     something between them was changed, removed or reordered",
                    &got[..16.min(got.len())],
                    &want[..16.min(want.len())]
                ))
            }
            (Some(_), Some(_)) => {}
        }
        expected = Some(hash_line(line));
        checked += 1;
    }
    Ok(checked)
}

fn grants() -> Result<(), String> {
    let grants: Vec<(String, String, String, u64, String)> = call("ListGrants", &())?;
    if grants.is_empty() {
        println!("no remembered grants");
        return Ok(());
    }
    let (identity, capability, decision, via, when) =
        ("IDENTITY", "CAPABILITY", "DECISION", "VIA", "WHEN");
    println!("{identity:<38} {capability:<16} {decision:<8} {via:<10} {when}");
    for (identity, capability, decision, at, via) in grants {
        println!("{identity:<38} {capability:<16} {decision:<8} {via:<10} {at}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Administration
// ---------------------------------------------------------------------------

fn grant(args: &[String], allow: bool) -> Result<(), String> {
    let (identity, capability) = match args {
        [identity, capability] => (identity, capability),
        _ => return Err("usage: aidctl grant|deny IDENTITY CAPABILITY".into()),
    };
    call::<_, ()>("SetGrant", &(identity.as_str(), capability.as_str(), allow))?;
    println!(
        "{} {capability} for {identity}",
        if allow { "granted" } else { "denied" }
    );
    Ok(())
}

fn revoke(args: &[String]) -> Result<(), String> {
    let identity = args.first().ok_or("usage: aidctl revoke IDENTITY")?;
    let removed: u32 = call("Revoke", &(identity.as_str(),))?;
    println!("revoked {removed} grant(s) for {identity}");
    Ok(())
}

fn install(args: &[String]) -> Result<(), String> {
    let mut source = String::new();
    let mut digest = String::new();
    let mut name = String::new();
    let mut options: HashMap<String, OwnedValue> = HashMap::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--source" => source = iter.next().cloned().unwrap_or_default(),
            "--digest" => digest = iter.next().cloned().unwrap_or_default(),
            "--name" => name = iter.next().cloned().unwrap_or_default(),
            "--context" | "--max-context" => {
                let value = iter.next().and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
                options.insert(
                    "max_ctx".into(),
                    Value::U32(value).try_into().map_err(|_| "context")?,
                );
            }
            "--format" | "--backend" | "--license" => {
                let key = arg.trim_start_matches("--").to_string();
                let value = iter.next().cloned().unwrap_or_default();
                options.insert(
                    key,
                    Value::Str(value.as_str().into()).try_into().map_err(|_| "option")?,
                );
            }
            "--capability" => {
                let value = iter.next().cloned().unwrap_or_default();
                let mut existing: Vec<String> = options
                    .get("capabilities")
                    .and_then(|v| Vec::<String>::try_from(v.clone()).ok())
                    .unwrap_or_default();
                existing.push(value);
                options.insert(
                    "capabilities".into(),
                    Value::Array(existing.into()).try_into().map_err(|_| "capabilities")?,
                );
            }
            "--help" => {
                println!(
                    "usage: aidctl install --name NAME --source URL --digest sha256:HEX
              [--format gguf] [--backend NAME] [--license SPDX]
              [--capability generate] [--capability embed] ...

Capabilities are checked twice and both are refusals, not warnings: at
install, a capability no configured backend serves for this format is
refused rather than recorded; at request, a model is refused a capability
it did not claim even when its backend offers it. Default is
--capability generate, so a model that should also embed needs it named.

  --context N     the largest context this model can serve. Absent means
                  unknown, which is treated as no ceiling — policy and the
                  backend still bound it. It is not detected from the weights:
                  reading a GGUF header would mean a weight parser in the
                  daemon, and that is the backend's job. If you install a 32k
                  model without this, sessions get whatever policy allows.

Sources: https://…, file:///…, oci://registry/repo@sha256:…, remote:MODEL-ID
The digest is mandatory except for a remote: source. The download runs in
ai-daemon-fetch, which has a network and no access to the model store; the
daemon verifies the bytes and moves them in. That helper also runs with
ProtectHome=yes, so a file:// path under /home or /root is invisible to it
however the file is permissioned — stage those outside home (/var/cache, /srv
and /tmp all work) and install from there. --format gguf (the default) is
checked against the file's magic, so a mislabelled file is refused rather
than handed to a backend.

  remote:MODEL-ID registers a model that lives on somebody else's machine
  and is served by the configured remote provider. Nothing is downloaded
  and there is nothing to verify, so no digest is asked for: the integrity
  of a remote model is the endpoint's promise, not this machine's
  measurement. Every session on it reports local=false, and the consent
  prompt says so before the first prompt goes anywhere."
                );
                return Ok(());
            }
            other => return Err(format!("unknown option {other:?}")),
        }
    }
    // A remote model has no bytes here, so there is no digest to demand.
    // Refusing one that was supplied anyway rather than ignoring it: a digest
    // on a remote install would look like verification that is not happening.
    let remote = source.starts_with("remote:");
    if remote && !digest.is_empty() {
        return Err("a remote: source takes no --digest; nothing is downloaded to verify".into());
    }
    if source.is_empty() || name.is_empty() || (digest.is_empty() && !remote) {
        return Err("--name, --source and --digest are all required".into());
    }
    let installed: String =
        call("InstallModel", &(source.as_str(), digest.as_str(), name.as_str(), options))?;
    println!("installed {installed}");
    Ok(())
}

fn remove(args: &[String]) -> Result<(), String> {
    let name = args.first().ok_or("usage: aidctl remove NAME")?;
    call::<_, ()>("RemoveModel", &(name.as_str(),))?;
    println!("removed {name}");
    Ok(())
}

fn set_alias(args: &[String]) -> Result<(), String> {
    let (alias, target) = match args {
        [alias, target] => (alias, target),
        _ => return Err("usage: aidctl alias ALIAS MODEL".into()),
    };
    call::<_, ()>("SetAlias", &(alias.as_str(), target.as_str()))?;
    println!("{alias} -> {target}");
    Ok(())
}

fn pin(args: &[String], pinned: bool) -> Result<(), String> {
    let model = args.first().ok_or("usage: aidctl pin|unpin MODEL")?;
    call::<_, ()>("PinModel", &(model.as_str(), pinned))?;
    println!("{} {model}", if pinned { "pinned" } else { "unpinned" });
    Ok(())
}

// ---------------------------------------------------------------------------
// Actually using it
// ---------------------------------------------------------------------------

struct SessionHandle {
    path: OwnedObjectPath,
    socket: UnixStream,
    connection: Connection,
}

/// Ask the session portal who it thinks we are.
///
/// Useful on its own — an app that wants to show the user which identity its
/// prompts will be attributed to should not have to open a session to find out
/// — and it is the smallest possible check that a machine's portal is working.
fn portal(args: &[String]) -> Result<(), String> {
    if args.iter().any(|a| a == "--help") {
        println!(
            "usage: aidctl portal

Asks {PORTAL_NAME} on the session bus what application identity it would
assert for this process. Fails if there is no portal, or if this process is
not in a sandbox the portal can vouch for — an unsandboxed program has no
strong identity to carry and should call the daemon directly."
        );
        return Ok(());
    }
    let session = Connection::session()
        .map_err(|e| format!("cannot reach the session bus: {e}"))?;
    let (kind, app_id): (String, String) = session
        .call_method(Some(PORTAL_NAME), PORTAL_PATH, Some(PORTAL_IFACE), "Identify", &())
        .map_err(|e| format!("Identify: {e}"))?
        .body()
        .deserialize()
        .map_err(|e| format!("Identify reply: {e}"))?;
    println!("{kind} application {app_id}");
    println!("the daemon will see this as identity portal:{app_id}");
    Ok(())
}

fn open_session(model: &str, options: HashMap<String, OwnedValue>) -> Result<SessionHandle, String> {
    open_session_by(model, options, false)
}

fn open_session_by(
    model: &str,
    options: HashMap<String, OwnedValue>,
    via_portal: bool,
) -> Result<SessionHandle, String> {
    // Close always goes to the daemon on the system bus, whichever route
    // opened the session: the object path in the reply is the daemon's, and
    // the portal does not proxy it. An app that genuinely cannot reach the
    // system bus simply drops the descriptor, which the daemon treats as a
    // closed session anyway.
    let connection = connect()?;
    let reply = if via_portal {
        let session = Connection::session()
            .map_err(|e| format!("cannot reach the session bus: {e}"))?;
        session
            .call_method(
                Some(PORTAL_NAME),
                PORTAL_PATH,
                Some(PORTAL_IFACE),
                "CreateSession",
                &(model, options),
            )
            .map_err(|e| format!("portal CreateSession: {e}"))?
    } else {
        connection
            .call_method(
                Some(BUS_NAME),
                MANAGER_PATH,
                Some(MANAGER_IFACE),
                "CreateSession",
                &(model, options),
            )
            .map_err(|e| format!("CreateSession: {e}"))?
    };
    // The portal returns the descriptor first, because that is the thing the
    // app actually needs; the daemon returns the path first. Same two values.
    let (path, fd): (OwnedObjectPath, zbus::zvariant::OwnedFd) = if via_portal {
        let (fd, path): (zbus::zvariant::OwnedFd, OwnedObjectPath) = reply
            .body()
            .deserialize()
            .map_err(|e| format!("portal CreateSession reply: {e}"))?;
        (path, fd)
    } else {
        reply
            .body()
            .deserialize()
            .map_err(|e| format!("CreateSession reply: {e}"))?
    };
    let raw = std::os::fd::OwnedFd::from(fd);
    // SAFETY: the bus handed us an owned descriptor for our end of the
    // socketpair; nothing else in this process holds it.
    let socket = unsafe { UnixStream::from_raw_fd(std::os::fd::IntoRawFd::into_raw_fd(raw)) };
    Ok(SessionHandle { path, socket, connection })
}

impl SessionHandle {
    fn close(self) {
        let _ = self.connection.call_method(
            Some(BUS_NAME),
            self.path.as_str(),
            Some(SESSION_IFACE),
            "Close",
            &(),
        );
    }
}

fn generate(args: &[String]) -> Result<(), String> {
    let mut model = "default".to_string();
    let mut prompt = String::new();
    let mut system = String::new();
    let mut priority = "interactive".to_string();
    let mut max_tokens: u32 = 64;
    let mut tool: Option<String> = None;
    let mut image: Option<String> = None;
    let mut raw_image: Option<String> = None;
    let mut show_usage = false;
    let mut cancel_after: Option<u64> = None;
    let mut logprobs: Option<u32> = None;
    // So a v1 client can be impersonated on purpose. Without it, "we still
    // serve the old protocol" is a claim with nothing behind it.
    let mut proto = DATA_PROTO;
    let mut via_portal = false;
    // Narrowing, not configuring: these can only ever ask for less than the
    // caller is already allowed. That is what makes a session fd something you
    // can hand to a child — you can give away strictly less than you hold, and
    // there is no request on the far end that widens it back.
    let mut no_tools = false;
    let mut narrow_rate: Option<u64> = None;
    let mut narrow_models: Option<Vec<String>> = None;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-m" | "--model" => model = iter.next().cloned().unwrap_or_default(),
            "-s" | "--system" => system = iter.next().cloned().unwrap_or_default(),
            "--priority" => priority = iter.next().cloned().unwrap_or_default(),
            "--max-tokens" => {
                max_tokens = iter.next().and_then(|v| v.parse().ok()).unwrap_or(max_tokens)
            }
            "--tool" => tool = iter.next().cloned(),
            "--image" => image = iter.next().cloned(),
            "--image-raw" => raw_image = iter.next().cloned(),
            "--usage" => show_usage = true,
            "--logprobs" => logprobs = iter.next().and_then(|v| v.parse().ok()),
            "--proto" => proto = iter.next().and_then(|v| v.parse().ok()).unwrap_or(DATA_PROTO),
            "--cancel-after" => cancel_after = iter.next().and_then(|v| v.parse().ok()),
            "--via-portal" => via_portal = true,
            "--no-tools" => no_tools = true,
            "--narrow-rate" => narrow_rate = iter.next().and_then(|v| v.parse().ok()),
            "--narrow-models" => {
                narrow_models = iter.next().map(|v| {
                    v.split(',').map(|m| m.trim().to_string()).collect::<Vec<_>>()
                })
            }
            "--help" => {
                println!(
                    "usage: aidctl generate [options] [PROMPT]

  -m, --model NAME     model or alias (default: default)
  -s, --system TEXT    system message
      --priority CLASS interactive (default) or background
      --max-tokens N    cap the completion
      --tool FILE       JSON array of tool schemas; enables tool calling
      --no-tools        open a session that cannot make tool calls, whatever
                        this identity is otherwise permitted
      --narrow-rate N   tokens/minute for this session only, if lower than
                        what policy already allows
      --narrow-models A,B
                        restrict this session to a subset of what policy allows

                        These three can only take away. They exist so a
                        supervisor can open a session, hand the descriptor to a
                        child, and know the child holds strictly less than it
                        does — asking for more than you are allowed silently
                        gets you what you were already allowed.

      --via-portal      open the session through the session-bus portal, so
                        the daemon identifies this process by application id
                        rather than by unit. Only works inside a sandbox.
      --image FILE      attach a PNG, decoded by ai-daemon-decode
      --image-raw WxH:FILE
                        attach raw RGBA8 pixels, decoded by nobody
      --usage           print the usage record when the turn ends
      --logprobs N      ask for N alternatives per token, and show them
      --proto N         speak an older data protocol, to see what it is sent
      --cancel-after MS send the protocol's Cancel this long after asking, to
                        watch a generation actually stop

With no PROMPT, reads one from stdin."
                );
                return Ok(());
            }
            other if other.starts_with('-') => return Err(format!("unknown option {other:?}")),
            other => prompt = other.to_string(),
        }
    }
    if prompt.is_empty() {
        if std::io::stdin().is_terminal() {
            return Err("give a prompt as an argument or on stdin".into());
        }
        std::io::stdin()
            .read_to_string(&mut prompt)
            .map_err(|e| format!("reading stdin: {e}"))?;
    }

    let mut options: HashMap<String, OwnedValue> = HashMap::new();
    options.insert(
        "priority".into(),
        Value::Str(priority.as_str().into()).try_into().map_err(|_| "priority")?,
    );
    if no_tools {
        options.insert("no_tools".into(), Value::Bool(true).try_into().map_err(|_| "no_tools")?);
    }
    if let Some(rate) = narrow_rate {
        options.insert(
            "max_tokens_per_minute".into(),
            Value::U64(rate).try_into().map_err(|_| "narrow rate")?,
        );
    }
    if let Some(models) = &narrow_models {
        options.insert(
            "allowed_models".into(),
            Value::Array(models.clone().into()).try_into().map_err(|_| "narrow models")?,
        );
    }
    let session = open_session_by(&model, options, via_portal)?;
    let mut socket = session.socket.try_clone().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(session.socket.try_clone().map_err(|e| e.to_string())?);

    frame::write_cbor(&mut socket, &Request::Hello { proto })
        .map_err(|e| format!("hello: {e}"))?;
    if let Some(Event::Hello { session: info, .. }) = read_event(&mut reader)? {
        eprintln!(
            "session {} on {} (identity {}, local={}, context {})",
            info.session, info.model, info.identity, info.local, info.max_context
        );
        // What this session can actually be asked for — the model's claims
        // intersected with its backend's. Printed because the alternative is
        // finding out one refusal at a time.
        eprintln!("capabilities: {}", info.capabilities.join(", "));
    }

    let mut messages = Vec::new();
    if !system.is_empty() {
        messages.push(Message {
            role: "system".into(),
            content: system,
            attachments: Vec::new(),
            tool_call_id: None,
        });
    }
    let mut attachments = Vec::new();
    if let Some(path) = &image {
        let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
        frame::write_cbor(
            &mut socket,
            &Request::Attach {
                id: "img1".into(),
                kind: frame::AttachKind::Image,
                meta: frame::AttachMeta { encoded: Some("image/png".into()), ..Default::default() },
                len: bytes.len() as u64,
            },
        )
        .map_err(|e| format!("attach: {e}"))?;
        frame::write_blob(&mut socket, &bytes).map_err(|e| format!("attach blob: {e}"))?;
        attachments.push("img1".to_string());
    }
    if let Some(spec) = &raw_image {
        // "WIDTHxHEIGHT:path". Raw is the form that needs no codec anywhere:
        // the client decoded it, and the daemon parses nothing.
        let (dimensions, path) = spec
            .split_once(':')
            .ok_or("--image-raw takes WIDTHxHEIGHT:PATH")?;
        let (width, height) = dimensions
            .split_once('x')
            .ok_or("--image-raw takes WIDTHxHEIGHT:PATH")?;
        let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
        frame::write_cbor(
            &mut socket,
            &Request::Attach {
                id: "raw1".into(),
                kind: frame::AttachKind::Image,
                meta: frame::AttachMeta {
                    w: Some(width.parse().map_err(|_| "width")?),
                    h: Some(height.parse().map_err(|_| "height")?),
                    fmt: Some("rgba8".into()),
                    ..Default::default()
                },
                len: bytes.len() as u64,
            },
        )
        .map_err(|e| format!("attach: {e}"))?;
        frame::write_blob(&mut socket, &bytes).map_err(|e| format!("attach blob: {e}"))?;
        attachments.push("raw1".to_string());
    }

    messages.push(Message {
        role: "user".into(),
        content: prompt,
        attachments,
        tool_call_id: None,
    });

    let tools: Option<Vec<ToolSchema>> = match &tool {
        Some(path) => {
            let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            Some(serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?)
        }
        None => None,
    };

    frame::write_cbor(
        &mut socket,
        &Request::Generate {
            messages,
            stream: true,
            params: Some(Params {
                max_tokens: Some(max_tokens),
                logprobs,
                ..Default::default()
            }),
            grammar: None,
            tools: tools.clone(),
        },
    )
    .map_err(|e| format!("generate: {e}"))?;

    // The data-plane Cancel, sent from a second thread because this one is
    // about to block reading tokens — which is the whole difficulty the daemon
    // has with it too.
    if let Some(delay) = cancel_after {
        let mut socket = session.socket.try_clone().map_err(|e| e.to_string())?;
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(delay));
            let _ = frame::write_cbor(&mut socket, &Request::Cancel);
        });
    }

    let mut exit = 0;
    loop {
        match read_event(&mut reader)? {
            None => break,
            Some(Event::Token { tok, logprobs }) => {
                print!("{tok}");
                if let Some(alternatives) = logprobs {
                    let shown: Vec<String> = alternatives
                        .iter()
                        .map(|a| format!("{}={:.2}", a.tok.trim(), a.logprob))
                        .collect();
                    print!("[{}]", shown.join(" "));
                }
                let _ = std::io::stdout().flush();
            }
            Some(Event::ToolCall { tool_call }) => {
                println!("\n[tool_call {} {}({})]", tool_call.id, tool_call.name, tool_call.arguments);
                // The daemon never executes a tool. aidctl does not either; it
                // answers with a placeholder so the round-trip (§10) is
                // visible end to end, and says exactly that.
                println!("[aidctl does not execute tools; replying with a canned result]");
                frame::write_cbor(
                    &mut socket,
                    &Request::ToolResult { id: tool_call.id.clone(), content: canned() },
                )
                .map_err(|e| format!("tool_result: {e}"))?;
            }
            Some(Event::ToolCalls { tool_calls }) => {
                // The point of the batch: a real client runs these
                // concurrently. Answering them one at a time would put back
                // the serialisation the model just avoided.
                println!("\n[tool_calls {}]", tool_calls.len());
                for call in &tool_calls {
                    println!("  {} {}({})", call.id, call.name, call.arguments);
                }
                println!("[aidctl does not execute tools; replying with canned results]");
                frame::write_cbor(
                    &mut socket,
                    &Request::ToolResults {
                        results: tool_calls
                            .iter()
                            .map(|call| ToolResultItem { id: call.id.clone(), content: canned() })
                            .collect(),
                    },
                )
                .map_err(|e| format!("tool_results: {e}"))?;
            }
            Some(Event::Media { media }) => {
                let bytes = read_blob(&mut reader, media.len)?;
                let name = match media.kind {
                    MediaKind::Image => format!("{}.rgba", media.id),
                    MediaKind::Audio => format!("{}.f32", media.id),
                };
                std::fs::write(&name, &bytes).map_err(|e| format!("{name}: {e}"))?;
                match media.kind {
                    MediaKind::Image => println!(
                        "[media {} image {}x{} {} -> {name} ({} bytes)]",
                        media.id,
                        media.w.unwrap_or(0),
                        media.h.unwrap_or(0),
                        media.fmt.as_deref().unwrap_or("rgba8"),
                        bytes.len()
                    ),
                    MediaKind::Audio => println!(
                        "[media {} audio {} samples at {} Hz -> {name}]",
                        media.id,
                        bytes.len() / 4,
                        media.rate.unwrap_or(0)
                    ),
                }
            }
            Some(Event::Notice { event, detail }) => {
                eprintln!("\n[{event}] {detail}");
            }
            Some(Event::Done { usage, finish_reason, .. }) => {
                if finish_reason.as_deref() == Some("tool_call") {
                    continue;
                }
                println!();
                if show_usage {
                    eprintln!(
                        "usage: prompt={} completion={} attachment={} finish={}",
                        usage.prompt_tokens,
                        usage.completion_tokens,
                        usage.attachment_tokens,
                        finish_reason.unwrap_or_else(|| "-".into())
                    );
                }
                break;
            }
            Some(Event::Error { error }) => {
                eprintln!("\n[{}] {}", error.code, error.message);
                exit = 1;
                break;
            }
            Some(other) => eprintln!("[unexpected event {other:?}]"),
        }
    }

    session.close();
    if exit != 0 {
        std::process::exit(exit);
    }
    Ok(())
}

/// Ask for an image or a clip and write what comes back.
fn generate_media(args: &[String]) -> Result<(), String> {
    let mut model = "default".to_string();
    let mut kind = MediaKind::Image;
    let mut prompt = String::new();
    let mut count: u32 = 1;
    let mut proto = DATA_PROTO;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-m" | "--model" => model = iter.next().cloned().unwrap_or_default(),
            "--audio" => kind = MediaKind::Audio,
            "--image" => kind = MediaKind::Image,
            "--count" => count = iter.next().and_then(|v| v.parse().ok()).unwrap_or(1),
            "--proto" => proto = iter.next().and_then(|v| v.parse().ok()).unwrap_or(DATA_PROTO),
            "--help" => {
                println!(
                    "usage: aidctl generate-media [--image|--audio] [-m MODEL] [--count N] PROMPT

Writes each result beside you as <session>-<n>.rgba or .f32 — raw, because
the daemon links no encoders any more than it links decoders. Needs the
generate-media capability and a backend declaring image-out or audio-out."
                );
                return Ok(());
            }
            other if other.starts_with('-') => return Err(format!("unknown option {other:?}")),
            other => prompt = other.to_string(),
        }
    }
    if prompt.is_empty() {
        return Err("give a prompt".into());
    }

    let session = open_session(&model, HashMap::new())?;
    let mut socket = session.socket.try_clone().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(session.socket.try_clone().map_err(|e| e.to_string())?);
    frame::write_cbor(&mut socket, &Request::Hello { proto })
        .map_err(|e| format!("hello: {e}"))?;
    let _ = read_event(&mut reader);

    frame::write_cbor(
        &mut socket,
        &Request::GenerateMedia { kind, prompt, params: None, count },
    )
    .map_err(|e| format!("generate_media: {e}"))?;

    let mut exit = 0;
    loop {
        match read_event(&mut reader)? {
            None => break,
            Some(Event::Media { media }) => {
                let bytes = read_blob(&mut reader, media.len)?;
                let name = match media.kind {
                    MediaKind::Image => format!("{}.rgba", media.id),
                    MediaKind::Audio => format!("{}.f32", media.id),
                };
                std::fs::write(&name, &bytes).map_err(|e| format!("{name}: {e}"))?;
                match media.kind {
                    MediaKind::Image => println!(
                        "image {}x{} {} -> {name} ({} bytes)",
                        media.w.unwrap_or(0),
                        media.h.unwrap_or(0),
                        media.fmt.as_deref().unwrap_or("rgba8"),
                        bytes.len()
                    ),
                    MediaKind::Audio => println!(
                        "audio {} samples at {} Hz -> {name}",
                        bytes.len() / 4,
                        media.rate.unwrap_or(0)
                    ),
                }
            }
            Some(Event::Done { usage, .. }) => {
                println!("usage: media_bytes={}", usage.media_bytes);
                break;
            }
            Some(Event::Error { error }) => {
                eprintln!("[{}] {}", error.code, error.message);
                exit = 1;
                break;
            }
            Some(_) => {}
        }
    }
    session.close();
    if exit != 0 {
        std::process::exit(exit);
    }
    Ok(())
}

fn embed(args: &[String]) -> Result<(), String> {
    let mut model = "embed".to_string();
    let mut inputs: Vec<String> = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-m" | "--model" => model = iter.next().cloned().unwrap_or_default(),
            "--help" => {
                println!("usage: aidctl embed [-m MODEL] TEXT [TEXT...]");
                return Ok(());
            }
            other => inputs.push(other.to_string()),
        }
    }
    if inputs.is_empty() {
        return Err("give at least one string to embed".into());
    }

    let session = open_session(&model, HashMap::new())?;
    let mut socket = session.socket.try_clone().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(session.socket.try_clone().map_err(|e| e.to_string())?);
    frame::write_cbor(&mut socket, &Request::Embed { inputs })
        .map_err(|e| format!("embed: {e}"))?;
    loop {
        match read_event(&mut reader)? {
            None => break,
            Some(Event::Vectors { vectors }) => {
                for vector in vectors {
                    let head: Vec<String> =
                        vector.iter().take(8).map(|v| format!("{v:.4}")).collect();
                    println!("[{}] dim={}", head.join(", "), vector.len());
                }
            }
            Some(Event::Done { .. }) => break,
            Some(Event::Error { error }) => {
                session.close();
                return Err(format!("{}: {}", error.code, error.message));
            }
            Some(_) => {}
        }
    }
    session.close();
    Ok(())
}

fn tokenize(args: &[String]) -> Result<(), String> {
    let mut model = "default".to_string();
    let mut text = String::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-m" | "--model" => model = iter.next().cloned().unwrap_or_default(),
            other => text = other.to_string(),
        }
    }
    if text.is_empty() {
        return Err("usage: aidctl tokenize [-m MODEL] TEXT".into());
    }
    let session = open_session(&model, HashMap::new())?;
    let mut socket = session.socket.try_clone().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(session.socket.try_clone().map_err(|e| e.to_string())?);
    frame::write_cbor(&mut socket, &Request::Tokenize { text })
        .map_err(|e| format!("tokenize: {e}"))?;
    loop {
        match read_event(&mut reader)? {
            None => break,
            Some(Event::Tokens { tokens }) => println!("{tokens:?}"),
            Some(Event::Done { .. }) => break,
            Some(Event::Error { error }) => {
                session.close();
                return Err(format!("{}: {}", error.code, error.message));
            }
            Some(_) => {}
        }
    }
    session.close();
    Ok(())
}

fn canned() -> String {
    "{\"ok\":true,\"note\":\"canned result from aidctl\"}".into()
}

/// Read exactly `len` bytes of BLOB frames, the way every payload arrives.
fn read_blob(reader: &mut impl Read, len: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(len.min(1 << 20) as usize);
    while (bytes.len() as u64) < len {
        match frame::read_frame(reader) {
            Ok(Some(Frame::Blob(mut chunk))) => bytes.append(&mut chunk),
            Ok(Some(Frame::Cbor(_))) => return Err("a request frame interrupted the payload".into()),
            Ok(None) => return Err("the payload ended early".into()),
            Err(e) => return Err(format!("payload: {e}")),
        }
    }
    Ok(bytes)
}

fn read_event(reader: &mut impl Read) -> Result<Option<Event>, String> {
    match frame::read_frame(reader) {
        Ok(None) => Ok(None),
        Ok(Some(Frame::Blob(_))) => Err("the daemon sent a BLOB where an event was expected".into()),
        Ok(Some(Frame::Cbor(value))) => value
            .deserialized()
            .map(Some)
            .map_err(|e| format!("unrecognised event from the daemon: {e}")),
        Err(e) => Err(format!("reading from the session socket: {e}")),
    }
}

fn render(value: &OwnedValue) -> String {
    let value: &Value<'_> = value;
    match value {
        Value::Str(s) => s.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::U8(v) => v.to_string(),
        Value::U16(v) => v.to_string(),
        Value::U32(v) => v.to_string(),
        Value::U64(v) => v.to_string(),
        Value::I16(v) => v.to_string(),
        Value::I32(v) => v.to_string(),
        Value::I64(v) => v.to_string(),
        Value::F64(v) => v.to_string(),
        Value::Array(array) => {
            let items: Vec<String> = array
                .iter()
                .map(|v| match v {
                    Value::Str(s) => s.to_string(),
                    other => format!("{other:?}"),
                })
                .collect();
            if items.is_empty() {
                "-".into()
            } else {
                items.join(", ")
            }
        }
        other => format!("{other:?}"),
    }
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn print_help() {
    println!(
        "aidctl {} — administer and inspect ai-daemon

inspection
  status                      what the daemon is doing right now
  models                      installed models, both stores
  aliases                     default / fast / embed and where they point
  resolve ALIAS               what an alias resolves to for you
  sessions                    open sessions, their identities and usage
  grants                      every remembered consent decision

using it
  generate [opts] [PROMPT]    open a session and stream an answer
  generate-media [opts] PROMPT  ask for an image or a clip (§11)
  embed [-m MODEL] TEXT...    embedding vectors
  tokenize [-m MODEL] TEXT    token ids

administration (polkit action io.github.agraves.aidaemon.model-admin)
  install --name N --source URL --digest sha256:HEX [--context N]
  install --name N --source remote:MODEL-ID   a model on somebody else's machine
  portal                      what app identity the session portal would assert
  remove NAME
  alias ALIAS MODEL
  pin MODEL | unpin MODEL
  spend                       what each identity has spent today, and its ceiling
  audit --verify              walk the audit log's hash chain and report the first break
  grant IDENTITY CAPABILITY   capabilities: generate, generate-tools, generate-media, embed, model-admin
  deny IDENTITY CAPABILITY
  revoke IDENTITY             forget every grant, and close live sessions

`aidctl generate --help` and `aidctl install --help` have more.",
        env!("CARGO_PKG_VERSION")
    );
}

/// Kept so the fd we hand back to the kernel is unmistakably ours.
#[allow(dead_code)]
fn fd_of(socket: &UnixStream) -> i32 {
    socket.as_raw_fd()
}
