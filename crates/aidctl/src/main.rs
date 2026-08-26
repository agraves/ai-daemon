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

use ai_daemon_proto::frame::{self, Event, Frame, Message, Params, Request, ToolSchema};
use ai_daemon_proto::DATA_PROTO;
use zbus::blocking::Connection;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

const BUS_NAME: &str = "io.github.agraves.AIDaemon1";
const MANAGER_PATH: &str = "/io/github/agraves/AIDaemon1/Manager";
const MANAGER_IFACE: &str = "io.github.agraves.AIDaemon1.Manager";
const SESSION_IFACE: &str = "io.github.agraves.AIDaemon1.Session";

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
        "remove" => remove(rest),
        "alias" => set_alias(rest),
        "pin" => pin(rest, true),
        "unpin" => pin(rest, false),
        "generate" => generate(rest),
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
            if get("pinned") == "true" { "  (pinned)" } else { "" }
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

Sources: https://…, file:///…, oci://registry/repo@sha256:…
The digest is mandatory. The download runs in ai-daemon-fetch, which has a
network and no access to the model store; the daemon verifies the bytes and
moves them in. --format gguf (the default) is checked against the file's
magic, so a mislabelled file is refused rather than handed to a backend."
                );
                return Ok(());
            }
            other => return Err(format!("unknown option {other:?}")),
        }
    }
    if source.is_empty() || digest.is_empty() || name.is_empty() {
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

fn open_session(model: &str, options: HashMap<String, OwnedValue>) -> Result<SessionHandle, String> {
    let connection = connect()?;
    let reply = connection
        .call_method(
            Some(BUS_NAME),
            MANAGER_PATH,
            Some(MANAGER_IFACE),
            "CreateSession",
            &(model, options),
        )
        .map_err(|e| format!("CreateSession: {e}"))?;
    let (path, fd): (OwnedObjectPath, zbus::zvariant::OwnedFd) = reply
        .body()
        .deserialize()
        .map_err(|e| format!("CreateSession reply: {e}"))?;
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
    let mut show_usage = false;

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
            "--usage" => show_usage = true,
            "--help" => {
                println!(
                    "usage: aidctl generate [options] [PROMPT]

  -m, --model NAME     model or alias (default: default)
  -s, --system TEXT    system message
      --priority CLASS interactive (default) or background
      --max-tokens N    cap the completion
      --tool FILE       JSON array of tool schemas; enables tool calling
      --image FILE      attach a PNG, decoded by ai-daemon-decode
      --usage           print the usage record when the turn ends

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
    let session = open_session(&model, options)?;
    let mut socket = session.socket.try_clone().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(session.socket.try_clone().map_err(|e| e.to_string())?);

    frame::write_cbor(&mut socket, &Request::Hello { proto: DATA_PROTO })
        .map_err(|e| format!("hello: {e}"))?;
    if let Some(Event::Hello { session: info, .. }) = read_event(&mut reader)? {
        eprintln!(
            "session {} on {} (identity {}, local={}, context {})",
            info.session, info.model, info.identity, info.local, info.max_context
        );
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
            params: Some(Params { max_tokens: Some(max_tokens), ..Default::default() }),
            grammar: None,
            tools: tools.clone(),
        },
    )
    .map_err(|e| format!("generate: {e}"))?;

    let mut exit = 0;
    loop {
        match read_event(&mut reader)? {
            None => break,
            Some(Event::Token { tok }) => {
                print!("{tok}");
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
                    &Request::ToolResult {
                        id: tool_call.id.clone(),
                        content: "{\"ok\":true,\"note\":\"canned result from aidctl\"}".into(),
                    },
                )
                .map_err(|e| format!("tool_result: {e}"))?;
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
  embed [-m MODEL] TEXT...    embedding vectors
  tokenize [-m MODEL] TEXT    token ids

administration (polkit action io.github.agraves.aidaemon.model-admin)
  install --name N --source URL --digest sha256:HEX
  remove NAME
  alias ALIAS MODEL
  pin MODEL | unpin MODEL
  grant IDENTITY CAPABILITY   capabilities: generate, generate-tools, embed, model-admin
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
