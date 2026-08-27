//! ai-daemon-shim — an OpenAI-compatible endpoint on loopback, off by default.
//!
//! This is the adoption bridge from §15: every editor plugin and desktop
//! assistant on Linux already points at `http://127.0.0.1:11434` or
//! `:8080/v1`, and telling all of them to rewrite against D-Bus first is how a
//! platform never gets adopted. Point them here instead and they work
//! unchanged — but now every request passes the policy engine, appears in
//! `aidctl sessions`, is counted against a rate limit, and lands in the audit
//! log.
//!
//! Three properties are load-bearing and are enforced here rather than
//! documented:
//!
//! * **Loopback only.** The listener binds `127.0.0.1`; there is no option to
//!   bind anything else, because "no network listener ever" is a property
//!   users should be able to check rather than trust.
//! * **Lowest trust.** Everything the shim introduces is `Class::Shim` in the
//!   daemon's policy engine. A client that was written for a server with no
//!   authorisation gets the identity that deserves. Named clients (below) do
//!   not change that class — a shared secret over loopback is not peer
//!   credentials — they only stop every caller sharing one grant.
//! * **No remote fetches.** `image_url` accepts `data:` URLs and nothing else.
//!   Following a URL here would be a server-side request forgery primitive
//!   sitting inside the machine's AI service.
//!
//! It runs as its own unprivileged unit, not inside the daemon, so a bug in
//! this HTTP parser is a bug in an unprivileged process that holds no grants.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ai_daemon_proto::frame::{self, AttachKind, AttachMeta, Event, Frame, Message, Params, Request};
use ai_daemon_proto::DATA_PROTO;
use zbus::blocking::Connection;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

const BUS_NAME: &str = "io.github.agraves.AIDaemon1";
const MANAGER_PATH: &str = "/io/github/agraves/AIDaemon1/Manager";
const MANAGER_IFACE: &str = "io.github.agraves.AIDaemon1.Manager";
const SESSION_IFACE: &str = "io.github.agraves.AIDaemon1.Session";

/// Ollama's port, because that is what the software this exists for is
/// already configured to talk to.
const DEFAULT_PORT: u16 = 11_434;
const DEFAULT_CONFIG: &str = "/etc/ai-daemon/shim.toml";
const MAX_BODY: usize = 32 * 1024 * 1024;

fn main() {
    let mut port = DEFAULT_PORT;
    let mut config_path = std::path::PathBuf::from(DEFAULT_CONFIG);
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => port = args.next().and_then(|v| v.parse().ok()).unwrap_or(port),
            "--config" => {
                config_path = args.next().map(std::path::PathBuf::from).unwrap_or(config_path)
            }
            "--version" | "-V" => {
                println!("ai-daemon-shim {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--help" | "-h" => {
                println!(
                    "ai-daemon-shim {} — OpenAI-compatible endpoint for ai-daemon

usage: ai-daemon-shim [--port N]   (default {DEFAULT_PORT}, always on 127.0.0.1)

usage: ai-daemon-shim [--port N] [--config {DEFAULT_CONFIG}]

OpenAI:    GET /v1/models, POST /v1/chat/completions, POST /v1/responses,
           POST /v1/embeddings
Anthropic: POST /v1/messages, POST /v1/messages/count_tokens

Every request becomes an ai-daemon session at the lowest trust class. A
caller presenting a token named in the config is identified as that client
(shim:<name>) so policy, rate limits and revocation are per agent; one
without a token is anonymous, because loopback TCP carries no peer
credentials. Off by default; enable with
`systemctl enable --now ai-daemon-shim.service`.",
                    env!("CARGO_PKG_VERSION")
                );
                return;
            }
            other => {
                eprintln!("ai-daemon-shim: unknown argument {other:?}");
                std::process::exit(1);
            }
        }
    }

    let config = Arc::new(ShimConfig::load(&config_path));

    // Not configurable, and that is the feature.
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let listener = match TcpListener::bind(address) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("<3>ai-daemon-shim: cannot bind {address}: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("<6>ai-daemon-shim {} listening on {address}", env!("CARGO_PKG_VERSION"));

    let served = Arc::new(AtomicU64::new(0));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let served = served.clone();
        let config = config.clone();
        std::thread::spawn(move || {
            let n = served.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = serve(stream, &config) {
                eprintln!("<4>ai-daemon-shim: request {n} failed: {e}");
            }
        });
    }
}

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
    /// The bearer token or `x-api-key` the caller presented, if any.
    token: Option<String>,
}

/// Who may call, and what to call them.
///
/// A loopback TCP socket has no `SO_PEERCRED`: the kernel will not say which
/// process is on the other end, so before this every HTTP client on the
/// machine reached the daemon as one identity — one grant, one rate limit, one
/// revocation, shared by all of them. On a box running six agents that is the
/// difference between per-agent policy and none.
///
/// A token is a weaker instrument than peer credentials and this does not
/// pretend otherwise: any local process that can read the token file can
/// present the token. What it buys is that *cooperating* clients are told
/// apart, which is what the machine's owner needs to say "the CI runner gets
/// this much and the editor gets that much". The file should be 0640 and owned
/// by the shim's user; the package ships an example and no tokens.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ShimConfig {
    /// Refuse callers with no recognised token.
    ///
    /// Off by default, because the entire purpose of this bridge is that
    /// existing software works unchanged, and existing software does not know
    /// to send a token. On means "this machine has named its agents and does
    /// not want anonymous ones", which is the right setting once it has.
    require_token: bool,
    #[serde(rename = "client")]
    clients: Vec<ShimClient>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ShimClient {
    /// What the daemon will know this caller as: `shim:<name>`.
    name: String,
    token: String,
}

impl ShimConfig {
    fn load(path: &std::path::Path) -> ShimConfig {
        let Ok(text) = std::fs::read_to_string(path) else {
            return ShimConfig::default();
        };
        match toml::from_str::<ShimConfig>(&text) {
            Ok(config) => {
                let named: Vec<&str> = config.clients.iter().map(|c| c.name.as_str()).collect();
                eprintln!(
                    "<6>ai-daemon-shim: {} named client(s){}: {}",
                    named.len(),
                    if config.require_token { ", anonymous callers refused" } else { "" },
                    named.join(", ")
                );
                config
            }
            Err(e) => {
                // Failing closed on an unreadable client table: the file
                // exists, so somebody meant to name their agents, and running
                // as if they had not would silently merge them all again.
                eprintln!("<3>ai-daemon-shim: {} is unreadable ({e}); refusing all callers", path.display());
                ShimConfig { require_token: true, clients: Vec::new() }
            }
        }
    }

    /// The name for a presented token, if it is one we know.
    ///
    /// Compared in constant time over the whole table, so the time taken does
    /// not narrow down which token was close.
    fn name_for(&self, token: Option<&str>) -> Option<String> {
        let token = token?;
        let mut found = None;
        for client in &self.clients {
            if constant_time_eq(client.token.as_bytes(), token.as_bytes()) {
                found = Some(client.name.clone());
            }
        }
        found
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn serve(mut stream: TcpStream, config: &ShimConfig) -> Result<(), String> {
    let mut peer = peer_cred(stream.as_raw_fd())?;
    let request = read_request(&mut stream)?;
    peer.client = config.name_for(request.token.as_deref());

    // Anthropic's shape for its own routes, OpenAI's for the rest: a client
    // that cannot parse the other API's error body is a client that gets a
    // wall of nothing when it is refused.
    let anthropic = request.path.starts_with("/v1/messages");
    if config.require_token && peer.client.is_none() {
        let body = if anthropic {
            anthropic_error("authentication_error", "no recognised token; this machine names its clients")
        } else {
            error_body("authentication_error", "no recognised token; this machine names its clients")
        };
        respond(&mut stream, 401, &body)?;
        return Ok(());
    }

    let result = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/v1/models") | ("GET", "/api/tags") => list_models(),
        ("POST", "/v1/chat/completions") => {
            return chat(&mut stream, &request, &peer);
        }
        ("POST", "/v1/responses") => {
            return responses(&mut stream, &request, &peer);
        }
        ("POST", "/v1/embeddings") => embeddings(&request, &peer),
        ("POST", "/v1/messages") => {
            return messages(&mut stream, &request, &peer);
        }
        ("POST", "/v1/messages/count_tokens") => count_tokens(&request, &peer),
        ("GET", "/health") => Ok(serde_json::json!({"status": "ok"})),
        _ => {
            respond(&mut stream, 404, &error_body("not_found", "no such route"))?;
            return Ok(());
        }
    };

    match result {
        Ok(json) => respond(&mut stream, 200, &json),
        Err(e) if anthropic => {
            respond(&mut stream, 400, &anthropic_error("invalid_request_error", &e))
        }
        Err(e) => respond(&mut stream, 400, &error_body("invalid_request_error", &e)),
    }
}

/// Anthropic's error envelope, which is not OpenAI's.
fn anthropic_error(kind: &str, message: &str) -> serde_json::Value {
    serde_json::json!({"type": "error", "error": {"type": kind, "message": message}})
}

/// The path a request routes on: the target with any query string removed.
fn route_path(target: &str) -> &str {
    target.split('?').next().unwrap_or(target)
}

fn read_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    // The request target, minus any query string. Routing matches the path
    // exactly, so a query has to come off first or it changes the route.
    //
    // Not hypothetical, and not an edge case: Claude Code sends every turn to
    // `POST /v1/messages?beta=true`. Matching the raw target sent that to the
    // 404 arm, and a 404 from /v1/messages is what an Anthropic client reads
    // as "that model does not exist" — so the failure surfaced to the user as
    // `There's an issue with the selected model`, naming a model that was
    // installed and working. The session-title call, which carries no query,
    // went through on the same connection, which made it look like auth and
    // the model were fine and only one request was refused.
    //
    // Nothing here reads a query parameter and nothing should: these are
    // hints about the body's dialect, and the body is what this parses.
    let path = route_path(parts.next().unwrap_or_default()).to_string();

    let mut content_length = 0usize;
    let mut token: Option<String> = None;
    loop {
        line.clear();
        if reader.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            break;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
            // Both spellings, because the two APIs this speaks disagree:
            // OpenAI clients send Authorization, Anthropic clients send
            // x-api-key, and Claude Code sends the latter.
            if name.eq_ignore_ascii_case("authorization") {
                token = value
                    .trim()
                    .strip_prefix("Bearer ")
                    .or_else(|| value.trim().strip_prefix("bearer "))
                    .map(|t| t.trim().to_string());
            } else if name.eq_ignore_ascii_case("x-api-key") {
                token = Some(value.trim().to_string());
            }
        }
    }
    if content_length > MAX_BODY {
        return Err(format!("body of {content_length} bytes is over the limit"));
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).map_err(|e| e.to_string())?;
    }
    Ok(HttpRequest { method, path, body, token })
}

fn respond(stream: &mut TcpStream, status: u16, body: &serde_json::Value) -> Result<(), String> {
    let text = body.to_string();
    write!(
        stream,
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        reason(status),
        text.len()
    )
    .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        _ => "Error",
    }
}

fn error_body(kind: &str, message: &str) -> serde_json::Value {
    serde_json::json!({"error": {"type": kind, "message": message}})
}

// ---------------------------------------------------------------------------
// Peer identity
// ---------------------------------------------------------------------------

struct Peer {
    pid: u32,
    uid: u32,
    /// The configured name for the token this caller presented, if any.
    client: Option<String>,
}

fn peer_cred(fd: RawFd) -> Result<Peer, String> {
    // A loopback TCP socket has no SO_PEERCRED, so on the listener this shim
    // actually has, this *always* falls through to naming ourselves — every
    // caller arrived as the same identity and shared one grant, one rate
    // limit and one revocation. That is what the token table above is for.
    // The call is kept because it costs nothing and is correct the day this
    // learns to listen on a Unix socket, where the kernel does answer.
    let mut ucred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: correctly sized output for SO_PEERCRED on a socket we own.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut ucred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 || ucred.pid == 0 {
        // Fall back to naming ourselves. The daemon then sees "the shim" as
        // the identity, which is honest: we could not tell it anything better.
        return Ok(Peer {
            pid: std::process::id(),
            uid: unsafe { libc::getuid() },
            client: None,
        });
    }
    Ok(Peer { pid: ucred.pid as u32, uid: ucred.uid, client: None })
}

// ---------------------------------------------------------------------------
// Talking to the daemon
// ---------------------------------------------------------------------------

struct Session {
    path: OwnedObjectPath,
    socket: UnixStream,
    connection: Connection,
}

impl Session {
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

fn open_session(model: &str, peer: &Peer, background: bool) -> Result<Session, String> {
    let connection = Connection::system().map_err(|e| format!("system bus: {e}"))?;
    let mut options: HashMap<String, OwnedValue> = HashMap::new();
    options.insert(
        "shim_peer_pid".into(),
        Value::U32(peer.pid).try_into().map_err(|_| "peer pid")?,
    );
    options.insert(
        "shim_peer_uid".into(),
        Value::U32(peer.uid).try_into().map_err(|_| "peer uid")?,
    );
    if let Some(name) = &peer.client {
        options.insert(
            "shim_client".into(),
            Value::Str(name.as_str().into()).try_into().map_err(|_| "client name")?,
        );
    }
    // Ask for as much context as the machine will give, and let it say no.
    //
    // Neither wire format this bridge speaks has a field for context length —
    // an OpenAI or Anthropic client states `max_tokens` for its *output* and
    // assumes the window is a property of the model it named. So the shim is
    // the only thing in the path that can ask, and when it did not ask, every
    // HTTP session took the backend's fallback of 4096.
    //
    // That is below the floor for the callers this bridge exists to serve.
    // Claude Code's system prompt alone measures ~8.8k tokens, so it was
    // refused before its first turn — with an accurate message about a 4096
    // window that no configuration appeared to control, because raising
    // `max_context` in policy correctly changed a ceiling that nothing was
    // reaching up to.
    //
    // `max_context` is documented as clamped by policy and by the model, so
    // asking for everything is a request for "whatever I am allowed", not a
    // way around either limit.
    options.insert(
        "max_context".into(),
        Value::U32(u32::MAX).try_into().map_err(|_| "max context")?,
    );
    options.insert(
        "priority".into(),
        Value::Str(if background { "background" } else { "interactive" }.into())
            .try_into()
            .map_err(|_| "priority")?,
    );
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
    // SAFETY: an owned descriptor handed over the bus; nothing else holds it.
    let socket = unsafe { UnixStream::from_raw_fd(raw.into_raw_fd()) };
    Ok(Session { path, socket, connection })
}

fn list_models() -> Result<serde_json::Value, String> {
    let connection = Connection::system().map_err(|e| format!("system bus: {e}"))?;
    let reply = connection
        .call_method(Some(BUS_NAME), MANAGER_PATH, Some(MANAGER_IFACE), "ListModels", &())
        .map_err(|e| format!("ListModels: {e}"))?;
    let models: Vec<HashMap<String, OwnedValue>> =
        reply.body().deserialize().map_err(|e| e.to_string())?;
    let data: Vec<serde_json::Value> = models
        .iter()
        .filter_map(|m| m.get("name"))
        .filter_map(|v| String::try_from(v.clone()).ok())
        .map(|name| {
            serde_json::json!({
                "id": name,
                "object": "model",
                "owned_by": "ai-daemon",
            })
        })
        .collect();
    Ok(serde_json::json!({"object": "list", "data": data}))
}

// ---------------------------------------------------------------------------
// /v1/chat/completions
// ---------------------------------------------------------------------------

fn chat(stream: &mut TcpStream, request: &HttpRequest, peer: &Peer) -> Result<(), String> {
    let body: serde_json::Value = match serde_json::from_slice(&request.body) {
        Ok(body) => body,
        Err(e) => {
            return respond(stream, 400, &error_body("invalid_request_error", &e.to_string()));
        }
    };
    let model = body.get("model").and_then(|m| m.as_str()).unwrap_or("default").to_string();
    let streaming = body.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);

    let session = match open_session(&model, peer, false) {
        Ok(session) => session,
        Err(e) => {
            let status = if e.contains("AccessDenied") { 403 } else { 400 };
            return respond(stream, status, &error_body("permission_error", &e));
        }
    };
    let mut socket = session.socket.try_clone().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(session.socket.try_clone().map_err(|e| e.to_string())?);
    frame::write_cbor(&mut socket, &Request::Hello { proto: DATA_PROTO }).map_err(|e| e.to_string())?;
    let _ = read_event(&mut reader);

    // Attachments first, so the ids exist before the message that names them.
    let mut messages: Vec<Message> = Vec::new();
    let mut attachment_index = 0usize;
    for entry in body.get("messages").and_then(|m| m.as_array()).cloned().unwrap_or_default() {
        let role = entry.get("role").and_then(|r| r.as_str()).unwrap_or("user").to_string();
        let mut text = String::new();
        let mut attachments: Vec<String> = Vec::new();

        match entry.get("content") {
            Some(serde_json::Value::String(s)) => text = s.clone(),
            Some(serde_json::Value::Array(parts)) => {
                for part in parts {
                    match part.get("type").and_then(|t| t.as_str()) {
                        Some("text") => {
                            if let Some(s) = part.get("text").and_then(|t| t.as_str()) {
                                text.push_str(s);
                            }
                        }
                        Some("image_url") => {
                            let url = part
                                .get("image_url")
                                .and_then(|u| u.get("url"))
                                .and_then(|u| u.as_str())
                                .unwrap_or_default();
                            let bytes = match decode_data_url(url) {
                                Ok(bytes) => bytes,
                                Err(e) => {
                                    session.close();
                                    return respond(
                                        stream,
                                        400,
                                        &error_body("invalid_request_error", &e),
                                    );
                                }
                            };
                            attachment_index += 1;
                            let id = format!("img{attachment_index}");
                            frame::write_cbor(
                                &mut socket,
                                &Request::Attach {
                                    id: id.clone(),
                                    kind: AttachKind::Image,
                                    meta: AttachMeta {
                                        encoded: Some("image/png".into()),
                                        ..Default::default()
                                    },
                                    len: bytes.len() as u64,
                                },
                            )
                            .map_err(|e| e.to_string())?;
                            frame::write_blob(&mut socket, &bytes).map_err(|e| e.to_string())?;
                            attachments.push(id);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        messages.push(Message {
            role,
            content: text,
            attachments,
            tool_call_id: entry
                .get("tool_call_id")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        });
    }

    let tools = body.get("tools").and_then(|t| t.as_array()).map(|list| {
        list.iter()
            .filter_map(|entry| {
                let function = entry.get("function")?;
                Some(ai_daemon_proto::frame::ToolSchema {
                    name: function.get("name")?.as_str()?.to_string(),
                    description: function
                        .get("description")
                        .and_then(|d| d.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    json_schema: function
                        .get("parameters")
                        .cloned()
                        .unwrap_or(serde_json::json!({"type": "object"})),
                })
            })
            .collect::<Vec<_>>()
    });

    let params = Params {
        temperature: body.get("temperature").and_then(|v| v.as_f64()).map(|v| v as f32),
        top_p: body.get("top_p").and_then(|v| v.as_f64()).map(|v| v as f32),
        seed: body.get("seed").and_then(|v| v.as_u64()),
        max_tokens: body
            .get("max_tokens")
            .or_else(|| body.get("max_completion_tokens"))
            .and_then(|v| v.as_u64())
            .map(|v| v as u32),
        stop: body.get("stop").and_then(|s| s.as_array()).map(|items| {
            items.iter().filter_map(|i| i.as_str().map(str::to_string)).collect()
        }),
        // Of the v2 sampling controls, only the two OpenAI itself defines are
        // mapped. top_k, min_p and repeat_penalty have no field in that API,
        // and inventing one here would mean a client's request meaning
        // something different through the shim than through the native
        // protocol — which is the one thing a compatibility bridge must not do.
        logit_bias: body
            .get("logit_bias")
            .and_then(|v| v.as_object())
            .map(|map| {
                map.iter()
                    .filter_map(|(token, bias)| {
                        Some((token.parse().ok()?, bias.as_f64()? as f32))
                    })
                    .collect()
            })
            .unwrap_or_default(),
        logprobs: body
            .get("top_logprobs")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .or_else(|| {
                // Bare `logprobs: true` means the chosen token's own figure.
                body.get("logprobs").and_then(|v| v.as_bool()).and_then(|on| on.then_some(1))
            }),
        ..Default::default()
    };

    frame::write_cbor(
        &mut socket,
        &Request::Generate { messages, stream: true, params: Some(params), grammar: None, tools },
    )
    .map_err(|e| e.to_string())?;

    let mut cancel_channel = session.socket.try_clone().map_err(|e| e.to_string())?;
    let outcome = if streaming {
        relay_sse(stream, &mut reader, &model)
    } else {
        relay_json(stream, &mut reader, &mut cancel_channel, &model)
    };
    session.close();
    outcome
}

fn relay_sse(
    stream: &mut TcpStream,
    reader: &mut impl Read,
    model: &str,
) -> Result<(), String> {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n"
    )
    .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    let id = format!("chatcmpl-{}", std::process::id());
    loop {
        match read_event(reader)? {
            None => break,
            Some(Event::Token { tok, .. }) => {
                let chunk = serde_json::json!({
                    "id": id,
                    "object": "chat.completion.chunk",
                    "model": model,
                    "choices": [{"index": 0, "delta": {"content": tok}, "finish_reason": null}],
                });
                write!(stream, "data: {chunk}\n\n").map_err(|e| e.to_string())?;
                stream.flush().map_err(|e| e.to_string())?;
            }
            Some(Event::ToolCall { tool_call }) => {
                let chunk = serde_json::json!({
                    "id": id,
                    "object": "chat.completion.chunk",
                    "model": model,
                    "choices": [{
                        "index": 0,
                        "delta": {"tool_calls": [{
                            "index": 0,
                            "id": tool_call.id,
                            "type": "function",
                            "function": {"name": tool_call.name, "arguments": tool_call.arguments},
                        }]},
                        "finish_reason": null,
                    }],
                });
                write!(stream, "data: {chunk}\n\n").map_err(|e| e.to_string())?;
                stream.flush().map_err(|e| e.to_string())?;
            }
            Some(Event::Notice { event, detail }) => {
                // Not an OpenAI concept, so it goes out as a comment: an SSE
                // client ignores it, and a human reading the stream sees why
                // their context went away.
                write!(stream, ": {event} {detail}\n\n").map_err(|e| e.to_string())?;
            }
            Some(Event::Done { usage, finish_reason, .. }) => {
                let chunk = serde_json::json!({
                    "id": id,
                    "object": "chat.completion.chunk",
                    "model": model,
                    "choices": [{
                        "index": 0,
                        "delta": {},
                        "finish_reason": finish_reason.unwrap_or_else(|| "stop".into()),
                    }],
                    "usage": {
                        "prompt_tokens": usage.prompt_tokens,
                        "completion_tokens": usage.completion_tokens,
                        "total_tokens": usage.prompt_tokens + usage.completion_tokens,
                    },
                });
                write!(stream, "data: {chunk}\n\ndata: [DONE]\n\n").map_err(|e| e.to_string())?;
                stream.flush().map_err(|e| e.to_string())?;
                break;
            }
            Some(Event::Error { error }) => {
                let chunk = error_body(&error.code, &error.message);
                write!(stream, "data: {chunk}\n\ndata: [DONE]\n\n").map_err(|e| e.to_string())?;
                stream.flush().map_err(|e| e.to_string())?;
                break;
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Has the HTTP client gone away?
///
/// Asked between events rather than discovered on the next write, because a
/// non-streaming completion does not write anything until it is finished: the
/// first attempt to notice a vanished client would otherwise be the response
/// nobody is there to read, by which point the daemon has generated the whole
/// thing and held a decode slot to do it.
fn peer_hung_up(stream: &TcpStream) -> bool {
    let mut pollfd = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLRDHUP,
        revents: 0,
    };
    // SAFETY: one initialised pollfd, a matching count, and no blocking.
    let ready = unsafe { libc::poll(&mut pollfd, 1, 0) };
    ready > 0 && pollfd.revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR) != 0
}

fn relay_json(
    stream: &mut TcpStream,
    reader: &mut impl Read,
    daemon: &mut UnixStream,
    model: &str,
) -> Result<(), String> {
    let mut content = String::new();
    let mut tool_calls: Vec<serde_json::Value> = Vec::new();
    let mut abandoned = false;
    loop {
        if !abandoned && peer_hung_up(stream) {
            // Tell the daemon to stop. Then keep draining until it says done,
            // so the session ends the way every other session ends rather than
            // by having its socket yanked.
            abandoned = true;
            eprintln!("<6>ai-daemon-shim: client went away; cancelling the generation");
            let _ = frame::write_cbor(daemon, &Request::Cancel);
        }
        match read_event(reader)? {
            None => break,
            Some(Event::Token { tok, .. }) => content.push_str(&tok),
            Some(Event::ToolCall { tool_call }) => tool_calls.push(serde_json::json!({
                "id": tool_call.id,
                "type": "function",
                "function": {"name": tool_call.name, "arguments": tool_call.arguments},
            })),
            Some(Event::Done { usage, finish_reason, .. }) => {
                if abandoned {
                    // Nobody to answer. The session is closed by the caller.
                    return Ok(());
                }
                let mut message = serde_json::json!({"role": "assistant", "content": content});
                if !tool_calls.is_empty() {
                    message["tool_calls"] = serde_json::Value::Array(tool_calls);
                    message["content"] = serde_json::Value::Null;
                }
                let body = serde_json::json!({
                    "id": format!("chatcmpl-{}", std::process::id()),
                    "object": "chat.completion",
                    "model": model,
                    "choices": [{
                        "index": 0,
                        "message": message,
                        "finish_reason": finish_reason.unwrap_or_else(|| "stop".into()),
                    }],
                    "usage": {
                        "prompt_tokens": usage.prompt_tokens,
                        "completion_tokens": usage.completion_tokens,
                        "total_tokens": usage.prompt_tokens + usage.completion_tokens,
                    },
                });
                return respond(stream, 200, &body);
            }
            Some(Event::Error { error }) => {
                let status = match error.code.as_str() {
                    "policy-denied" => 403,
                    "rate-limited" => 429,
                    _ => 400,
                };
                return respond(stream, status, &error_body(&error.code, &error.message));
            }
            Some(_) => {}
        }
    }
    respond(stream, 400, &error_body("api_error", "the session ended without a reply"))
}

fn embeddings(request: &HttpRequest, peer: &Peer) -> Result<serde_json::Value, String> {
    let body: serde_json::Value =
        serde_json::from_slice(&request.body).map_err(|e| e.to_string())?;
    let model = body.get("model").and_then(|m| m.as_str()).unwrap_or("embed").to_string();
    let inputs: Vec<String> = match body.get("input") {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(items)) => {
            items.iter().filter_map(|i| i.as_str().map(str::to_string)).collect()
        }
        _ => return Err("input must be a string or an array of strings".into()),
    };

    // Embedding is the batch case the priority classes exist for (§8): nobody
    // is watching a cursor, so it yields to interactive work.
    let session = open_session(&model, peer, true)?;
    let mut socket = session.socket.try_clone().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(session.socket.try_clone().map_err(|e| e.to_string())?);
    frame::write_cbor(&mut socket, &Request::Embed { inputs }).map_err(|e| e.to_string())?;

    let mut data = Vec::new();
    let mut prompt_tokens = 0u64;
    loop {
        match read_event(&mut reader)? {
            None => break,
            Some(Event::Vectors { vectors }) => {
                for (index, vector) in vectors.into_iter().enumerate() {
                    data.push(serde_json::json!({
                        "object": "embedding",
                        "index": index,
                        "embedding": vector,
                    }));
                }
            }
            Some(Event::Done { usage, .. }) => {
                prompt_tokens = usage.prompt_tokens;
                break;
            }
            Some(Event::Error { error }) => {
                session.close();
                return Err(format!("{}: {}", error.code, error.message));
            }
            Some(_) => {}
        }
    }
    session.close();
    Ok(serde_json::json!({
        "object": "list",
        "model": model,
        "data": data,
        "usage": {"prompt_tokens": prompt_tokens, "total_tokens": prompt_tokens},
    }))
}

/// `data:` URLs and nothing else.
///
/// OpenAI's `image_url` permits an `https://` URL, and honouring that would
/// make this process fetch attacker-chosen URLs on behalf of a local caller —
/// a server-side request forgery primitive inside the machine's AI service.
/// §11 rules it out and so does this function.
fn decode_data_url(url: &str) -> Result<Vec<u8>, String> {
    let rest = url
        .strip_prefix("data:")
        .ok_or("only data: URLs are accepted; this shim never fetches a remote URL")?;
    let (_meta, payload) = rest
        .split_once(',')
        .ok_or("malformed data: URL")?;
    if !rest.split(',').next().unwrap_or_default().contains(";base64") {
        return Err("only base64 data: URLs are accepted".into());
    }
    base64_decode(payload)
}

fn base64_decode(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut accumulator: u32 = 0;
    let mut bits = 0u32;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            b'\n' | b'\r' | b' ' | b'\t' => continue,
            other => return Err(format!("invalid base64 byte {other:#04x}")),
        } as u32;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }
    Ok(out)
}

fn read_event(reader: &mut impl Read) -> Result<Option<Event>, String> {
    match frame::read_frame(reader) {
        Ok(None) => Ok(None),
        Ok(Some(Frame::Blob(_))) => Err("the daemon sent a BLOB where an event was expected".into()),
        Ok(Some(Frame::Cbor(value))) => value
            .deserialized()
            .map(Some)
            .map_err(|e| format!("unrecognised event: {e}")),
        Err(e) => Err(format!("session socket: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Anthropic Messages API — POST /v1/messages
//
// The other half of §15's "OpenAI/Anthropic-compatible shim", and on a machine
// running Claude Code it is the half that matters: that client speaks the
// Messages API and nothing else, so without this route the most-used agent on
// the box cannot be pointed at the daemon at all.
//
// Everything below the wire format is shared with the OpenAI route — same
// session, same policy engine, same audit record, same rate limit. Only the
// shapes differ, and they differ in ways worth naming rather than papering
// over: `system` is a top-level field rather than a message, `max_tokens` is
// required, tool results come back inside a *user* turn, and the streaming
// protocol is a state machine of named events rather than one chunk shape.
// ---------------------------------------------------------------------------

/// What a turn of Anthropic content parsed down to.
struct AnthropicTurn {
    messages: Vec<Message>,
    tools: Option<Vec<ai_daemon_proto::frame::ToolSchema>>,
    params: Params,
    stream: bool,
    model: String,
}

fn parse_messages_body(
    body: &serde_json::Value,
    socket: &mut UnixStream,
) -> Result<AnthropicTurn, String> {
    let model = body.get("model").and_then(|m| m.as_str()).unwrap_or("default").to_string();
    // Required by the API, and not defaulted here: a client that omits it is
    // a client whose author expects a hard error, and inventing a ceiling
    // would produce a truncation they cannot explain.
    let max_tokens = body
        .get("max_tokens")
        .and_then(|v| v.as_u64())
        .ok_or("max_tokens is required")? as u32;

    let mut messages: Vec<Message> = Vec::new();

    // `system` is a field, not a message. It may be a bare string or the
    // content-block array the caching API uses; both mean the same prompt.
    match body.get("system") {
        Some(serde_json::Value::String(s)) if !s.is_empty() => messages.push(Message {
            role: "system".into(),
            content: s.clone(),
            attachments: Vec::new(),
            tool_call_id: None,
        }),
        Some(serde_json::Value::Array(blocks)) => {
            let joined: String = blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("\n");
            if !joined.is_empty() {
                messages.push(Message {
                    role: "system".into(),
                    content: joined,
                    attachments: Vec::new(),
                    tool_call_id: None,
                });
            }
        }
        _ => {}
    }

    let mut attachment_index = 0usize;
    for entry in body.get("messages").and_then(|m| m.as_array()).cloned().unwrap_or_default() {
        let role = entry.get("role").and_then(|r| r.as_str()).unwrap_or("user").to_string();
        let mut text = String::new();
        let mut attachments: Vec<String> = Vec::new();
        // A single Anthropic turn can carry several tool results. The daemon's
        // history is one message per result, so the turn fans out.
        let mut tool_results: Vec<Message> = Vec::new();

        match entry.get("content") {
            Some(serde_json::Value::String(s)) => text = s.clone(),
            Some(serde_json::Value::Array(parts)) => {
                for part in parts {
                    match part.get("type").and_then(|t| t.as_str()) {
                        Some("text") => {
                            if let Some(s) = part.get("text").and_then(|t| t.as_str()) {
                                text.push_str(s);
                            }
                        }
                        Some("image") => {
                            // base64 only. `url` sources are refused for the
                            // same reason image_url is on the OpenAI side:
                            // following one would put a server-side request
                            // forgery primitive inside the machine's AI
                            // service, and this process is the one place that
                            // must not fetch on a prompt's say-so.
                            let source = part.get("source").ok_or("image block has no source")?;
                            match source.get("type").and_then(|t| t.as_str()) {
                                Some("base64") => {}
                                Some(other) => {
                                    return Err(format!(
                                        "image source {other:?} is not accepted; send base64. \
                                         This shim never fetches a URL a prompt named."
                                    ))
                                }
                                None => return Err("image source has no type".into()),
                            }
                            let media = source
                                .get("media_type")
                                .and_then(|m| m.as_str())
                                .unwrap_or("image/png")
                                .to_string();
                            let data = source
                                .get("data")
                                .and_then(|d| d.as_str())
                                .ok_or("image source has no data")?;
                            let bytes = base64_decode(data)?;
                            attachment_index += 1;
                            let id = format!("img{attachment_index}");
                            frame::write_cbor(
                                socket,
                                &Request::Attach {
                                    id: id.clone(),
                                    kind: AttachKind::Image,
                                    meta: AttachMeta { encoded: Some(media), ..Default::default() },
                                    len: bytes.len() as u64,
                                },
                            )
                            .map_err(|e| e.to_string())?;
                            frame::write_blob(socket, &bytes).map_err(|e| e.to_string())?;
                            attachments.push(id);
                        }
                        Some("tool_result") => {
                            let id = part
                                .get("tool_use_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default()
                                .to_string();
                            // The content of a result is itself either a
                            // string or blocks.
                            let content = match part.get("content") {
                                Some(serde_json::Value::String(s)) => s.clone(),
                                Some(serde_json::Value::Array(blocks)) => blocks
                                    .iter()
                                    .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                                    .collect::<Vec<_>>()
                                    .join("\n"),
                                other => other.map(|o| o.to_string()).unwrap_or_default(),
                            };
                            tool_results.push(Message {
                                role: "tool".into(),
                                content,
                                attachments: Vec::new(),
                                tool_call_id: Some(id),
                            });
                        }
                        Some("tool_use") => {
                            // The assistant's own earlier call, replayed. Kept
                            // in the same shape the daemon writes for one, so
                            // a conversation that came back through this route
                            // looks the same going out as it did coming in.
                            let id = part.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                            let name =
                                part.get("name").and_then(|v| v.as_str()).unwrap_or_default();
                            let input = part
                                .get("input")
                                .cloned()
                                .unwrap_or(serde_json::json!({}))
                                .to_string();
                            if !text.is_empty() {
                                text.push('\n');
                            }
                            text.push_str(&format!(
                                "{{\"tool_call\":{{\"id\":\"{id}\",\"name\":\"{name}\",\"arguments\":{input}}}}}"
                            ));
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }

        if !text.is_empty() || !attachments.is_empty() {
            messages.push(Message { role, content: text, attachments, tool_call_id: None });
        }
        messages.extend(tool_results);
    }

    let tools = body.get("tools").and_then(|t| t.as_array()).map(|list| {
        list.iter()
            .filter_map(|entry| {
                Some(ai_daemon_proto::frame::ToolSchema {
                    // Anthropic puts these at the top level of the tool, where
                    // OpenAI nests them under `function`.
                    name: entry.get("name")?.as_str()?.to_string(),
                    description: entry
                        .get("description")
                        .and_then(|d| d.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    json_schema: entry
                        .get("input_schema")
                        .cloned()
                        .unwrap_or(serde_json::json!({"type": "object"})),
                })
            })
            .collect::<Vec<_>>()
    });

    let params = Params {
        temperature: body.get("temperature").and_then(|v| v.as_f64()).map(|v| v as f32),
        top_p: body.get("top_p").and_then(|v| v.as_f64()).map(|v| v as f32),
        // Unlike OpenAI, Anthropic defines top_k — so mapping it is carrying
        // the caller's request, not inventing a meaning for it.
        top_k: body.get("top_k").and_then(|v| v.as_u64()).map(|v| v as u32),
        max_tokens: Some(max_tokens),
        stop: body.get("stop_sequences").and_then(|s| s.as_array()).map(|items| {
            items.iter().filter_map(|i| i.as_str().map(str::to_string)).collect()
        }),
        ..Default::default()
    };

    Ok(AnthropicTurn {
        messages,
        tools,
        params,
        stream: body.get("stream").and_then(|s| s.as_bool()).unwrap_or(false),
        model,
    })
}

fn messages(stream: &mut TcpStream, request: &HttpRequest, peer: &Peer) -> Result<(), String> {
    let body: serde_json::Value = match serde_json::from_slice(&request.body) {
        Ok(body) => body,
        Err(e) => {
            return respond(
                stream,
                400,
                &anthropic_error("invalid_request_error", &e.to_string()),
            )
        }
    };
    let model = body.get("model").and_then(|m| m.as_str()).unwrap_or("default").to_string();

    let session = match open_session(&model, peer, false) {
        Ok(session) => session,
        Err(e) => {
            let status = if e.contains("AccessDenied") { 403 } else { 400 };
            return respond(stream, status, &anthropic_error("permission_error", &e));
        }
    };
    let mut socket = session.socket.try_clone().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(session.socket.try_clone().map_err(|e| e.to_string())?);
    frame::write_cbor(&mut socket, &Request::Hello { proto: DATA_PROTO })
        .map_err(|e| e.to_string())?;
    let _ = read_event(&mut reader);

    let turn = match parse_messages_body(&body, &mut socket) {
        Ok(turn) => turn,
        Err(e) => {
            session.close();
            return respond(stream, 400, &anthropic_error("invalid_request_error", &e));
        }
    };

    frame::write_cbor(
        &mut socket,
        &Request::Generate {
            messages: turn.messages,
            stream: true,
            params: Some(turn.params),
            grammar: None,
            tools: turn.tools,
        },
    )
    .map_err(|e| e.to_string())?;

    let mut cancel_channel = session.socket.try_clone().map_err(|e| e.to_string())?;
    let outcome = if turn.stream {
        relay_anthropic_sse(stream, &mut reader, &turn.model)
    } else {
        relay_anthropic_json(stream, &mut reader, &mut cancel_channel, &turn.model)
    };
    session.close();
    outcome
}

/// Anthropic's stop reasons, which are not OpenAI's.
fn anthropic_stop_reason(finish: Option<&str>, tool_used: bool) -> &'static str {
    if tool_used {
        return "tool_use";
    }
    match finish {
        Some("length") => "max_tokens",
        Some("stop_sequence") => "stop_sequence",
        // `cancelled` has no Anthropic spelling. end_turn is the honest
        // approximation: the turn ended and no more tokens are coming.
        _ => "end_turn",
    }
}

fn relay_anthropic_json(
    stream: &mut TcpStream,
    reader: &mut impl Read,
    daemon: &mut UnixStream,
    model: &str,
) -> Result<(), String> {
    let mut text = String::new();
    let mut blocks: Vec<serde_json::Value> = Vec::new();
    let mut usage = ai_daemon_proto::frame::Usage::default();
    let mut finish: Option<String> = None;
    let mut tool_used = false;
    let mut abandoned = false;

    loop {
        if !abandoned && peer_hung_up(stream) {
            abandoned = true;
            eprintln!("<6>ai-daemon-shim: client went away; cancelling the generation");
            let _ = frame::write_cbor(daemon, &Request::Cancel);
        }
        match read_event(reader)? {
            None => break,
            Some(Event::Token { tok, .. }) => text.push_str(&tok),
            Some(Event::ToolCall { tool_call }) => {
                tool_used = true;
                blocks.push(tool_use_block(&tool_call));
            }
            Some(Event::ToolCalls { tool_calls }) => {
                tool_used = true;
                blocks.extend(tool_calls.iter().map(tool_use_block));
            }
            Some(Event::Done { usage: u, finish_reason, .. }) => {
                usage = u;
                finish = finish_reason;
                break;
            }
            Some(Event::Error { error }) => {
                if abandoned {
                    return Ok(());
                }
                let status = match error.code.as_str() {
                    "policy-denied" => 403,
                    "rate-limited" => 429,
                    _ => 400,
                };
                let kind = match error.code.as_str() {
                    "policy-denied" => "permission_error",
                    "rate-limited" => "rate_limit_error",
                    _ => "invalid_request_error",
                };
                return respond(stream, status, &anthropic_error(kind, &error.message));
            }
            Some(_) => {}
        }
    }
    if abandoned {
        return Ok(());
    }

    // Text first, then tool calls: that is the order a Messages response puts
    // them in, and a client that reads content[0] expecting prose gets prose.
    let mut content = Vec::new();
    if !text.is_empty() {
        content.push(serde_json::json!({"type": "text", "text": text}));
    }
    content.extend(blocks);

    let reply = serde_json::json!({
        "id": format!("msg_{}", std::process::id()),
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": anthropic_stop_reason(finish.as_deref(), tool_used),
        "stop_sequence": serde_json::Value::Null,
        "usage": {
            "input_tokens": usage.prompt_tokens,
            "output_tokens": usage.completion_tokens,
        },
    });
    respond(stream, 200, &reply)
}

fn tool_use_block(call: &ai_daemon_proto::frame::ToolCall) -> serde_json::Value {
    serde_json::json!({
        "type": "tool_use",
        "id": call.id,
        "name": call.name,
        // Anthropic carries arguments as an object, not the JSON *string*
        // OpenAI uses. A backend that produced something unparseable would
        // otherwise become a client-side crash, so it degrades to an empty
        // object rather than emitting a string where an object belongs.
        "input": serde_json::from_str::<serde_json::Value>(&call.arguments)
            .unwrap_or(serde_json::json!({})),
    })
}

/// The Messages streaming state machine.
///
/// Not one repeated chunk shape like OpenAI's: a client tracks named events
/// and block indices, and skipping any of them leaves it waiting. So every
/// path out of here — including an error mid-stream — closes the blocks it
/// opened and sends `message_stop`.
fn relay_anthropic_sse(
    stream: &mut TcpStream,
    reader: &mut impl Read,
    model: &str,
) -> Result<(), String> {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n"
    )
    .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    let id = format!("msg_{}", std::process::id());
    let send = |stream: &mut TcpStream, event: &str, data: serde_json::Value| -> Result<(), String> {
        write!(stream, "event: {event}\ndata: {data}\n\n").map_err(|e| e.to_string())?;
        stream.flush().map_err(|e| e.to_string())
    };

    send(
        stream,
        "message_start",
        serde_json::json!({
            "type": "message_start",
            "message": {
                "id": id,
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [],
                "stop_reason": serde_json::Value::Null,
                "stop_sequence": serde_json::Value::Null,
                "usage": {"input_tokens": 0, "output_tokens": 0},
            },
        }),
    )?;

    let mut index = 0usize;
    let mut text_open = false;
    let mut tool_used = false;
    let mut usage = ai_daemon_proto::frame::Usage::default();
    let mut finish: Option<String> = None;

    loop {
        match read_event(reader)? {
            None => break,
            Some(Event::Token { tok, .. }) => {
                if !text_open {
                    send(
                        stream,
                        "content_block_start",
                        serde_json::json!({
                            "type": "content_block_start",
                            "index": index,
                            "content_block": {"type": "text", "text": ""},
                        }),
                    )?;
                    text_open = true;
                }
                send(
                    stream,
                    "content_block_delta",
                    serde_json::json!({
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {"type": "text_delta", "text": tok},
                    }),
                )?;
            }
            Some(Event::ToolCall { tool_call }) => {
                index = close_text_block(stream, &send, index, &mut text_open)?;
                index = stream_tool_use(stream, &send, index, &tool_call)?;
                tool_used = true;
            }
            Some(Event::ToolCalls { tool_calls }) => {
                index = close_text_block(stream, &send, index, &mut text_open)?;
                for call in &tool_calls {
                    index = stream_tool_use(stream, &send, index, call)?;
                }
                tool_used = true;
            }
            Some(Event::Notice { event, detail }) => {
                // Not a Messages event. An SSE comment: clients ignore it, and
                // a human watching the stream sees why their context went.
                write!(stream, ": {event} {detail}\n\n").map_err(|e| e.to_string())?;
            }
            Some(Event::Done { usage: u, finish_reason, .. }) => {
                usage = u;
                finish = finish_reason;
                break;
            }
            Some(Event::Error { error }) => {
                // Close what is open before the error, or a client is left
                // holding an unterminated block.
                let _ = close_text_block(stream, &send, index, &mut text_open);
                send(
                    stream,
                    "error",
                    serde_json::json!({
                        "type": "error",
                        "error": {"type": "api_error", "message": format!("{}: {}", error.code, error.message)},
                    }),
                )?;
                send(stream, "message_stop", serde_json::json!({"type": "message_stop"}))?;
                return Ok(());
            }
            Some(_) => {}
        }
    }

    close_text_block(stream, &send, index, &mut text_open)?;
    send(
        stream,
        "message_delta",
        serde_json::json!({
            "type": "message_delta",
            "delta": {
                "stop_reason": anthropic_stop_reason(finish.as_deref(), tool_used),
                "stop_sequence": serde_json::Value::Null,
            },
            "usage": {"output_tokens": usage.completion_tokens},
        }),
    )?;
    send(stream, "message_stop", serde_json::json!({"type": "message_stop"}))
}

type Send = dyn Fn(&mut TcpStream, &str, serde_json::Value) -> Result<(), String>;

fn close_text_block(
    stream: &mut TcpStream,
    send: &Send,
    index: usize,
    open: &mut bool,
) -> Result<usize, String> {
    if !*open {
        return Ok(index);
    }
    send(
        stream,
        "content_block_stop",
        serde_json::json!({"type": "content_block_stop", "index": index}),
    )?;
    *open = false;
    Ok(index + 1)
}

fn stream_tool_use(
    stream: &mut TcpStream,
    send: &Send,
    index: usize,
    call: &ai_daemon_proto::frame::ToolCall,
) -> Result<usize, String> {
    send(
        stream,
        "content_block_start",
        serde_json::json!({
            "type": "content_block_start",
            "index": index,
            "content_block": {"type": "tool_use", "id": call.id, "name": call.name, "input": {}},
        }),
    )?;
    // The daemon delivers a whole call at once — it is grammar-constrained, so
    // there is no partial state worth streaming — but the client's parser is
    // built for deltas, so it arrives as one.
    send(
        stream,
        "content_block_delta",
        serde_json::json!({
            "type": "content_block_delta",
            "index": index,
            "delta": {"type": "input_json_delta", "partial_json": call.arguments},
        }),
    )?;
    send(
        stream,
        "content_block_stop",
        serde_json::json!({"type": "content_block_stop", "index": index}),
    )?;
    Ok(index + 1)
}

/// POST /v1/messages/count_tokens — the daemon's tokenizer, in Anthropic's
/// clothes. Claude Code asks before it sends, to decide what to trim.
// ---------------------------------------------------------------------------
// OpenAI Responses API — POST /v1/responses
//
// The second of OpenAI's two shapes, and for some clients now the only one.
// codex-cli 0.150 refuses to start against a provider configured for chat
// completions at all — `wire_api = "chat" is no longer supported` — so a
// bridge that speaks only /v1/chat/completions cannot serve it, however
// correct that endpoint is. Supporting one OpenAI dialect turned out to mean
// supporting the one its clients have left.
//
// The differences that matter here are shallow: `input` replaces `messages`
// and may be a bare string, `instructions` replaces the system message,
// `max_output_tokens` replaces `max_tokens`, tools are flat rather than
// wrapped in a `function` object, and the reply is an `output` array of items
// rather than a `choices` array. Everything underneath is the same session.
// ---------------------------------------------------------------------------

struct ResponsesTurn {
    messages: Vec<Message>,
    tools: Option<Vec<ai_daemon_proto::frame::ToolSchema>>,
    params: Params,
    stream: bool,
    model: String,
}

/// Flatten a Responses content value: either a bare string, or the part array
/// whose text lives under `input_text` / `output_text` / `text`.
fn responses_text(content: Option<&serde_json::Value>) -> String {
    match content {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(parts)) => {
            let mut text = String::new();
            for part in parts {
                match part.get("type").and_then(|t| t.as_str()) {
                    Some("input_text") | Some("output_text") | Some("text") | None => {
                        if let Some(s) = part.get("text").and_then(|t| t.as_str()) {
                            text.push_str(s);
                        }
                    }
                    // Images arrive as data: URLs or not at all, for the same
                    // reason they do on the other two routes: this process
                    // does not fetch what a prompt names.
                    _ => {}
                }
            }
            text
        }
        _ => String::new(),
    }
}

fn parse_responses_body(body: &serde_json::Value) -> Result<ResponsesTurn, String> {
    let model = body.get("model").and_then(|m| m.as_str()).unwrap_or("default").to_string();
    let mut messages: Vec<Message> = Vec::new();

    // `instructions` is the system prompt under another name.
    if let Some(text) = body.get("instructions").and_then(|i| i.as_str()) {
        if !text.is_empty() {
            messages.push(Message {
                role: "system".into(),
                content: text.to_string(),
                attachments: Vec::new(),
                tool_call_id: None,
            });
        }
    }

    match body.get("input") {
        // The one-shot form: `input` is the whole user turn.
        Some(serde_json::Value::String(s)) => messages.push(Message {
            role: "user".into(),
            content: s.clone(),
            attachments: Vec::new(),
            tool_call_id: None,
        }),
        Some(serde_json::Value::Array(items)) => {
            for item in items {
                match item.get("type").and_then(|t| t.as_str()) {
                    // A tool result on its way back in. `call_id` is the
                    // Responses spelling of tool_call_id.
                    Some("function_call_output") => {
                        let output = match item.get("output") {
                            Some(serde_json::Value::String(s)) => s.clone(),
                            Some(other) => other.to_string(),
                            None => String::new(),
                        };
                        messages.push(Message {
                            role: "tool".into(),
                            content: output,
                            attachments: Vec::new(),
                            tool_call_id: item
                                .get("call_id")
                                .and_then(|c| c.as_str())
                                .map(str::to_string),
                        });
                    }
                    // The model's own earlier tool call, replayed. Carried as
                    // assistant text so the turn reads in order; the daemon
                    // mints tool calls itself and does not need it structured.
                    Some("function_call") => {
                        let name = item.get("name").and_then(|n| n.as_str()).unwrap_or("");
                        let args = item.get("arguments").and_then(|a| a.as_str()).unwrap_or("");
                        messages.push(Message {
                            role: "assistant".into(),
                            content: format!("{name}({args})"),
                            attachments: Vec::new(),
                            tool_call_id: None,
                        });
                    }
                    // "message", or an item with no type at all, which the API
                    // permits for the plain {role, content} shape.
                    _ => {
                        let role =
                            item.get("role").and_then(|r| r.as_str()).unwrap_or("user").to_string();
                        messages.push(Message {
                            role,
                            content: responses_text(item.get("content")),
                            attachments: Vec::new(),
                            tool_call_id: None,
                        });
                    }
                }
            }
        }
        _ => return Err("input is required".into()),
    }

    if messages.iter().all(|m| m.role == "system") {
        return Err("input contained no user or tool message".into());
    }

    // Tools are flat here: {type, name, description, parameters} rather than
    // chat's {type, function: {...}}.
    let tools = body.get("tools").and_then(|t| t.as_array()).map(|list| {
        list.iter()
            .filter(|t| {
                t.get("type").and_then(|k| k.as_str()).map(|k| k == "function").unwrap_or(true)
            })
            .map(|t| ai_daemon_proto::frame::ToolSchema {
                name: t.get("name").and_then(|n| n.as_str()).unwrap_or_default().to_string(),
                description: t
                    .get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or_default()
                    .to_string(),
                json_schema: t.get("parameters").cloned().unwrap_or(serde_json::Value::Null),
            })
            .collect::<Vec<_>>()
    });

    let params = Params {
        temperature: body.get("temperature").and_then(|v| v.as_f64()).map(|v| v as f32),
        top_p: body.get("top_p").and_then(|v| v.as_f64()).map(|v| v as f32),
        max_tokens: body.get("max_output_tokens").and_then(|v| v.as_u64()).map(|v| v as u32),
        ..Default::default()
    };

    Ok(ResponsesTurn {
        messages,
        tools: tools.filter(|t| !t.is_empty()),
        params,
        stream: body.get("stream").and_then(|s| s.as_bool()).unwrap_or(false),
        model,
    })
}

fn responses(stream: &mut TcpStream, request: &HttpRequest, peer: &Peer) -> Result<(), String> {
    let body: serde_json::Value = match serde_json::from_slice(&request.body) {
        Ok(body) => body,
        Err(e) => return respond(stream, 400, &error_body("invalid_request_error", &e.to_string())),
    };
    let turn = match parse_responses_body(&body) {
        Ok(turn) => turn,
        Err(e) => return respond(stream, 400, &error_body("invalid_request_error", &e)),
    };

    let session = match open_session(&turn.model, peer, false) {
        Ok(session) => session,
        Err(e) => {
            let status = if e.contains("AccessDenied") { 403 } else { 400 };
            return respond(stream, status, &error_body("permission_error", &e));
        }
    };
    let mut socket = session.socket.try_clone().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(session.socket.try_clone().map_err(|e| e.to_string())?);
    frame::write_cbor(&mut socket, &Request::Hello { proto: DATA_PROTO })
        .map_err(|e| e.to_string())?;
    let _ = read_event(&mut reader);

    frame::write_cbor(
        &mut socket,
        &Request::Generate {
            messages: turn.messages,
            stream: true,
            params: Some(turn.params),
            grammar: None,
            tools: turn.tools,
        },
    )
    .map_err(|e| e.to_string())?;

    let mut cancel_channel = session.socket.try_clone().map_err(|e| e.to_string())?;
    let outcome = if turn.stream {
        relay_responses_sse(stream, &mut reader, &turn.model)
    } else {
        relay_responses_json(stream, &mut reader, &mut cancel_channel, &turn.model)
    };
    session.close();
    outcome
}

/// A `function_call` output item, which is how Responses carries a tool call.
fn responses_call_item(call: &ai_daemon_proto::frame::ToolCall) -> serde_json::Value {
    serde_json::json!({
        "type": "function_call",
        "id": format!("fc_{}", call.id),
        "call_id": call.id,
        "name": call.name,
        // A JSON *string*, unlike the Anthropic route's object.
        "arguments": call.arguments.to_string(),
        "status": "completed",
    })
}

fn responses_envelope(
    id: &str,
    model: &str,
    status: &str,
    output: Vec<serde_json::Value>,
    usage: &ai_daemon_proto::frame::Usage,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "object": "response",
        "status": status,
        "model": model,
        "output": output,
        "parallel_tool_calls": true,
        "usage": {
            "input_tokens": usage.prompt_tokens,
            "output_tokens": usage.completion_tokens,
            "total_tokens": usage.prompt_tokens + usage.completion_tokens,
        },
    })
}

fn relay_responses_json(
    stream: &mut TcpStream,
    reader: &mut impl Read,
    daemon: &mut UnixStream,
    model: &str,
) -> Result<(), String> {
    let mut text = String::new();
    let mut calls: Vec<serde_json::Value> = Vec::new();
    let mut usage = ai_daemon_proto::frame::Usage::default();
    let mut abandoned = false;

    loop {
        if !abandoned && peer_hung_up(stream) {
            abandoned = true;
            eprintln!("<6>ai-daemon-shim: client went away; cancelling the generation");
            let _ = frame::write_cbor(daemon, &Request::Cancel);
        }
        match read_event(reader)? {
            None => break,
            Some(Event::Token { tok, .. }) => text.push_str(&tok),
            Some(Event::ToolCall { tool_call }) => calls.push(responses_call_item(&tool_call)),
            Some(Event::ToolCalls { tool_calls }) => {
                calls.extend(tool_calls.iter().map(responses_call_item))
            }
            Some(Event::Done { usage: u, .. }) => {
                usage = u;
                break;
            }
            Some(Event::Error { error }) => {
                if abandoned {
                    return Ok(());
                }
                let status = match error.code.as_str() {
                    "policy-denied" => 403,
                    "rate-limited" => 429,
                    _ => 400,
                };
                return respond(stream, status, &error_body(&error.code, &error.message));
            }
            Some(_) => {}
        }
    }
    if abandoned {
        return Ok(());
    }

    let id = format!("resp_{}", std::process::id());
    let mut output = Vec::new();
    if !text.is_empty() {
        output.push(serde_json::json!({
            "type": "message",
            "id": format!("msg_{}", std::process::id()),
            "status": "completed",
            "role": "assistant",
            "content": [{"type": "output_text", "text": text, "annotations": []}],
        }));
    }
    output.extend(calls);
    respond(stream, 200, &responses_envelope(&id, model, "completed", output, &usage))
}

fn relay_responses_sse(
    stream: &mut TcpStream,
    reader: &mut impl Read,
    model: &str,
) -> Result<(), String> {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n"
    )
    .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    // Every Responses event carries a sequence number, and clients that track
    // ordering reject a stream without one.
    let mut seq = 0u64;
    let mut send = |stream: &mut TcpStream, kind: &str, mut data: serde_json::Value| -> Result<(), String> {
        if let Some(obj) = data.as_object_mut() {
            obj.insert("sequence_number".into(), serde_json::json!(seq));
        }
        seq += 1;
        write!(stream, "event: {kind}\ndata: {data}\n\n").map_err(|e| e.to_string())?;
        stream.flush().map_err(|e| e.to_string())
    };

    let id = format!("resp_{}", std::process::id());
    let msg_id = format!("msg_{}", std::process::id());
    let empty = ai_daemon_proto::frame::Usage::default();

    send(
        stream,
        "response.created",
        serde_json::json!({
            "type": "response.created",
            "response": responses_envelope(&id, model, "in_progress", vec![], &empty),
        }),
    )?;

    let mut text = String::new();
    let mut calls: Vec<serde_json::Value> = Vec::new();
    let mut usage = ai_daemon_proto::frame::Usage::default();
    let mut text_open = false;
    let mut index = 0usize;

    loop {
        match read_event(reader)? {
            None => break,
            Some(Event::Token { tok, .. }) => {
                if !text_open {
                    text_open = true;
                    send(
                        stream,
                        "response.output_item.added",
                        serde_json::json!({
                            "type": "response.output_item.added",
                            "output_index": index,
                            "item": {
                                "type": "message", "id": msg_id, "status": "in_progress",
                                "role": "assistant", "content": [],
                            },
                        }),
                    )?;
                    send(
                        stream,
                        "response.content_part.added",
                        serde_json::json!({
                            "type": "response.content_part.added",
                            "item_id": msg_id, "output_index": index, "content_index": 0,
                            "part": {"type": "output_text", "text": "", "annotations": []},
                        }),
                    )?;
                }
                text.push_str(&tok);
                send(
                    stream,
                    "response.output_text.delta",
                    serde_json::json!({
                        "type": "response.output_text.delta",
                        "item_id": msg_id, "output_index": index, "content_index": 0,
                        "delta": tok,
                    }),
                )?;
            }
            Some(Event::ToolCall { tool_call }) => calls.push(responses_call_item(&tool_call)),
            Some(Event::ToolCalls { tool_calls }) => {
                calls.extend(tool_calls.iter().map(responses_call_item))
            }
            Some(Event::Done { usage: u, .. }) => {
                usage = u;
                break;
            }
            Some(Event::Error { error }) => {
                send(
                    stream,
                    "response.failed",
                    serde_json::json!({
                        "type": "response.failed",
                        "response": {
                            "id": id, "object": "response", "status": "failed", "model": model,
                            "error": {"code": error.code, "message": error.message},
                        },
                    }),
                )?;
                return Ok(());
            }
            Some(_) => {}
        }
    }

    if text_open {
        send(
            stream,
            "response.output_text.done",
            serde_json::json!({
                "type": "response.output_text.done",
                "item_id": msg_id, "output_index": index, "content_index": 0, "text": text,
            }),
        )?;
        send(
            stream,
            "response.content_part.done",
            serde_json::json!({
                "type": "response.content_part.done",
                "item_id": msg_id, "output_index": index, "content_index": 0,
                "part": {"type": "output_text", "text": text, "annotations": []},
            }),
        )?;
        send(
            stream,
            "response.output_item.done",
            serde_json::json!({
                "type": "response.output_item.done",
                "output_index": index,
                "item": {
                    "type": "message", "id": msg_id, "status": "completed",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": text, "annotations": []}],
                },
            }),
        )?;
        index += 1;
    }

    for call in &calls {
        send(
            stream,
            "response.output_item.added",
            serde_json::json!({
                "type": "response.output_item.added",
                "output_index": index, "item": call,
            }),
        )?;
        send(
            stream,
            "response.function_call_arguments.done",
            serde_json::json!({
                "type": "response.function_call_arguments.done",
                "item_id": call.get("id"), "output_index": index,
                "arguments": call.get("arguments"),
            }),
        )?;
        send(
            stream,
            "response.output_item.done",
            serde_json::json!({
                "type": "response.output_item.done",
                "output_index": index, "item": call,
            }),
        )?;
        index += 1;
    }

    let mut output = Vec::new();
    if !text.is_empty() {
        output.push(serde_json::json!({
            "type": "message", "id": msg_id, "status": "completed", "role": "assistant",
            "content": [{"type": "output_text", "text": text, "annotations": []}],
        }));
    }
    output.extend(calls);
    send(
        stream,
        "response.completed",
        serde_json::json!({
            "type": "response.completed",
            "response": responses_envelope(&id, model, "completed", output, &usage),
        }),
    )
}

fn count_tokens(request: &HttpRequest, peer: &Peer) -> Result<serde_json::Value, String> {
    let body: serde_json::Value =
        serde_json::from_slice(&request.body).map_err(|e| e.to_string())?;
    let model = body.get("model").and_then(|m| m.as_str()).unwrap_or("default").to_string();

    // Everything the request would have sent, flattened. Counting only the
    // last turn would under-report by the whole conversation.
    let mut text = String::new();
    if let Some(system) = body.get("system") {
        match system {
            serde_json::Value::String(s) => text.push_str(s),
            serde_json::Value::Array(blocks) => {
                for block in blocks {
                    if let Some(s) = block.get("text").and_then(|t| t.as_str()) {
                        text.push_str(s);
                    }
                }
            }
            _ => {}
        }
    }
    for entry in body.get("messages").and_then(|m| m.as_array()).cloned().unwrap_or_default() {
        match entry.get("content") {
            Some(serde_json::Value::String(s)) => text.push_str(s),
            Some(serde_json::Value::Array(parts)) => {
                for part in parts {
                    if let Some(s) = part.get("text").and_then(|t| t.as_str()) {
                        text.push_str(s);
                    }
                }
            }
            _ => {}
        }
    }

    let session = open_session(&model, peer, true)?;
    let mut socket = session.socket.try_clone().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(session.socket.try_clone().map_err(|e| e.to_string())?);
    frame::write_cbor(&mut socket, &Request::Tokenize { text }).map_err(|e| e.to_string())?;

    let mut count = 0usize;
    loop {
        match read_event(&mut reader)? {
            None => break,
            Some(Event::Tokens { tokens }) => count = tokens.len(),
            Some(Event::Done { .. }) => break,
            Some(Event::Error { error }) => {
                session.close();
                return Err(format!("{}: {}", error.code, error.message));
            }
            Some(_) => {}
        }
    }
    session.close();
    Ok(serde_json::json!({"input_tokens": count}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_data_urls_decode() {
        // "hello" -> aGVsbG8=
        assert_eq!(
            decode_data_url("data:image/png;base64,aGVsbG8=").unwrap(),
            b"hello".to_vec()
        );
        assert_eq!(base64_decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(base64_decode("aGVsbG8h").unwrap(), b"hello!".to_vec());
        // Whitespace happens when a client wraps a long line.
        assert_eq!(base64_decode("aGVs\nbG8=").unwrap(), b"hello".to_vec());
        // URL-safe alphabet, because some clients use it.
        assert_eq!(base64_decode("-_8=").unwrap(), vec![0xfb, 0xff]);
    }

    /// The single most important refusal in this binary. Following an
    /// `image_url` would put a server-side request forgery primitive inside
    /// the machine's AI service, reachable by anything that can talk to
    /// loopback.
    #[test]
    fn a_remote_image_url_is_refused_rather_than_fetched() {
        for url in [
            "https://example.com/x.png",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/shadow",
            "ftp://internal/x.png",
        ] {
            let error = decode_data_url(url).unwrap_err();
            assert!(error.contains("never fetches"), "{url}: {error}");
        }
    }

    #[test]
    fn a_non_base64_data_url_is_refused() {
        let error = decode_data_url("data:text/plain,hello").unwrap_err();
        assert!(error.contains("base64"), "{error}");
    }

    #[test]
    fn invalid_base64_is_an_error_not_silent_truncation() {
        assert!(base64_decode("aGVs*bG8=").is_err());
    }

    #[test]
    fn error_bodies_are_openai_shaped_so_clients_recognise_them() {
        let body = error_body("rate-limited", "over the allowance");
        assert_eq!(body["error"]["type"], "rate-limited");
        assert_eq!(body["error"]["message"], "over the allowance");
    }

    /// The regression that kept Claude Code out. It sends every turn to
    /// `/v1/messages?beta=true`; matching the raw target routed that to 404,
    /// and an Anthropic client reads a 404 from /v1/messages as a missing
    /// model, so the user was told their installed model did not exist.
    #[test]
    fn a_query_string_does_not_change_the_route() {
        assert_eq!(route_path("/v1/messages?beta=true"), "/v1/messages");
        assert_eq!(route_path("/v1/messages"), "/v1/messages");
        assert_eq!(
            route_path("/v1/messages/count_tokens?beta=true"),
            "/v1/messages/count_tokens"
        );
        assert_eq!(route_path("/v1/chat/completions?a=1&b=2"), "/v1/chat/completions");
        assert_eq!(route_path("/v1/models?"), "/v1/models");
        assert_eq!(route_path(""), "");
    }
}
