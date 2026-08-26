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
//!   authorisation gets the identity that deserves.
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
const MAX_BODY: usize = 32 * 1024 * 1024;

fn main() {
    let mut port = DEFAULT_PORT;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => port = args.next().and_then(|v| v.parse().ok()).unwrap_or(port),
            "--version" | "-V" => {
                println!("ai-daemon-shim {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--help" | "-h" => {
                println!(
                    "ai-daemon-shim {} — OpenAI-compatible endpoint for ai-daemon

usage: ai-daemon-shim [--port N]   (default {DEFAULT_PORT}, always on 127.0.0.1)

Routes: GET /v1/models, POST /v1/chat/completions, POST /v1/embeddings.
Every request becomes an ai-daemon session under the caller's peer
credentials, at the lowest trust class. Off by default; enable with
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
        std::thread::spawn(move || {
            let n = served.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = serve(stream) {
                eprintln!("<4>ai-daemon-shim: request {n} failed: {e}");
            }
        });
    }
}

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn serve(mut stream: TcpStream) -> Result<(), String> {
    let peer = peer_cred(stream.as_raw_fd())?;
    let request = read_request(&mut stream)?;

    let result = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/v1/models") | ("GET", "/api/tags") => list_models(),
        ("POST", "/v1/chat/completions") => {
            return chat(&mut stream, &request, &peer);
        }
        ("POST", "/v1/embeddings") => embeddings(&request, &peer),
        ("GET", "/health") => Ok(serde_json::json!({"status": "ok"})),
        _ => {
            respond(&mut stream, 404, &error_body("not_found", "no such route"))?;
            return Ok(());
        }
    };

    match result {
        Ok(json) => respond(&mut stream, 200, &json),
        Err(e) => respond(&mut stream, 400, &error_body("invalid_request_error", &e)),
    }
}

fn read_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();

    let mut content_length = 0usize;
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
        }
    }
    if content_length > MAX_BODY {
        return Err(format!("body of {content_length} bytes is over the limit"));
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).map_err(|e| e.to_string())?;
    }
    Ok(HttpRequest { method, path, body })
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
}

fn peer_cred(fd: RawFd) -> Result<Peer, String> {
    // A loopback TCP socket has no SO_PEERCRED, so this is best-effort: the
    // shim reports what it can and the daemon treats the whole class as
    // untrusted anyway. Where the kernel does answer (a Unix socket, if the
    // shim is ever taught to listen on one), the answer is used.
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
        return Ok(Peer { pid: std::process::id(), uid: unsafe { libc::getuid() } });
    }
    Ok(Peer { pid: ucred.pid as u32, uid: ucred.uid })
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
            Some(Event::Token { tok }) => {
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
            Some(Event::Token { tok }) => content.push_str(&tok),
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
}
