//! ai-daemon-backend-llamacpp — the reference provider backend.
//!
//! llama.cpp is the right first backend for the same reason the spec names it:
//! one codebase covers CPU, Vulkan, CUDA, ROCm and SYCL, reads GGUF, and
//! already implements constrained decoding with GBNF, which §10's tool calling
//! depends on.
//!
//! This backend drives `llama-server` as a child process and speaks HTTP to it
//! on a loopback port, rather than linking libllama. Three reasons, in order
//! of how much they matter:
//!
//! 1. **The crash boundary is already the point.** §7 puts backends out of
//!    process so a GPU stack fault cannot take the policy engine with it. A
//!    backend that links CUDA and then also gets faulted by it has only moved
//!    the problem one process along; keeping the model runtime in a *third*
//!    process means a segfault costs the model, not the backend, and the
//!    daemon sees a clean error rather than a dead plugin.
//! 2. **Version skew is the distro's problem to solve, not ours.** Arch ships
//!    llama.cpp with its own ABI churn. Talking to its stable HTTP surface
//!    means a llama.cpp upgrade does not require rebuilding ai-daemon.
//! 3. **It is honest about what it is.** This is an adapter. Pretending
//!    otherwise by linking the library would buy a few milliseconds of
//!    per-token latency on a path already crossing two sockets.
//!
//! The cost is real and worth stating: one more process, one more loopback
//! socket, and a `llama-server` that must be on `$PATH` or named in the
//! backend's configuration. When it is not there, this backend declines to
//! load models and says so, rather than failing at first token.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ai_daemon_proto::backend::{BackendEvent, BackendInfo, BackendRequest};
use ai_daemon_proto::frame::{self, Message, Params, ToolCall, Usage};
use ai_daemon_proto::BACKEND_PROTO;

const NAME: &str = "llamacpp";
/// Port range the backend picks a free port from. Loopback only: the model
/// runtime must never be reachable from anywhere, which is why this is not
/// configurable to a real interface.
const PORT_BASE: u16 = 18_400;

type Writer = Arc<Mutex<UnixStream>>;

struct Loaded {
    #[allow(dead_code)]
    model_id: String,
    child: Child,
    port: u16,
    n_ctx: u32,
    kv_bytes_per_token: u64,
}

impl Drop for Loaded {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct State {
    server_binary: PathBuf,
    threads: Option<String>,
    gpu_layers: Option<String>,
    models: Mutex<HashMap<String, Loaded>>,
    paused: Mutex<HashMap<u64, Arc<AtomicBool>>>,
    cancelled: Mutex<HashMap<u64, Arc<AtomicBool>>>,
    /// The socket each generation is reading llama-server's stream from.
    ///
    /// Kept so a cancel can act on the transport rather than on a flag. During
    /// prompt evaluation llama-server sends nothing at all — tens of seconds
    /// on CPU with a large context, minutes on a document — so the generate
    /// thread is blocked in a read with no token boundary at which to notice
    /// anything, which is exactly when a user reaches for cancel.
    streams: Mutex<HashMap<u64, TcpStream>>,
}

fn main() {
    let fd: i32 = std::env::var("AI_DAEMON_BACKEND_FD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    // SAFETY: the daemon dup2'd our socketpair end onto this fd before exec.
    let socket = unsafe { UnixStream::from_raw_fd(fd) };
    let writer: Writer = match socket.try_clone() {
        Ok(clone) => Arc::new(Mutex::new(clone)),
        Err(e) => {
            eprintln!("<3>{NAME}: cannot dup the control socket: {e}");
            std::process::exit(1);
        }
    };

    let state = Arc::new(State {
        server_binary: locate_server(),
        threads: std::env::var("AI_DAEMON_LLAMACPP_THREADS").ok(),
        gpu_layers: std::env::var("AI_DAEMON_LLAMACPP_GPU_LAYERS").ok(),
        models: Mutex::new(HashMap::new()),
        paused: Mutex::new(HashMap::new()),
        cancelled: Mutex::new(HashMap::new()),
        streams: Mutex::new(HashMap::new()),
    });

    let mut reader = BufReader::new(socket);
    loop {
        let request: BackendRequest = match frame::read_typed(&mut reader) {
            Ok(Some(request)) => request,
            Ok(None) => break,
            Err(e) => {
                eprintln!("<3>{NAME}: protocol error: {e}");
                break;
            }
        };
        if handle(&state, &writer, request).is_break() {
            break;
        }
    }
    state.models.lock().unwrap().clear();
}

/// `llama-server` from configuration, then `$PATH`, then the places Arch and
/// Debian put it. Resolved once at startup so `hello` can be honest about
/// whether this backend can do anything.
fn locate_server() -> PathBuf {
    if let Ok(explicit) = std::env::var("AI_DAEMON_LLAMACPP_SERVER") {
        return PathBuf::from(explicit);
    }
    for candidate in [
        "/usr/bin/llama-server",
        "/usr/local/bin/llama-server",
        "/opt/llama.cpp/bin/llama-server",
    ] {
        if std::path::Path::new(candidate).exists() {
            return PathBuf::from(candidate);
        }
    }
    PathBuf::from("llama-server")
}

fn handle(state: &Arc<State>, writer: &Writer, request: BackendRequest) -> std::ops::ControlFlow<()> {
    match request {
        BackendRequest::Hello { proto } => {
            if proto != BACKEND_PROTO {
                send(writer, &BackendEvent::Error {
                    req_id: None,
                    code: "protocol".into(),
                    message: format!("{NAME} speaks protocol {BACKEND_PROTO}"),
                });
                return std::ops::ControlFlow::Break(());
            }
            let available = state.server_binary.exists()
                || which(&state.server_binary).is_some();
            if !available {
                eprintln!(
                    "<4>{NAME}: {} not found; this backend will decline every load",
                    state.server_binary.display()
                );
            }
            send(writer, &BackendEvent::Hello {
                proto: BACKEND_PROTO,
                info: BackendInfo {
                    name: NAME.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    formats: if available { vec!["gguf".into()] } else { Vec::new() },
                    quantizations: vec![
                        "q2_k".into(), "q3_k_m".into(), "q4_0".into(), "q4_k_s".into(),
                        "q4_k_m".into(), "q5_k_m".into(), "q6_k".into(), "q8_0".into(),
                        "f16".into(), "bf16".into(), "f32".into(),
                    ],
                    // Declared, not opened: the daemon checks these against
                    // the unit's DeviceAllow before it will use the backend,
                    // and llama-server is the process that actually opens them.
                    devices: detect_devices(),
                    device_memory: None,
                    capabilities: if available {
                        vec![
                            "generate".into(),
                            "embed".into(),
                            "logprobs".into(),
                            "grammar".into(),
                            "tools".into(),
                        ]
                    } else {
                        Vec::new()
                    },
                    local: true,
                },
            });
        }
        BackendRequest::Load { model_id, path, n_ctx, .. } => match load(state, &model_id, &path, n_ctx) {
            Ok((n_ctx, kv_bytes_per_token)) => {
                send(writer, &BackendEvent::Loaded { model_id, kv_bytes_per_token, n_ctx })
            }
            Err(e) => send(writer, &BackendEvent::Error {
                req_id: None,
                code: "backend-failed".into(),
                message: e,
            }),
        },
        BackendRequest::Unload { model_id } => {
            state.models.lock().unwrap().remove(&model_id);
            send(writer, &BackendEvent::Unloaded { model_id });
        }
        BackendRequest::Generate { req_id, model_id, messages, params, grammar, tools, attachments, .. } => {
            if !attachments.is_empty() {
                send(writer, &BackendEvent::Error {
                    req_id: Some(req_id),
                    code: "attachment-unsupported".into(),
                    message: "this backend does not declare vision or audio-in".into(),
                });
                return std::ops::ControlFlow::Continue(());
            }
            let paused = Arc::new(AtomicBool::new(false));
            let cancelled = Arc::new(AtomicBool::new(false));
            state.paused.lock().unwrap().insert(req_id, paused.clone());
            state.cancelled.lock().unwrap().insert(req_id, cancelled.clone());
            let state = state.clone();
            let writer = writer.clone();
            let has_tools = tools.is_some_and(|t| !t.is_empty());
            std::thread::spawn(move || {
                if let Err(e) = generate(
                    &state, &writer, req_id, &model_id, &messages, &params,
                    grammar.as_deref(), has_tools, &paused, &cancelled,
                ) {
                    send(&writer, &BackendEvent::Error {
                        req_id: Some(req_id),
                        code: "backend-failed".into(),
                        message: e,
                    });
                }
                state.paused.lock().unwrap().remove(&req_id);
                state.cancelled.lock().unwrap().remove(&req_id);
                state.streams.lock().unwrap().remove(&req_id);
            });
        }
        BackendRequest::Embed { req_id, model_id, inputs } => {
            let state = state.clone();
            let writer = writer.clone();
            std::thread::spawn(move || match embed(&state, &model_id, &inputs) {
                Ok(vectors) => {
                    send(&writer, &BackendEvent::Vectors { req_id, vectors });
                    send(&writer, &BackendEvent::Done {
                        req_id,
                        usage: Usage::default(),
                        finish_reason: Some("stop".into()),
                    });
                }
                Err(e) => send(&writer, &BackendEvent::Error {
                    req_id: Some(req_id),
                    code: "backend-failed".into(),
                    message: e,
                }),
            });
        }
        BackendRequest::Tokenize { req_id, model_id, text } => {
            let state = state.clone();
            let writer = writer.clone();
            std::thread::spawn(move || match tokenize(&state, &model_id, &text) {
                Ok(tokens) => {
                    let count = tokens.len() as u64;
                    send(&writer, &BackendEvent::Tokens { req_id, tokens });
                    send(&writer, &BackendEvent::Done {
                        req_id,
                        usage: Usage { prompt_tokens: count, ..Usage::default() },
                        finish_reason: Some("stop".into()),
                    });
                }
                Err(e) => send(&writer, &BackendEvent::Error {
                    req_id: Some(req_id),
                    code: "backend-failed".into(),
                    message: e,
                }),
            });
        }
        BackendRequest::Cancel { req_id } => {
            if let Some(flag) = state.cancelled.lock().unwrap().get(&req_id) {
                flag.store(true, Ordering::Relaxed);
            }
            // Then end the read, rather than hoping a token arrives to notice
            // the flag at. Shutting the socket also tells llama-server the
            // client is gone, which is how it drops the slot; the blocked
            // read_line returns at once and the loop reports finish=cancelled.
            //
            // Pause deliberately stays flag-only: a pause wants to resume, and
            // a boundary is the right place to wait at.
            if let Some(stream) = state.streams.lock().unwrap().get(&req_id) {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
        }
        BackendRequest::Pause { req_id } => {
            if let Some(flag) = state.paused.lock().unwrap().get(&req_id) {
                flag.store(true, Ordering::Relaxed);
            }
        }
        BackendRequest::Resume { req_id } => {
            if let Some(flag) = state.paused.lock().unwrap().get(&req_id) {
                flag.store(false, Ordering::Relaxed);
            }
        }
        // llama-server owns its own KV slots and reuses them by prefix; there
        // is nothing for this backend to drop that the server will not drop
        // itself. Saying so beats pretending to have complied.
        BackendRequest::DropCache { .. } => {}
        BackendRequest::Shutdown => return std::ops::ControlFlow::Break(()),
    }
    std::ops::ControlFlow::Continue(())
}

fn detect_devices() -> Vec<String> {
    let mut devices = Vec::new();
    for dir in ["/dev/dri", "/dev/accel"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                if name.starts_with("renderD") || name.starts_with("accel") {
                    devices.push(path.display().to_string());
                }
            }
        }
    }
    devices.sort();
    devices
}

fn which(binary: &std::path::Path) -> Option<PathBuf> {
    if binary.is_absolute() {
        return binary.exists().then(|| binary.to_path_buf());
    }
    let path = std::env::var("PATH").ok()?;
    path.split(':')
        .map(|dir| PathBuf::from(dir).join(binary))
        .find(|candidate| candidate.exists())
}

fn load(state: &State, model_id: &str, path: &str, n_ctx: u32) -> Result<(u32, u64), String> {
    if let Some(loaded) = state.models.lock().unwrap().get(model_id) {
        return Ok((loaded.n_ctx, loaded.kv_bytes_per_token));
    }
    let server = which(&state.server_binary)
        .ok_or_else(|| format!("{} is not installed", state.server_binary.display()))?;
    if !std::path::Path::new(path).exists() {
        return Err(format!("{path} does not exist"));
    }
    let n_ctx = if n_ctx == 0 { 4096 } else { n_ctx };
    let port = free_port().ok_or("no free loopback port for llama-server")?;

    let mut command = Command::new(&server);
    command
        .arg("--model").arg(path)
        .arg("--host").arg("127.0.0.1")
        .arg("--port").arg(port.to_string())
        .arg("--ctx-size").arg(n_ctx.to_string())
        // One slot: scheduling is the daemon's job (§8), and a server that
        // schedules behind our back would make the daemon's accounting a
        // fiction.
        .arg("--parallel").arg("1")
        .arg("--no-webui")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if let Some(threads) = &state.threads {
        command.arg("--threads").arg(threads);
    }
    if let Some(layers) = &state.gpu_layers {
        command.arg("--n-gpu-layers").arg(layers);
    }

    let child = command.spawn().map_err(|e| format!("spawning {}: {e}", server.display()))?;
    let mut loaded = Loaded {
        model_id: model_id.to_string(),
        child,
        port,
        n_ctx,
        kv_bytes_per_token: 0,
    };

    // Loading weights from cold cache is slow and legitimately so; the daemon
    // gives us five minutes and we use it rather than guessing a smaller one.
    let deadline = Instant::now() + Duration::from_secs(280);
    let mut ready = false;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = loaded.child.try_wait() {
            return Err(format!("llama-server exited with {status} before becoming ready"));
        }
        if http(port, "GET", "/health", None).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    if !ready {
        return Err("llama-server never became healthy".into());
    }

    loaded.kv_bytes_per_token = kv_estimate(port, n_ctx);
    let result = (loaded.n_ctx, loaded.kv_bytes_per_token);
    state.models.lock().unwrap().insert(model_id.to_string(), loaded);
    Ok(result)
}

/// Bytes of KV cache per token, from the server's own reported architecture
/// where it offers one, and from a conservative default where it does not.
///
/// The scheduler's global budget (§8) is only as good as this number, so
/// erring high is the safe direction: over-estimating costs throughput, and
/// under-estimating costs an OOM.
fn kv_estimate(port: u16, _n_ctx: u32) -> u64 {
    const DEFAULT: u64 = 131_072;
    let Ok(body) = http(port, "GET", "/props", None) else {
        return DEFAULT;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) else {
        return DEFAULT;
    };
    let meta = json.get("default_generation_settings").and_then(|s| s.get("model"));
    let layers = meta
        .and_then(|m| m.get("n_layer"))
        .and_then(|v| v.as_u64());
    let heads = meta
        .and_then(|m| m.get("n_head_kv"))
        .and_then(|v| v.as_u64());
    let embd = meta.and_then(|m| m.get("n_embd")).and_then(|v| v.as_u64());
    match (layers, heads, embd) {
        // key and value, two bytes each at f16, per head-dimension per layer.
        (Some(layers), Some(heads), Some(embd)) if heads > 0 => {
            let head_dim = embd / heads.max(1);
            (layers * heads * head_dim * 2 * 2).max(1024)
        }
        _ => DEFAULT,
    }
}

fn free_port() -> Option<u16> {
    for offset in 0..64u16 {
        let port = PORT_BASE + offset;
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Some(port);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn generate(
    state: &State,
    writer: &Writer,
    req_id: u64,
    model_id: &str,
    messages: &[Message],
    params: &Params,
    grammar: Option<&str>,
    has_tools: bool,
    paused: &AtomicBool,
    cancelled: &AtomicBool,
) -> Result<(), String> {
    let port = state
        .models
        .lock()
        .unwrap()
        .get(model_id)
        .map(|m| m.port)
        .ok_or_else(|| format!("{model_id} is not loaded"))?;

    let mut request = serde_json::json!({
        "messages": messages.iter().map(|m| serde_json::json!({
            "role": if m.role == "tool" { "user" } else { m.role.as_str() },
            "content": m.content,
        })).collect::<Vec<_>>(),
        "stream": true,
        "n_predict": params.max_tokens.unwrap_or(512),
    });
    if let Some(temperature) = params.temperature {
        request["temperature"] = serde_json::json!(temperature);
    }
    if let Some(top_p) = params.top_p {
        request["top_p"] = serde_json::json!(top_p);
    }
    if let Some(seed) = params.seed {
        request["seed"] = serde_json::json!(seed);
    }
    if let Some(stop) = &params.stop {
        request["stop"] = serde_json::json!(stop);
    }
    if let Some(grammar) = grammar {
        request["grammar"] = serde_json::json!(grammar);
    }

    let mut stream = open(port)?;
    match stream.try_clone() {
        Ok(clone) => {
            state.streams.lock().unwrap().insert(req_id, clone);
        }
        Err(e) => eprintln!(
            "<4>{NAME}: cannot dup the generation socket ({e}); a cancel will wait for the next token"
        ),
    }
    let body = request.to_string();
    write!(
        stream,
        "POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .map_err(|e| format!("writing to llama-server: {e}"))?;
    stream.flush().map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    // Skip the status line and headers; a non-200 is reported as the error it
    // is rather than parsed as SSE.
    let mut status_ok = false;
    loop {
        line.clear();
        if reader.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            return Err("llama-server closed before answering".into());
        }
        if line.starts_with("HTTP/") {
            status_ok = line.contains(" 200 ");
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    if !status_ok {
        let mut rest = String::new();
        let _ = reader.read_to_string(&mut rest);
        return Err(format!("llama-server refused the request: {}", rest.trim()));
    }

    let mut completion = String::new();
    let mut emitted = 0u64;
    let mut prompt_tokens = 0u64;
    let mut finish_reason = None;

    loop {
        line.clear();
        let read = match reader.read_line(&mut line) {
            Ok(read) => read,
            // A cancel shuts this socket from under us on purpose, so the
            // error it produces is the cancel arriving, not a backend failing.
            Err(e) => {
                if cancelled.load(Ordering::Relaxed) {
                    finish_reason = Some("cancelled".to_string());
                    break;
                }
                return Err(e.to_string());
            }
        };
        if read == 0 {
            if cancelled.load(Ordering::Relaxed) {
                finish_reason = Some("cancelled".to_string());
            }
            break;
        }
        let Some(payload) = line.strip_prefix("data: ") else { continue };
        let payload = payload.trim();
        if payload.is_empty() || payload == "[DONE]" {
            if payload == "[DONE]" {
                break;
            }
            continue;
        }
        let Ok(chunk) = serde_json::from_str::<serde_json::Value>(payload) else { continue };

        // Preemption at a token boundary, which is the moment we are in right
        // now: we hold a decoded token and have not forwarded it.
        while paused.load(Ordering::Relaxed) && !cancelled.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(10));
        }
        if cancelled.load(Ordering::Relaxed) {
            finish_reason = Some("cancelled".to_string());
            break;
        }

        if let Some(usage) = chunk.get("usage") {
            prompt_tokens = usage.get("prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(prompt_tokens);
        }
        let Some(choice) = chunk.get("choices").and_then(|c| c.get(0)) else { continue };
        if let Some(reason) = choice.get("finish_reason").and_then(|r| r.as_str()) {
            finish_reason = Some(reason.to_string());
        }
        let Some(token) = choice
            .get("delta")
            .and_then(|d| d.get("content"))
            .and_then(|c| c.as_str())
        else {
            continue;
        };
        if token.is_empty() {
            continue;
        }
        completion.push_str(token);
        emitted += 1;
        if !has_tools {
            send(writer, &BackendEvent::Token { req_id, tok: token.to_string() });
        }
    }

    // With tools, the grammar has constrained the whole completion to be one
    // JSON call, so it is buffered and emitted as the structured frame §10
    // promises rather than dribbled out as text the client would have to
    // reassemble and parse.
    if has_tools {
        match parse_tool_call(&completion) {
            Some(call) => {
                send(writer, &BackendEvent::ToolCall { req_id, tool_call: call });
                finish_reason = Some("tool_call".into());
            }
            None => {
                for token in completion.split_inclusive(' ') {
                    send(writer, &BackendEvent::Token { req_id, tok: token.to_string() });
                }
            }
        }
    }

    send(writer, &BackendEvent::Done {
        req_id,
        usage: Usage {
            prompt_tokens,
            completion_tokens: emitted,
            attachment_tokens: 0,
        },
        finish_reason: finish_reason.or_else(|| Some("stop".into())),
    });
    Ok(())
}

fn parse_tool_call(text: &str) -> Option<ToolCall> {
    let value: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
    let name = value.get("name")?.as_str()?.to_string();
    let arguments = value.get("arguments").cloned().unwrap_or(serde_json::json!({}));
    Some(ToolCall {
        // The daemon replaces nothing here; the id is this backend's and the
        // client echoes it back on `tool_result`.
        id: format!("call-{:x}", fnv(text)),
        name,
        arguments: arguments.to_string(),
    })
}

fn fnv(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn embed(state: &State, model_id: &str, inputs: &[String]) -> Result<Vec<Vec<f32>>, String> {
    let port = state
        .models
        .lock()
        .unwrap()
        .get(model_id)
        .map(|m| m.port)
        .ok_or_else(|| format!("{model_id} is not loaded"))?;
    let body = serde_json::json!({ "input": inputs }).to_string();
    let response = http(port, "POST", "/v1/embeddings", Some(&body))?;
    let json: serde_json::Value =
        serde_json::from_str(&response).map_err(|e| format!("embedding reply: {e}"))?;
    let data = json.get("data").and_then(|d| d.as_array()).ok_or("no embeddings in the reply")?;
    Ok(data
        .iter()
        .map(|entry| {
            entry
                .get("embedding")
                .and_then(|e| e.as_array())
                .map(|values| values.iter().filter_map(|v| v.as_f64()).map(|v| v as f32).collect())
                .unwrap_or_default()
        })
        .collect())
}

fn tokenize(state: &State, model_id: &str, text: &str) -> Result<Vec<u32>, String> {
    let port = state
        .models
        .lock()
        .unwrap()
        .get(model_id)
        .map(|m| m.port)
        .ok_or_else(|| format!("{model_id} is not loaded"))?;
    let body = serde_json::json!({ "content": text }).to_string();
    let response = http(port, "POST", "/tokenize", Some(&body))?;
    let json: serde_json::Value =
        serde_json::from_str(&response).map_err(|e| format!("tokenize reply: {e}"))?;
    Ok(json
        .get("tokens")
        .and_then(|t| t.as_array())
        .map(|values| values.iter().filter_map(|v| v.as_u64()).map(|v| v as u32).collect())
        .unwrap_or_default())
}

/// How long to wait for llama-server to say *anything*.
///
/// This is a gap timeout, not a request timeout: it bounds the silence before
/// the first token — which is prompt evaluation, and can legitimately run to
/// minutes on a long document — and the silence between tokens after that.
///
/// It used to double as the ceiling on a wedged server, because a cancel could
/// not reach a blocked read. It no longer does: a cancel shuts the socket. What
/// remains is the case where nobody cancels, and ten minutes of a model saying
/// nothing is a broken server rather than a slow one.
const TOKEN_GAP_TIMEOUT: Duration = Duration::from_secs(600);

fn open(port: u16) -> Result<TcpStream, String> {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .map_err(|e| format!("connecting to llama-server on {port}: {e}"))?;
    stream.set_read_timeout(Some(TOKEN_GAP_TIMEOUT)).ok();
    stream.set_nodelay(true).ok();
    Ok(stream)
}

/// A one-shot HTTP/1.1 request with `Connection: close`, which makes the body
/// "everything until EOF" and removes any need to implement chunked transfer
/// decoding in a process that has quite enough parsing to do already.
fn http(port: u16, method: &str, path: &str, body: Option<&str>) -> Result<String, String> {
    let mut stream = open(port)?;
    let body = body.unwrap_or("");
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let mut response = String::new();
    stream.read_to_string(&mut response).map_err(|e| e.to_string())?;
    let (head, payload) = response
        .split_once("\r\n\r\n")
        .ok_or("malformed HTTP reply from llama-server")?;
    if !head.lines().next().unwrap_or_default().contains(" 200 ") {
        return Err(format!("llama-server said: {}", head.lines().next().unwrap_or_default()));
    }
    Ok(payload.to_string())
}

fn send(writer: &Writer, event: &BackendEvent) {
    let mut guard = writer.lock().unwrap();
    if let Err(e) = frame::write_cbor(&mut *guard, event) {
        eprintln!("<3>{NAME}: writing to the daemon failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    /// A llama-server that accepts, sends the response headers, and then says
    /// nothing — which is what a real one does while it evaluates the prompt.
    /// The verification box has no llama.cpp, so this is the only place the
    /// real backend's cancellation is exercised at all.
    fn silent_server() -> (u16, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                let _ = socket.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n",
                );
                let _ = socket.flush();
                // Then nothing at all, until the far end goes away.
                //
                // The request has to be drained, not sampled: closing with
                // unread bytes still in the receive buffer makes the kernel
                // send RST, and the client sees a connection reset that looks
                // like a backend failure rather than the silence being staged.
                let mut sink = [0u8; 4096];
                loop {
                    match std::io::Read::read(&mut socket, &mut sink) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => continue,
                    }
                }
            }
        });
        (port, handle)
    }

    fn state_with(port: u16) -> Arc<State> {
        let child = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("a placeholder child for the Loaded record");
        let mut models = HashMap::new();
        models.insert(
            "m".to_string(),
            Loaded { model_id: "m".into(), child, port, n_ctx: 2048, kv_bytes_per_token: 64 },
        );
        Arc::new(State {
            server_binary: PathBuf::from("/nonexistent"),
            threads: None,
            gpu_layers: None,
            models: Mutex::new(models),
            paused: Mutex::new(HashMap::new()),
            cancelled: Mutex::new(HashMap::new()),
            streams: Mutex::new(HashMap::new()),
        })
    }

    /// The regression. Cancel used to be observed only after an SSE chunk
    /// parsed, so during prompt evaluation — when nothing arrives — it set a
    /// flag nobody read and the generation held its decode slot until the
    /// 600-second read timeout.
    #[test]
    fn a_cancel_during_prompt_evaluation_stops_the_read_now() {
        let (port, server) = silent_server();
        let state = state_with(port);
        let (ours, theirs) = UnixStream::pair().unwrap();
        let writer: Writer = Arc::new(Mutex::new(ours));

        let paused = Arc::new(AtomicBool::new(false));
        let cancelled = Arc::new(AtomicBool::new(false));
        state.paused.lock().unwrap().insert(1, paused.clone());
        state.cancelled.lock().unwrap().insert(1, cancelled.clone());

        let started = Instant::now();
        let worker = {
            let state = state.clone();
            let writer = writer.clone();
            let paused = paused.clone();
            let cancelled = cancelled.clone();
            std::thread::spawn(move || {
                generate(
                    &state,
                    &writer,
                    1,
                    "m",
                    &[Message {
                        role: "user".into(),
                        content: "a long document".into(),
                        attachments: Vec::new(),
                        tool_call_id: None,
                    }],
                    &Params::default(),
                    None,
                    false,
                    &paused,
                    &cancelled,
                )
            })
        };

        // Let it get as far as blocking on the read, then cancel the way the
        // daemon does.
        std::thread::sleep(Duration::from_millis(300));
        let _ = handle(&state, &writer, BackendRequest::Cancel { req_id: 1 });

        let outcome = worker.join().unwrap();
        let elapsed = started.elapsed();
        assert!(outcome.is_ok(), "a cancel is not a backend failure: {outcome:?}");
        assert!(
            elapsed < Duration::from_secs(10),
            "took {elapsed:?}; the read was not interrupted"
        );

        // And it reported the right ending.
        let mut reader = std::io::BufReader::new(theirs);
        let event: BackendEvent = frame::read_typed(&mut reader).unwrap().unwrap();
        match &event {
            BackendEvent::Done { finish_reason, .. } => {
                assert_eq!(finish_reason.as_deref(), Some("cancelled"), "{event:?}");
            }
            other => panic!("expected done, got {other:?}"),
        }

        state.models.lock().unwrap().clear();
        let _ = server.join();
    }

    /// Pause stays flag-based on purpose: it wants to resume, and shutting the
    /// socket would not let it. So a pause must leave the socket registered.
    #[test]
    fn a_pause_does_not_close_the_socket() {
        let (port, server) = silent_server();
        let state = state_with(port);
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let writer: Writer = Arc::new(Mutex::new(ours));
        let paused = Arc::new(AtomicBool::new(false));
        state.paused.lock().unwrap().insert(2, paused.clone());

        let _ = handle(&state, &writer, BackendRequest::Pause { req_id: 2 });
        assert!(paused.load(Ordering::Relaxed), "the flag is how a pause works");
        assert!(
            state.streams.lock().unwrap().is_empty(),
            "and it must not have touched a socket"
        );

        state.models.lock().unwrap().clear();
        drop(server);
    }
}
