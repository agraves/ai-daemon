// SPDX-License-Identifier: Apache-2.0

//! ai-daemon-backend-remote — the provider that is not on this machine.
//!
//! §7 permits a backend that sends bytes to somebody else's computer, and the
//! whole point of permitting it in the architecture is that the architecture
//! can hold one *without lying about it*. Everything this backend produces is
//! marked `local: false`, which the daemon threads into the consent prompt,
//! into every session's info, and into every audit record. The daemon never
//! substitutes a remote model for a local one.
//!
//! ## Why this is a unit and not a child process
//!
//! Every other backend is spawned by the daemon over a socketpair. This one
//! cannot be: the daemon runs with `PrivateNetwork=yes` (§9), so anything it
//! forks has no network at all — that is the point of the setting, and it is
//! not negotiable for the process that holds every prompt on the machine.
//!
//! So this runs as its own unit, with its own user and its own network, and
//! the daemon *connects* to it. Two consequences worth being plain about:
//!
//! * §9's claim narrows honestly. "The process that touches prompts has no
//!   network" is still true of `ai-daemon`. It is not true of the machine once
//!   a remote provider is installed, because this process has both — that is
//!   what a remote provider *is*, and it is why installing one is a deliberate
//!   act and why every session it serves says `local: false`.
//! * The default install does not have one. There is no configuration shipped
//!   that points at any endpoint, and with no config file this backend
//!   declares no models and no capabilities, so the daemon routes around it.
//!
//! ## TLS
//!
//! curl's, deliberately, exactly as `ai-daemon-fetch` argues. Linking a TLS
//! stack and an HTTP client here would add a large dependency surface to do a
//! job the base system already does, and curl is a dependency the package
//! declares and the distro audits. It also gives cancellation somewhere to
//! act: killing the transfer's process group ends a request now rather than at
//! the next token.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ai_daemon_proto::backend::{BackendEvent, BackendInfo, BackendRequest};
use ai_daemon_proto::frame::{self, Message, Params, TokenProb, ToolCall, ToolSchema, Usage};
use ai_daemon_proto::{BACKEND_PROTO, MIN_BACKEND_PROTO};
use serde::Deserialize;

const NAME: &str = "remote";
const DEFAULT_CONFIG: &str = "/etc/ai-daemon/remote.toml";
// Its own runtime directory, not the daemon's. /run/ai-daemon holds the
// session sockets, and letting this uid create files there would mean letting
// the one process with a network unlink a live session's socket.
const DEFAULT_SOCKET: &str = "/run/ai-daemon-remote/remote.sock";

/// Where prompts go, and which names map to which model over there.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    /// An OpenAI-compatible base, e.g. `https://api.example.com/v1`.
    ///
    /// Vendor-neutral on purpose: this is the interoperability protocol the
    /// shim already speaks, it works against a dozen services and a local
    /// vLLM, and a project trying to standardise an interface should not bless
    /// one company's API in its reference backend.
    base_url: String,
    /// The key lives in its own file so it is not in a config the package
    /// installs world-readable. Read once at startup and never logged.
    api_key_file: Option<PathBuf>,
    /// Local model name -> the identifier the endpoint knows it by.
    models: HashMap<String, String>,
    /// What the endpoint can do. Not discovered, because asking an endpoint
    /// what it supports and believing the answer is how a capability becomes
    /// a guess; an administrator writes down what they are paying for.
    capabilities: Vec<String>,
    /// Permit `http://`.
    ///
    /// Off, so a typo in `base_url` cannot put prompts on the wire in clear:
    /// curl is told `--proto =https` and refuses the request rather than
    /// downgrading. It exists because "the endpoint is a vLLM on the machine
    /// next to this one" is a real deployment and demanding a certificate for
    /// it would push people to disable something worse. Saying yes here is
    /// saying yes to plaintext prompts, and the log says so at every startup.
    allow_plaintext: bool,
}

impl Config {
    fn load(path: &Path) -> Config {
        let Ok(text) = std::fs::read_to_string(path) else {
            eprintln!(
                "<5>{NAME}: no {} — declaring no models, so the daemon routes around this backend",
                path.display()
            );
            return Config::default();
        };
        match toml::from_str::<Config>(&text) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("<3>{NAME}: {} is unreadable ({e}); declaring nothing", path.display());
                Config::default()
            }
        }
    }

    fn usable(&self) -> bool {
        !self.base_url.is_empty() && !self.models.is_empty()
    }
}

type Writer = Arc<Mutex<UnixStream>>;

struct State {
    config: Config,
    api_key: Option<String>,
    /// The curl process serving each in-flight request, so a cancel can end
    /// the transfer rather than wait for the next token — the same lesson the
    /// llama.cpp backend learned about acting on the transport.
    transfers: Mutex<HashMap<u64, Child>>,
    cancelled: Mutex<HashMap<u64, Arc<AtomicBool>>>,
}

fn main() {
    let mut config_path = PathBuf::from(DEFAULT_CONFIG);
    let mut socket_path = PathBuf::from(DEFAULT_SOCKET);
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config_path = args.next().map(PathBuf::from).unwrap_or(config_path),
            "--socket" => socket_path = args.next().map(PathBuf::from).unwrap_or(socket_path),
            "--version" | "-V" => {
                println!("ai-daemon-backend-remote {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--help" | "-h" => {
                println!(
                    "ai-daemon-backend-remote {} — remote provider for ai-daemon

usage: ai-daemon-backend-remote [--config {DEFAULT_CONFIG}] [--socket {DEFAULT_SOCKET}]

Listens on a Unix socket and speaks the provider protocol; the daemon
connects to it. A unit rather than a child process because the daemon has
no network to give one. Off unless {DEFAULT_CONFIG} names an endpoint.",
                    env!("CARGO_PKG_VERSION")
                );
                return;
            }
            other => {
                eprintln!("{NAME}: unknown argument {other:?}");
                std::process::exit(1);
            }
        }
    }

    let config = Config::load(&config_path);
    let api_key = config.api_key_file.as_ref().and_then(|path| {
        match std::fs::read_to_string(path) {
            Ok(key) => Some(key.trim().to_string()),
            Err(e) => {
                eprintln!("<3>{NAME}: cannot read the key at {} ({e})", path.display());
                None
            }
        }
    });
    if config.allow_plaintext {
        eprintln!(
            "<4>{NAME}: allow_plaintext is set — prompts may travel to {} unencrypted",
            config.base_url
        );
    }
    if config.usable() {
        eprintln!(
            "<6>{NAME}: {} model(s) via {}{}",
            config.models.len(),
            config.base_url,
            if api_key.is_some() { "" } else { " (no key configured)" }
        );
    }
    let state = Arc::new(State {
        config,
        api_key,
        transfers: Mutex::new(HashMap::new()),
        cancelled: Mutex::new(HashMap::new()),
    });

    let _ = std::fs::remove_file(&socket_path);
    let listener = match UnixListener::bind(&socket_path) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("<3>{NAME}: cannot bind {}: {e}", socket_path.display());
            std::process::exit(1);
        }
    };
    // Group-readable, not world: the daemon's group may connect and nothing
    // else may. A socket anyone could reach is an API key anyone can spend.
    if let Err(e) = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o660)) {
        eprintln!("<3>{NAME}: cannot restrict {}: {e}", socket_path.display());
        std::process::exit(1);
    }
    eprintln!("<6>{NAME}: listening on {}", socket_path.display());

    for connection in listener.incoming() {
        let Ok(socket) = connection else { continue };
        let state = state.clone();
        // One daemon at a time in practice, but a thread each so a restarted
        // daemon does not queue behind a connection nobody is reading.
        std::thread::spawn(move || serve(state, socket));
    }
}

fn serve(state: Arc<State>, socket: UnixStream) {
    let writer: Writer = match socket.try_clone() {
        Ok(clone) => Arc::new(Mutex::new(clone)),
        Err(e) => {
            eprintln!("<3>{NAME}: cannot dup the control socket: {e}");
            return;
        }
    };
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
}

fn handle(
    state: &Arc<State>,
    writer: &Writer,
    request: BackendRequest,
) -> std::ops::ControlFlow<()> {
    match request {
        BackendRequest::Hello { proto } => {
            if !(MIN_BACKEND_PROTO..=BACKEND_PROTO).contains(&proto) {
                send(writer, &BackendEvent::Error {
                    req_id: None,
                    code: "protocol".into(),
                    message: format!("{NAME} speaks protocol {MIN_BACKEND_PROTO}..={BACKEND_PROTO}"),
                });
                return std::ops::ControlFlow::Break(());
            }
            let usable = state.config.usable();
            send(writer, &BackendEvent::Hello {
                proto: BACKEND_PROTO,
                info: BackendInfo {
                    name: NAME.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    // No weight format: nothing is loaded from disk here.
                    formats: if usable { vec!["remote".into()] } else { Vec::new() },
                    quantizations: Vec::new(),
                    // No device claims. The accelerator is somebody else's.
                    devices: Vec::new(),
                    device_memory: None,
                    capabilities: if usable {
                        let mut declared = state.config.capabilities.clone();
                        if declared.is_empty() {
                            declared = vec!["generate".into(), "tools".into()];
                        }
                        declared
                    } else {
                        Vec::new()
                    },
                    // The whole reason this file exists.
                    local: false,
                },
            });
        }
        // Nothing to load: the weights are not here. Answered rather than
        // ignored so the daemon's load path is the same shape for every
        // backend, and so kv_bytes_per_token is stated rather than guessed —
        // it is zero, because this machine holds no KV cache for a remote
        // model and the scheduler must not reserve budget for one.
        BackendRequest::Load { model_id, n_ctx, .. } => {
            if state.config.models.contains_key(&model_id) {
                send(writer, &BackendEvent::Loaded {
                    model_id,
                    kv_bytes_per_token: 0,
                    n_ctx: if n_ctx == 0 { 8192 } else { n_ctx },
                });
            } else {
                send(writer, &BackendEvent::Error {
                    req_id: None,
                    code: "no-such-model".into(),
                    message: format!("{model_id} is not in this backend's model map"),
                });
            }
        }
        BackendRequest::Unload { model_id } => {
            send(writer, &BackendEvent::Unloaded { model_id });
        }
        BackendRequest::Generate {
            req_id, model_id, messages, params, tools, parallel_tools, attachments, ..
        } => {
            if !attachments.is_empty() {
                send(writer, &BackendEvent::Error {
                    req_id: Some(req_id),
                    code: "attachment-unsupported".into(),
                    message: "this backend declares no vision or audio-in".into(),
                });
                return std::ops::ControlFlow::Continue(());
            }
            let cancelled = Arc::new(AtomicBool::new(false));
            state.cancelled.lock().unwrap().insert(req_id, cancelled.clone());
            let state = state.clone();
            let writer = writer.clone();
            let tools = tools.unwrap_or_default();
            std::thread::spawn(move || {
                if let Err(e) = generate(
                    &state, &writer, req_id, &model_id, &messages, &params, &tools,
                    parallel_tools, &cancelled,
                ) {
                    send(&writer, &BackendEvent::Error {
                        req_id: Some(req_id),
                        code: "backend-failed".into(),
                        message: e,
                    });
                }
                state.cancelled.lock().unwrap().remove(&req_id);
                state.transfers.lock().unwrap().remove(&req_id);
            });
        }
        BackendRequest::Cancel { req_id } => {
            if let Some(flag) = state.cancelled.lock().unwrap().get(&req_id) {
                flag.store(true, Ordering::SeqCst);
            }
            // End the transfer rather than wait for the next token to notice
            // the flag: a remote endpoint can be silent for a long time, and
            // billing usually continues while it is.
            if let Some(child) = state.transfers.lock().unwrap().get(&req_id) {
                // SAFETY: killing a process group we created and have not
                // reaped, so the id cannot have been recycled.
                unsafe {
                    libc_kill_group(child.id() as i32);
                }
            }
        }
        // Nothing here holds a slot to pause or a cache to drop: the work is
        // happening somewhere else, and saying so beats pretending to comply.
        BackendRequest::Pause { .. }
        | BackendRequest::Resume { .. }
        | BackendRequest::DropCache { .. } => {}
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
        BackendRequest::Tokenize { req_id, .. } => {
            // No tokeniser here: the endpoint owns it and does not expose one.
            send(writer, &BackendEvent::Error {
                req_id: Some(req_id),
                code: "attachment-unsupported".into(),
                message: format!("{NAME} cannot tokenize; the model is not on this machine"),
            });
        }
        BackendRequest::GenerateMedia { req_id, kind, .. } => {
            send(writer, &BackendEvent::Error {
                req_id: Some(req_id),
                code: "attachment-unsupported".into(),
                message: format!("{NAME} does not generate {}", kind.as_str()),
            });
        }
        // Ends this connection, not this process. The daemon does not own
        // this unit and does not send it — but an older one might, and the
        // right reading of it from here is "I am done with this socket".
        BackendRequest::Shutdown => return std::ops::ControlFlow::Break(()),
    }
    std::ops::ControlFlow::Continue(())
}

/// `kill(-pid, SIGKILL)` without pulling in the libc crate for one call.
///
/// # Safety
/// `pid` must be a process group we created and have not yet reaped.
unsafe fn libc_kill_group(pid: i32) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    const SIGKILL: i32 = 9;
    kill(-pid, SIGKILL);
}

/// Build the request body. Shape is OpenAI's, because that is the one every
/// endpoint worth pointing this at already speaks.
#[allow(clippy::too_many_arguments)]
fn body_for(
    remote_model: &str,
    messages: &[Message],
    params: &Params,
    tools: &[ToolSchema],
    parallel_tools: bool,
    stream: bool,
) -> serde_json::Value {
    let mut body = serde_json::json!({
        "model": remote_model,
        "messages": messages.iter().map(|m| serde_json::json!({
            // The daemon's history is model-agnostic: a tool call is an
            // assistant message whose content is JSON, and a result comes back
            // as role "tool". OpenAI wants role "tool" paired with the
            // tool_call_id of a structured tool_calls block it issued, and the
            // daemon does not keep that pairing because most backends do not
            // need it. Handing the result over as a user turn is a
            // degradation, and a visible one: the model reads the result
            // rather than being handed it. Doing better means the daemon
            // carrying provider-shaped call ids through its history, which is
            // a change to the history format and not to this backend.
            "role": if m.role == "tool" { "user" } else { m.role.as_str() },
            "content": m.content,
        })).collect::<Vec<_>>(),
        "stream": stream,
    });
    if let Some(v) = params.temperature {
        body["temperature"] = serde_json::json!(v);
    }
    if let Some(v) = params.top_p {
        body["top_p"] = serde_json::json!(v);
    }
    if let Some(v) = params.seed {
        body["seed"] = serde_json::json!(v);
    }
    if let Some(v) = params.max_tokens {
        body["max_tokens"] = serde_json::json!(v);
    }
    if let Some(stop) = &params.stop {
        body["stop"] = serde_json::json!(stop);
    }
    if !params.logit_bias.is_empty() {
        // Token ids as decimal strings, which is how OpenAI spells this map.
        let bias: serde_json::Map<String, serde_json::Value> = params
            .logit_bias
            .iter()
            .map(|(token, bias)| (token.to_string(), serde_json::json!(bias)))
            .collect();
        body["logit_bias"] = serde_json::Value::Object(bias);
    }
    if let Some(wanted) = params.logprobs.filter(|n| *n > 0) {
        body["logprobs"] = serde_json::json!(true);
        body["top_logprobs"] = serde_json::json!(wanted);
    }
    // The endpoint's own function calling. There is no grammar to hand it —
    // constrained decoding needs the logits and those are on somebody else's
    // machine — so the schemas travel and the endpoint does the shaping. The
    // daemon knows the guarantee is weaker there and checks every call that
    // comes back against the tools the client actually offered.
    if !tools.is_empty() {
        body["tools"] = serde_json::json!(tools
            .iter()
            .map(|tool| serde_json::json!({
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": if tool.json_schema.is_null() {
                        serde_json::json!({"type": "object", "properties": {}})
                    } else {
                        tool.json_schema.clone()
                    },
                },
            }))
            .collect::<Vec<_>>());
        body["parallel_tool_calls"] = serde_json::json!(parallel_tools);
    }
    body
}

/// Start curl against the endpoint, in its own process group so a cancel can
/// end the whole transfer.
fn start_transfer(
    state: &State,
    path: &str,
    body: &serde_json::Value,
) -> Result<Child, String> {
    let url = format!("{}/{path}", state.config.base_url.trim_end_matches('/'));
    let mut command = Command::new("curl");
    command
        .args([
            "-sS",
            "--fail-with-body",
            "--no-buffer",
            "--proto",
            if state.config.allow_plaintext { "=http,https" } else { "=https" },
            "--proto-redir",
            // Never on a redirect, whatever allow_plaintext says: a downgrade
            // chosen by the far end is not a deployment decision anybody made.
            "=https",
            "--max-redirs",
            "3",
            "--connect-timeout",
            "30",
            "-H",
            "Content-Type: application/json",
        ])
        .arg("-d")
        .arg(body.to_string());
    if let Some(key) = &state.api_key {
        // Via an argument, which is visible in /proc to this uid only — the
        // unit runs as its own user and ProtectProc keeps other users out. A
        // file would be better and curl's --header @file is not portable
        // enough to rely on; worth revisiting if it becomes so.
        command.arg("-H").arg(format!("Authorization: Bearer {key}"));
    }
    command
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        // Captured, not inherited: curl's diagnosis of why a transfer failed
        // is the only thing that distinguishes "the endpoint is down" from
        // "the URL is http and you did not allow that", and it belongs in the
        // error the caller sees rather than in a log nobody is reading.
        .stderr(Stdio::piped());
    // SAFETY: setsid is async-signal-safe and is the only call between fork
    // and exec.
    unsafe {
        command.pre_exec(|| {
            if libc_setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn().map_err(|e| format!("running curl: {e}"))
}

unsafe fn libc_setsid() -> i32 {
    extern "C" {
        fn setsid() -> i32;
    }
    setsid()
}

#[allow(clippy::too_many_arguments)]
fn generate(
    state: &State,
    writer: &Writer,
    req_id: u64,
    model_id: &str,
    messages: &[Message],
    params: &Params,
    tools: &[ToolSchema],
    parallel_tools: bool,
    cancelled: &AtomicBool,
) -> Result<(), String> {
    let remote_model = state
        .config
        .models
        .get(model_id)
        .ok_or_else(|| format!("{model_id} is not in this backend's model map"))?
        .clone();

    let body = body_for(&remote_model, messages, params, tools, parallel_tools, true);
    let mut child = start_transfer(state, "chat/completions", &body)?;
    let stdout = child.stdout.take().ok_or("curl has no stdout")?;
    state.transfers.lock().unwrap().insert(req_id, child);

    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let mut emitted = 0u64;
    let mut prompt_tokens = 0u64;
    let mut finish_reason = None;
    let mut collected: Vec<ToolCall> = Vec::new();

    loop {
        line.clear();
        let read = reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if read == 0 {
            if cancelled.load(Ordering::SeqCst) {
                finish_reason = Some("cancelled".to_string());
            }
            break;
        }
        if cancelled.load(Ordering::SeqCst) {
            finish_reason = Some("cancelled".to_string());
            break;
        }
        let Some(payload) = line.strip_prefix("data: ") else { continue };
        let payload = payload.trim();
        if payload == "[DONE]" {
            break;
        }
        if payload.is_empty() {
            continue;
        }
        let Ok(chunk) = serde_json::from_str::<serde_json::Value>(payload) else { continue };
        if let Some(usage) = chunk.get("usage") {
            prompt_tokens =
                usage.get("prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(prompt_tokens);
        }
        let Some(choice) = chunk.get("choices").and_then(|c| c.get(0)) else { continue };
        if let Some(reason) = choice.get("finish_reason").and_then(|r| r.as_str()) {
            finish_reason = Some(reason.to_string());
        }
        let delta = choice.get("delta");

        if let Some(calls) = delta.and_then(|d| d.get("tool_calls")).and_then(|c| c.as_array()) {
            for call in calls {
                let function = call.get("function");
                let fallback_id = format!("call-{req_id}-{}", collected.len());
                collected.push(ToolCall {
                    id: call
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&fallback_id)
                        .to_string(),
                    name: function
                        .and_then(|f| f.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    arguments: function
                        .and_then(|f| f.get("arguments"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("{}")
                        .to_string(),
                });
            }
            continue;
        }

        let Some(token) = delta.and_then(|d| d.get("content")).and_then(|c| c.as_str()) else {
            continue;
        };
        if token.is_empty() {
            continue;
        }
        emitted += 1;
        let logprobs = choice
            .get("logprobs")
            .and_then(|l| l.get("content"))
            .and_then(|c| c.as_array())
            .and_then(|entries| entries.first())
            .and_then(|entry| entry.get("top_logprobs"))
            .and_then(|top| top.as_array())
            .map(|alternatives| {
                alternatives
                    .iter()
                    .filter_map(|alternative| {
                        Some(TokenProb {
                            tok: alternative.get("token")?.as_str()?.to_string(),
                            logprob: alternative.get("logprob")?.as_f64()? as f32,
                        })
                    })
                    .collect()
            });
        // Text alongside tool calls is the model narrating; the daemon's turn
        // ends on the calls, so streaming it would leave a half-sentence in
        // the transcript that no later frame completes.
        if tools.is_empty() {
            send(writer, &BackendEvent::Token { req_id, tok: token.to_string(), logprobs });
        }
    }

    // How the transfer ended, which is not the same question as what it sent.
    //
    // This used to be missing and the gap was not subtle: curl refusing to
    // speak http to an https-only configuration writes nothing to stdout and
    // exits non-zero, the read loop saw a clean EOF, and the daemon was told
    // the generation finished normally with no tokens. A refusal that arrives
    // as an empty success is worse than no refusal at all — the caller
    // believes the model had nothing to say.
    // Taken out of the map first and waited on with the lock released: a
    // cancel for a different request must not queue behind this one reaping.
    let finished = state.transfers.lock().unwrap().remove(&req_id);
    if let Some(mut child) = finished {
        let mut complaint = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            let _ = stderr.read_to_string(&mut complaint);
        }
        let _ = child.kill();
        let status = child.wait();
        let failed = status.map(|s| !s.success()).unwrap_or(true);
        // A cancelled transfer is killed on purpose, so its non-zero exit is
        // the expected outcome and not something to report as a fault.
        if failed && !cancelled.load(Ordering::SeqCst) {
            let complaint = complaint.trim();
            return Err(if complaint.is_empty() {
                format!("the transfer to {} failed and said nothing", state.config.base_url)
            } else {
                complaint.lines().last().unwrap_or(complaint).to_string()
            });
        }
    }

    if !collected.is_empty() {
        if collected.len() > 1 && parallel_tools {
            send(writer, &BackendEvent::ToolCalls { req_id, tool_calls: collected });
        } else {
            send(writer, &BackendEvent::ToolCall {
                req_id,
                tool_call: collected.remove(0),
            });
        }
        finish_reason = Some("tool_call".into());
    }

    send(writer, &BackendEvent::Done {
        req_id,
        usage: Usage { prompt_tokens, completion_tokens: emitted, ..Usage::default() },
        finish_reason: finish_reason.or_else(|| Some("stop".into())),
    });
    Ok(())
}

fn embed(state: &State, model_id: &str, inputs: &[String]) -> Result<Vec<Vec<f32>>, String> {
    let remote_model = state
        .config
        .models
        .get(model_id)
        .ok_or_else(|| format!("{model_id} is not in this backend's model map"))?;
    let body = serde_json::json!({ "model": remote_model, "input": inputs });
    let mut child = start_transfer(state, "embeddings", &body)?;
    let mut stdout = child.stdout.take().ok_or("curl has no stdout")?;
    let mut response = String::new();
    stdout.read_to_string(&mut response).map_err(|e| e.to_string())?;
    let mut complaint = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut complaint);
    }
    // Same reasoning as the generate path: a transfer that never happened must
    // not read as an endpoint with nothing to say.
    if child.wait().map(|s| !s.success()).unwrap_or(true) {
        let complaint = complaint.trim();
        return Err(if complaint.is_empty() {
            format!("the transfer to {} failed and said nothing", state.config.base_url)
        } else {
            complaint.lines().last().unwrap_or(complaint).to_string()
        });
    }

    let json: serde_json::Value =
        serde_json::from_str(&response).map_err(|e| format!("embedding reply: {e}"))?;
    let data = json.get("data").and_then(|d| d.as_array()).ok_or_else(|| {
        format!("no embeddings in the reply: {}", response.chars().take(200).collect::<String>())
    })?;
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

fn send(writer: &Writer, event: &BackendEvent) {
    let mut guard = writer.lock().unwrap();
    if let Err(e) = frame::write_cbor(&mut *guard, event) {
        eprintln!("<3>{NAME}: writing to the daemon failed: {e}");
    }
    let _ = guard.flush();
}
