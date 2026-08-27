// SPDX-License-Identifier: Apache-2.0

//! ai-daemon-backend-mock — the conformance backend.
//!
//! It loads no weights, opens no devices and produces deterministic text. That
//! makes it useless for answering a question and exactly right for the two
//! things it is for:
//!
//! * **Testing the daemon.** Every property worth checking about ai-daemon —
//!   identity, consent, rate limits, preemption, KV eviction, tool round-trips,
//!   attachment budgets, the audit trail — is a property of the daemon, not of
//!   a language model. Exercising them against a real 8B model would make the
//!   tests slow, non-deterministic and dependent on a GPU nobody's CI has.
//! * **Conformance.** It is the reference implementation of the §7 provider
//!   protocol: a second backend author can diff against it.
//!
//! It is installed, not hidden, and it declares itself in every listing. A
//! backend that pretended to be a model would be a worse lie than a backend
//! that says what it is.

use std::collections::HashMap;
use std::io::{BufReader, Write};
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ai_daemon_proto::backend::{BackendEvent, BackendInfo, BackendRequest, RawAttachment};
use ai_daemon_proto::frame::{
    self, MediaKind, Message, Params, ToolCall, ToolSchema, TokenProb, Usage,
};
use ai_daemon_proto::BACKEND_PROTO;

const NAME: &str = "mock";
const KV_BYTES_PER_TOKEN: u64 = 131_072;

type Writer = Arc<Mutex<UnixStream>>;

struct Model {
    n_ctx: u32,
}

struct State {
    models: Mutex<HashMap<String, Model>>,
    paused: Mutex<HashMap<u64, Arc<AtomicBool>>>,
    cancelled: Mutex<HashMap<u64, Arc<AtomicBool>>>,
    /// Sessions whose cache the daemon has dropped. Tracked only so the
    /// backend can prove it honoured the request; nothing here is real memory.
    dropped: Mutex<Vec<String>>,
}

fn main() {
    let fd: i32 = std::env::var("AI_DAEMON_BACKEND_FD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    // SAFETY: the daemon dup2'd our end of the socketpair onto this fd before
    // exec and closed its own copy; we are the only owner.
    let socket = unsafe { UnixStream::from_raw_fd(fd) };
    let writer: Writer = match socket.try_clone() {
        Ok(clone) => Arc::new(Mutex::new(clone)),
        Err(e) => {
            eprintln!("<3>{NAME}: cannot dup the control socket: {e}");
            std::process::exit(1);
        }
    };
    let state = Arc::new(State {
        models: Mutex::new(HashMap::new()),
        paused: Mutex::new(HashMap::new()),
        cancelled: Mutex::new(HashMap::new()),
        dropped: Mutex::new(Vec::new()),
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
}

fn handle(state: &Arc<State>, writer: &Writer, request: BackendRequest) -> std::ops::ControlFlow<()> {
    match request {
        BackendRequest::Hello { proto } => {
            if proto != BACKEND_PROTO {
                send(
                    writer,
                    &BackendEvent::Error {
                        req_id: None,
                        code: "protocol".into(),
                        message: format!("{NAME} speaks protocol {BACKEND_PROTO}"),
                    },
                );
                return std::ops::ControlFlow::Break(());
            }
            send(
                writer,
                &BackendEvent::Hello {
                    proto: BACKEND_PROTO,
                    info: BackendInfo {
                        name: NAME.into(),
                        version: env!("CARGO_PKG_VERSION").into(),
                        // `mock` is its own format so a real GGUF cannot be
                        // routed here by accident; `gguf` is offered too, but
                        // only ever chosen when a manifest names this backend.
                        formats: vec!["mock".into(), "gguf".into()],
                        quantizations: vec!["none".into()],
                        devices: Vec::new(),
                        device_memory: None,
                        capabilities: vec![
                            "generate".into(),
                            "embed".into(),
                            "logprobs".into(),
                            "grammar".into(),
                            "tools".into(),
                            "parallel-tools".into(),
                            "vision".into(),
                            "audio-in".into(),
                            "image-out".into(),
                            "audio-out".into(),
                        ],
                        local: true,
                    },
                },
            );
        }
        BackendRequest::Load { model_id, path, n_ctx, .. } => {
            // The daemon has already verified the digest; a real backend would
            // mmap `path` here. This one only checks it exists, so a broken
            // registry still fails at load time rather than at first token.
            if !path.is_empty() && !std::path::Path::new(&path).exists() {
                send(
                    writer,
                    &BackendEvent::Error {
                        req_id: None,
                        code: "no-such-model".into(),
                        message: format!("{path} does not exist"),
                    },
                );
                return std::ops::ControlFlow::Continue(());
            }
            let n_ctx = if n_ctx == 0 { 4096 } else { n_ctx };
            state.models.lock().unwrap().insert(model_id.clone(), Model { n_ctx });
            send(
                writer,
                &BackendEvent::Loaded { model_id, kv_bytes_per_token: KV_BYTES_PER_TOKEN, n_ctx },
            );
        }
        BackendRequest::Unload { model_id } => {
            state.models.lock().unwrap().remove(&model_id);
            send(writer, &BackendEvent::Unloaded { model_id });
        }
        BackendRequest::Generate {
            req_id,
            model_id,
            session_id,
            messages,
            params,
            grammar,
            tools,
            parallel_tools,
            attachments,
        } => {
            let paused = Arc::new(AtomicBool::new(false));
            let cancelled = Arc::new(AtomicBool::new(false));
            state.paused.lock().unwrap().insert(req_id, paused.clone());
            state.cancelled.lock().unwrap().insert(req_id, cancelled.clone());
            let writer = writer.clone();
            let state = state.clone();
            std::thread::spawn(move || {
                generate(
                    &state, &writer, req_id, &model_id, &session_id, &messages, &params,
                    grammar.as_deref(), tools.as_deref(), parallel_tools, &attachments,
                    &paused, &cancelled,
                );
                state.paused.lock().unwrap().remove(&req_id);
                state.cancelled.lock().unwrap().remove(&req_id);
            });
        }
        BackendRequest::Embed { req_id, inputs, .. } => {
            let vectors: Vec<Vec<f32>> = inputs.iter().map(|text| embed(text)).collect();
            let tokens: u64 = inputs.iter().map(|t| (t.len() as u64).div_ceil(4)).sum();
            send(writer, &BackendEvent::Vectors { req_id, vectors });
            send(
                writer,
                &BackendEvent::Done {
                    req_id,
                    usage: Usage { prompt_tokens: tokens, completion_tokens: 0, ..Usage::default() },
                    finish_reason: Some("stop".into()),
                },
            );
        }
        BackendRequest::Tokenize { req_id, text, .. } => {
            let tokens: Vec<u32> = tokenize(&text);
            let count = tokens.len() as u64;
            send(writer, &BackendEvent::Tokens { req_id, tokens });
            send(
                writer,
                &BackendEvent::Done {
                    req_id,
                    usage: Usage { prompt_tokens: count, completion_tokens: 0, ..Usage::default() },
                    finish_reason: Some("stop".into()),
                },
            );
        }
        BackendRequest::Cancel { req_id } => {
            if let Some(flag) = state.cancelled.lock().unwrap().get(&req_id) {
                flag.store(true, Ordering::Relaxed);
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
        BackendRequest::DropCache { session_id } => {
            state.dropped.lock().unwrap().push(session_id);
        }
        BackendRequest::GenerateMedia { req_id, model_id, kind, prompt, params, count, .. } => {
            let writer = writer.clone();
            let state = state.clone();
            std::thread::spawn(move || {
                generate_media(&state, &writer, req_id, &model_id, kind, &prompt, &params, count);
            });
        }
        BackendRequest::Shutdown => return std::ops::ControlFlow::Break(()),
    }
    std::ops::ControlFlow::Continue(())
}

#[allow(clippy::too_many_arguments)]
fn generate(
    state: &State,
    writer: &Writer,
    req_id: u64,
    model_id: &str,
    session_id: &str,
    messages: &[Message],
    params: &Params,
    grammar: Option<&str>,
    tools: Option<&[ToolSchema]>,
    parallel_tools: bool,
    attachments: &[RawAttachment],
    paused: &AtomicBool,
    cancelled: &AtomicBool,
) {
    let n_ctx = state
        .models
        .lock()
        .unwrap()
        .get(model_id)
        .map(|m| m.n_ctx)
        .unwrap_or(0);
    if n_ctx == 0 {
        send(
            writer,
            &BackendEvent::Error {
                req_id: Some(req_id),
                code: "no-such-model".into(),
                message: format!("{model_id} is not loaded"),
            },
        );
        return;
    }

    let prompt_tokens: u64 = messages.iter().map(|m| (m.content.len() as u64).div_ceil(4) + 4).sum();

    // A tool round-trip is the interesting path to exercise, so: if tools are
    // offered and the conversation has not answered one yet, call the first.
    let answered_a_tool = messages.iter().any(|m| m.role == "tool");
    if let Some(tools) = tools {
        if !answered_a_tool && !tools.is_empty() {
            // Every offered tool at once. A fixture that always calls exactly
            // one could not tell a daemon that handles parallel calls from one
            // that quietly drops all but the first, which is the property
            // being added.
            let calls: Vec<ToolCall> = tools
                .iter()
                .enumerate()
                .map(|(index, tool)| ToolCall {
                    id: format!("call-{req_id}-{index}"),
                    name: tool.name.clone(),
                    arguments: sample_arguments(&tool.json_schema),
                })
                .collect();
            if calls.len() == 1 || !parallel_tools {
                // One only: either that is all there was, or the daemon said
                // the client on the far end cannot answer more.
                send(writer, &BackendEvent::ToolCall { req_id, tool_call: calls[0].clone() });
            } else {
                send(writer, &BackendEvent::ToolCalls { req_id, tool_calls: calls });
            }
            send(
                writer,
                &BackendEvent::Done {
                    req_id,
                    usage: Usage { prompt_tokens, completion_tokens: 8, ..Usage::default() },
                    finish_reason: Some("tool_call".into()),
                },
            );
            return;
        }
    }

    // Exactly `max_tokens` tokens, every time: a description of what the
    // backend was handed, then filler. Emitting a fixed count is what makes
    // this useful as a fixture — a test that needs a generation to still be
    // running three seconds from now can just ask for one, instead of racing
    // whatever length a real model happened to choose.
    let reply = compose(session_id, messages, grammar, attachments, answered_a_tool);
    let limit = params.max_tokens.unwrap_or(64).max(1) as usize;
    let described: Vec<String> = reply.split_inclusive(' ').map(str::to_string).collect();
    let tokens: Vec<String> = described
        .into_iter()
        .chain((0..).map(|n: usize| format!("·{n} ")))
        .take(limit)
        .collect();
    let mut emitted = 0usize;
    for token in tokens {
        // Preemption is honoured at a token boundary, which is exactly the
        // contract §8 asks for: not mid-decode, and not later than the next
        // token.
        while paused.load(Ordering::Relaxed) && !cancelled.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(10));
        }
        if cancelled.load(Ordering::Relaxed) {
            send(
                writer,
                &BackendEvent::Done {
                    req_id,
                    usage: Usage {
                        prompt_tokens,
                        completion_tokens: emitted as u64,
                        ..Usage::default()
                    },
                    finish_reason: Some("cancelled".into()),
                },
            );
            return;
        }
        // Deterministic alternatives: the emitted token at a high probability
        // and a fixed ladder below it. Useless as a distribution, checkable as
        // a shape, which is what a fixture is for.
        let logprobs = params.logprobs.filter(|n| *n > 0).map(|wanted| {
            (0..wanted.min(8))
                .map(|rank| TokenProb {
                    tok: if rank == 0 { token.clone() } else { format!("alt{rank}") },
                    logprob: -(rank as f32) - 0.1,
                })
                .collect()
        });
        send(writer, &BackendEvent::Token { req_id, tok: token.clone(), logprobs });
        emitted += 1;
        // Slow enough that streaming is observably streaming, fast enough that
        // a test suite does not notice.
        std::thread::sleep(Duration::from_millis(4));
    }

    send(
        writer,
        &BackendEvent::Done {
            req_id,
            usage: Usage {
                prompt_tokens,
                completion_tokens: emitted as u64,
                attachment_tokens: attachments.len() as u64,
                ..Usage::default()
            },
            finish_reason: Some(if emitted >= limit { "length" } else { "stop" }.into()),
        },
    );
}

/// Produce media without a model, deterministically.
///
/// A gradient and a sine wave. Nothing here is diffusion or speech; what is
/// being exercised is the daemon's side — the capability gate, the policy
/// capability, the framing of bytes back to a client, and the accounting —
/// none of which is a property of the model that would eventually do it.
#[allow(clippy::too_many_arguments)]
fn generate_media(
    state: &State,
    writer: &Writer,
    req_id: u64,
    model_id: &str,
    kind: MediaKind,
    prompt: &str,
    params: &Params,
    count: u32,
) {
    if !state.models.lock().unwrap().contains_key(model_id) {
        send(
            writer,
            &BackendEvent::Error {
                req_id: Some(req_id),
                code: "no-such-model".into(),
                message: format!("{model_id} is not loaded"),
            },
        );
        return;
    }
    // The prompt seeds it, so the same prompt gives the same bytes and a test
    // can assert on them.
    let seed = params.seed.unwrap_or_else(|| fnv(prompt));
    let mut produced = 0u64;
    for index in 0..count.max(1) {
        let salt = seed.wrapping_add(index as u64);
        let event = match kind {
            MediaKind::Image => {
                let (w, h) = (32u32, 24u32);
                let mut data = Vec::with_capacity((w * h * 4) as usize);
                for y in 0..h {
                    for x in 0..w {
                        data.push((x * 8 + (salt & 0xff) as u32) as u8);
                        data.push((y * 10) as u8);
                        data.push(((x + y) * 4) as u8);
                        data.push(0xff);
                    }
                }
                produced += data.len() as u64;
                BackendEvent::Media {
                    req_id,
                    kind,
                    w: Some(w),
                    h: Some(h),
                    fmt: Some("rgba8".into()),
                    rate: None,
                    data,
                }
            }
            MediaKind::Audio => {
                let rate = 16_000u32;
                let samples = rate / 4; // a quarter second
                let tone = 220.0 + (salt % 440) as f32;
                let mut data = Vec::with_capacity(samples as usize * 4);
                for n in 0..samples {
                    let t = n as f32 / rate as f32;
                    let value = (t * tone * std::f32::consts::TAU).sin() * 0.25;
                    data.extend_from_slice(&value.to_le_bytes());
                }
                produced += data.len() as u64;
                BackendEvent::Media {
                    req_id,
                    kind,
                    w: None,
                    h: None,
                    fmt: None,
                    rate: Some(rate),
                    data,
                }
            }
        };
        send(writer, &event);
    }
    send(
        writer,
        &BackendEvent::Done {
            req_id,
            usage: Usage { media_bytes: produced, ..Usage::default() },
            finish_reason: Some("stop".into()),
        },
    );
}

/// The deterministic "completion": a description of what the backend was
/// actually given. Useless as prose, ideal as a test oracle — every property
/// the daemon is supposed to have preserved is visible in the text.
fn compose(
    session_id: &str,
    messages: &[Message],
    grammar: Option<&str>,
    attachments: &[RawAttachment],
    after_tool: bool,
) -> String {
    let last_user = messages
        .iter()
        .rev()
        .find(|m| m.role == "user")
        .map(|m| m.content.as_str())
        .unwrap_or("");
    let mut parts = vec![format!(
        "[mock:{session_id}] {} message(s); last user prompt was {} character(s).",
        messages.len(),
        last_user.chars().count()
    )];
    if after_tool {
        let result = messages
            .iter()
            .rev()
            .find(|m| m.role == "tool")
            .map(|m| m.content.clone())
            .unwrap_or_default();
        parts.push(format!("Tool result seen: {result}."));
    }
    for attachment in attachments {
        match attachment.kind.as_str() {
            "image" => parts.push(format!(
                "Image {} is {}x{} {} ({} bytes).",
                attachment.id,
                attachment.w.unwrap_or(0),
                attachment.h.unwrap_or(0),
                attachment.fmt.as_deref().unwrap_or("rgba8"),
                attachment.data.len()
            )),
            "audio" => parts.push(format!(
                "Audio {} is {} sample(s) at {} Hz.",
                attachment.id,
                attachment.data.len() / 4,
                attachment.rate.unwrap_or(0)
            )),
            other => parts.push(format!("Attachment {} of unknown kind {other}.", attachment.id)),
        }
    }
    if grammar.is_some() {
        parts.push("A decoding grammar was supplied.".into());
    }
    parts.join(" ")
}

/// A minimal instance of a JSON Schema: enough to be a well-formed tool call
/// the client can execute, deterministic so a test can assert on it.
fn sample_arguments(schema: &serde_json::Value) -> String {
    fn build(schema: &serde_json::Value) -> serde_json::Value {
        let Some(object) = schema.as_object() else {
            return serde_json::json!({});
        };
        if let Some(choices) = object.get("enum").and_then(|e| e.as_array()) {
            if let Some(first) = choices.first() {
                return first.clone();
            }
        }
        match object.get("type").and_then(|t| t.as_str()) {
            Some("string") => serde_json::Value::String("mock".into()),
            Some("integer") => serde_json::json!(1),
            Some("number") => serde_json::json!(1.0),
            Some("boolean") => serde_json::json!(true),
            Some("array") => match object.get("items") {
                Some(items) => serde_json::Value::Array(vec![build(items)]),
                None => serde_json::json!([]),
            },
            Some("object") | None => {
                let mut out = serde_json::Map::new();
                if let Some(properties) = object.get("properties").and_then(|p| p.as_object()) {
                    let required: Vec<&str> = object
                        .get("required")
                        .and_then(|r| r.as_array())
                        .map(|r| r.iter().filter_map(|v| v.as_str()).collect())
                        .unwrap_or_default();
                    for (key, subschema) in properties {
                        if required.is_empty() || required.contains(&key.as_str()) {
                            out.insert(key.clone(), build(subschema));
                        }
                    }
                }
                serde_json::Value::Object(out)
            }
            Some(_) => serde_json::Value::Null,
        }
    }
    build(schema).to_string()
}

/// FNV-1a over some text, as a single number. Used to seed generated media
/// from its prompt, so the same prompt gives the same bytes.
fn fnv(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// FNV-1a over the text, spread into a unit vector. Deterministic, and similar
/// strings do not produce similar vectors — which is honest, because this
/// backend has no semantics to offer.
fn embed(text: &str) -> Vec<f32> {
    const DIM: usize = 64;
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut vector = vec![0f32; DIM];
    for (index, byte) in text.bytes().enumerate() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        vector[index % DIM] += ((hash >> 32) as u32 as f32 / u32::MAX as f32) - 0.5;
    }
    let norm = vector.iter().map(|v| v * v).sum::<f32>().sqrt();
    if norm > 0.0 {
        for value in &mut vector {
            *value /= norm;
        }
    }
    vector
}

fn tokenize(text: &str) -> Vec<u32> {
    text.split_whitespace()
        .map(|word| {
            let mut hash: u32 = 2_166_136_261;
            for byte in word.bytes() {
                hash ^= byte as u32;
                hash = hash.wrapping_mul(16_777_619);
            }
            hash % 32_000
        })
        .collect()
}

fn send(writer: &Writer, event: &BackendEvent) {
    let mut guard = writer.lock().unwrap();
    if let Err(e) = frame::write_cbor(&mut *guard, event) {
        eprintln!("<3>{NAME}: writing to the daemon failed: {e}");
    }
    let _ = guard.flush();
}
