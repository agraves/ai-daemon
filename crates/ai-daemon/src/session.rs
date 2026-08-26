//! The session data plane (§8, §10, §11): one thread, one socket, one client.
//!
//! Everything expensive or blocking happens here rather than on the bus:
//! waiting for a decode slot, waiting for polkit to ask the user, waiting for
//! a backend to stream a token. The D-Bus layer hands this thread a socket and
//! forgets about it, which is why a model that takes thirty seconds to load
//! does not make the daemon look hung to every other caller.

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use ai_daemon_proto::backend::{BackendEvent, BackendRequest, RawAttachment};
use ai_daemon_proto::frame::{
    self, AttachKind, AttachMeta, Event, Frame, Message, Params, Request, SessionInfo, ToolSchema,
    Usage,
};
use ai_daemon_proto::DATA_PROTO;

use crate::backend::Backend;
use crate::decode;
use crate::grammar;
use crate::policy::{Limits, CAP_EMBED, CAP_GENERATE, CAP_GENERATE_TOOLS};
use crate::state::{Daemon, Session};
use crate::{debug, info, warn};

pub type Sink = Arc<Mutex<UnixStream>>;

/// Take over `socket` for the life of `session`.
pub fn spawn(daemon: Arc<Daemon>, session: Arc<Session>, socket: UnixStream, limits: Limits) {
    let name = format!("session-{}", session.id);
    let result = std::thread::Builder::new().name(name).spawn(move || {
        let sink: Sink = match socket.try_clone() {
            Ok(clone) => Arc::new(Mutex::new(clone)),
            Err(e) => {
                warn!("session {}: cannot dup its socket ({e}); closing", session.id);
                return;
            }
        };
        *session.sink.lock().unwrap() = Some(sink.clone());
        let mut worker = Worker {
            daemon: daemon.clone(),
            session: session.clone(),
            limits,
            sink,
            history: Vec::new(),
            tools: None,
            params: Params::default(),
            grammar: None,
            pending_tool_call: None,
        };
        worker.run(socket);
        worker.teardown();
    });
    if let Err(e) = result {
        warn!("could not start a thread for session: {e}");
    }
}

struct Worker {
    daemon: Arc<Daemon>,
    session: Arc<Session>,
    limits: Limits,
    sink: Sink,
    /// The conversation as the daemon has it. Kept because a tool round-trip
    /// (§10) resumes *this* session with its KV cache warm, which is the whole
    /// latency argument over a stateless HTTP loop.
    history: Vec<Message>,
    tools: Option<Vec<ToolSchema>>,
    params: Params,
    grammar: Option<String>,
    pending_tool_call: Option<String>,
}

impl Worker {
    fn run(&mut self, socket: UnixStream) {
        let mut reader = BufReader::new(socket);
        loop {
            if self.session.closed.load(Ordering::Relaxed) {
                return;
            }
            let request: Request = match frame::read_frame(&mut reader) {
                Ok(None) => {
                    debug!("session {}: client closed the socket", self.session.id);
                    return;
                }
                Ok(Some(Frame::Blob(_))) => {
                    self.send(&Event::error("protocol", "a BLOB arrived with no attachment to own it"));
                    return;
                }
                Ok(Some(Frame::Cbor(value))) => match value.deserialized() {
                    Ok(request) => request,
                    Err(e) => {
                        self.send(&Event::error("protocol", format!("unrecognised request: {e}")));
                        continue;
                    }
                },
                Err(e) => {
                    debug!("session {}: {e}", self.session.id);
                    return;
                }
            };
            self.daemon.touch();
            if let Err(fatal) = self.dispatch(request, &mut reader) {
                if fatal {
                    return;
                }
            }
        }
    }

    /// `Err(true)` means the socket is no longer usable and the thread should
    /// stop; `Err(false)` means the request failed but the session lives.
    fn dispatch(&mut self, request: Request, reader: &mut BufReader<UnixStream>) -> Result<(), bool> {
        match request {
            Request::Hello { proto } => {
                if proto != 0 && proto != DATA_PROTO {
                    self.send(&Event::error(
                        "protocol",
                        format!("this daemon speaks data protocol {DATA_PROTO}"),
                    ));
                    return Err(true);
                }
                let info = SessionInfo {
                    session: self.session.id.clone(),
                    model: self.session.model.clone(),
                    identity: self.session.identity.key(),
                    local: self.session.local,
                    capabilities: self.session_capabilities(),
                    max_context: self.session.max_context,
                };
                self.send(&Event::Hello { ok: true, proto: DATA_PROTO, session: info });
                Ok(())
            }
            Request::Attach { id, kind, meta, len } => self.attach(id, kind, meta, len, reader),
            Request::Generate { messages, stream, params, grammar, tools } => {
                self.history = messages;
                self.params = params.unwrap_or_default();
                self.tools = tools;
                self.grammar = grammar;
                self.pending_tool_call = None;
                self.turn(stream);
                Ok(())
            }
            Request::ToolResult { id, content } => {
                match self.pending_tool_call.take() {
                    Some(expected) if expected == id => {
                        self.history.push(Message {
                            role: "tool".into(),
                            content,
                            attachments: Vec::new(),
                            tool_call_id: Some(id),
                        });
                        self.turn(true);
                    }
                    Some(expected) => {
                        self.pending_tool_call = Some(expected.clone());
                        self.send(&Event::error(
                            "protocol",
                            format!("this session is waiting on tool call {expected}, not {id}"),
                        ));
                    }
                    None => {
                        self.send(&Event::error(
                            "protocol",
                            "no tool call is outstanding on this session",
                        ));
                    }
                }
                Ok(())
            }
            Request::Embed { inputs } => {
                self.embed(inputs);
                Ok(())
            }
            Request::Tokenize { text } => {
                self.tokenize(text);
                Ok(())
            }
            Request::Cancel => {
                self.session.cancelled.store(true, Ordering::Relaxed);
                if let Some(req_id) = *self.session.current_req.lock().unwrap() {
                    if let Ok(backend) = self.daemon.backends.get(&self.session.backend) {
                        backend.cancel(req_id);
                    }
                }
                Ok(())
            }
        }
    }

    // -----------------------------------------------------------------------
    // Attachments (§11)
    // -----------------------------------------------------------------------

    fn attach(
        &mut self,
        id: String,
        kind: AttachKind,
        meta: AttachMeta,
        len: u64,
        reader: &mut BufReader<UnixStream>,
    ) -> Result<(), bool> {
        let budget = &self.daemon.config.attachments;

        if len > budget.max_bytes {
            self.send(&Event::error(
                "policy-denied",
                format!("attachment of {len} bytes exceeds the {} byte limit", budget.max_bytes),
            ));
            return Err(true);
        }
        if self.session.attachments.lock().unwrap().len() as u32 >= budget.max_per_session {
            self.send(&Event::error(
                "policy-denied",
                format!("this session may hold {} attachments", budget.max_per_session),
            ));
            return Err(true);
        }

        // Read the declared payload before deciding anything else about it:
        // leaving unread bytes in the stream would desynchronise every frame
        // that follows, so a rejected attachment is still a drained one.
        let mut payload = Vec::with_capacity(len.min(1 << 20) as usize);
        while (payload.len() as u64) < len {
            match frame::read_frame(reader) {
                Ok(Some(Frame::Blob(mut chunk))) => payload.append(&mut chunk),
                Ok(Some(Frame::Cbor(_))) => {
                    self.send(&Event::error("protocol", "attachment interrupted by a request frame"));
                    return Err(true);
                }
                Ok(None) => return Err(true),
                Err(e) => {
                    debug!("session {}: reading attachment: {e}", self.session.id);
                    return Err(true);
                }
            }
            if payload.len() as u64 > len {
                self.send(&Event::error("protocol", "attachment BLOBs exceeded the declared length"));
                return Err(true);
            }
        }

        let raw = if let Some(hint) = meta.encoded.clone() {
            if !budget.allow_encoded {
                self.send(&Event::error(
                    "attachment-unsupported",
                    "this install accepts raw pixels and PCM only; decode client-side",
                ));
                return Err(false);
            }
            match decode::decode(&self.daemon.config.daemon.libexec_dir, kind, &hint, &payload) {
                Ok(decoded) => RawAttachment {
                    id: id.clone(),
                    kind: kind_str(kind).into(),
                    w: decoded.w,
                    h: decoded.h,
                    fmt: decoded.fmt,
                    rate: decoded.rate,
                    data: decoded.data,
                },
                Err(e) => {
                    // One decoder crash costs one attachment. That is the
                    // reason the decoder is a separate, confined process.
                    warn!("session {}: decoding {hint} attachment failed: {e}", self.session.id);
                    self.send(&Event::error("attachment-unsupported", e));
                    return Err(false);
                }
            }
        } else {
            RawAttachment {
                id: id.clone(),
                kind: kind_str(kind).into(),
                w: meta.w,
                h: meta.h,
                fmt: meta.fmt.clone(),
                rate: meta.rate,
                data: payload,
            }
        };

        if let Err(e) = self.check_attachment_budget(kind, &raw) {
            self.send(&Event::error("policy-denied", e));
            return Err(false);
        }

        self.session
            .attachment_bytes
            .fetch_add(raw.data.len() as u64, Ordering::Relaxed);
        self.session.attachments.lock().unwrap().insert(id, raw);
        Ok(())
    }

    fn check_attachment_budget(&self, kind: AttachKind, raw: &RawAttachment) -> Result<(), String> {
        let budget = &self.daemon.config.attachments;
        match kind {
            AttachKind::Image => {
                let (w, h) = (raw.w.unwrap_or(0) as u64, raw.h.unwrap_or(0) as u64);
                if w == 0 || h == 0 {
                    return Err("an image attachment needs w and h".into());
                }
                let pixels = w.saturating_mul(h);
                if pixels > budget.max_pixels {
                    return Err(format!(
                        "{pixels} pixels exceeds the {} pixel limit",
                        budget.max_pixels
                    ));
                }
                let bytes_per_pixel = match raw.fmt.as_deref() {
                    Some("rgb8") => 3,
                    Some("rgba8") | None => 4,
                    Some(other) => return Err(format!("unsupported pixel format {other:?}")),
                };
                let expected = pixels.saturating_mul(bytes_per_pixel);
                if raw.data.len() as u64 != expected {
                    return Err(format!(
                        "{}x{} {} needs {expected} bytes, got {}",
                        w,
                        h,
                        raw.fmt.as_deref().unwrap_or("rgba8"),
                        raw.data.len()
                    ));
                }
                Ok(())
            }
            AttachKind::Audio => {
                if raw.rate.unwrap_or(0) == 0 {
                    return Err("an audio attachment needs a sample rate".into());
                }
                let samples = raw.data.len() as u64 / 4;
                if samples > budget.max_samples {
                    return Err(format!(
                        "{samples} samples exceeds the {} sample limit",
                        budget.max_samples
                    ));
                }
                if raw.data.len() % 4 != 0 {
                    return Err("audio must be mono float32 PCM".into());
                }
                Ok(())
            }
        }
    }

    // -----------------------------------------------------------------------
    // Generation
    // -----------------------------------------------------------------------

    fn session_capabilities(&self) -> Vec<String> {
        let mut caps = Vec::new();
        if let Ok(backend) = self.daemon.backends.get(&self.session.backend) {
            caps.extend(backend.info.capabilities.iter().cloned());
        }
        caps
    }

    fn turn(&mut self, stream: bool) {
        let capability = if self.tools.is_some() { CAP_GENERATE_TOOLS } else { CAP_GENERATE };
        if let Err(reason) = self.daemon.policy.check(&self.session.identity, capability) {
            self.daemon.audit.denied(&self.session.identity, capability, &reason);
            self.send(&Event::error("policy-denied", reason));
            return;
        }

        let backend = match self.daemon.backends.get(&self.session.backend) {
            Ok(backend) => backend,
            Err(e) => {
                self.send(&Event::error("backend-failed", e));
                return;
            }
        };

        // A grammar the client supplied and a grammar we compile from tools are
        // the same field on the wire, so one has to win. Tools win: the client
        // asked for well-formed calls, and a hand-written grammar that also
        // permits free text would silently defeat that.
        let mut effective_grammar = self.grammar.clone();
        if let Some(tools) = &self.tools {
            if !backend.can("grammar") || !backend.can("tools") {
                self.send(&Event::error(
                    "attachment-unsupported",
                    format!(
                        "backend {} does not offer constrained tool calling",
                        backend.name
                    ),
                ));
                return;
            }
            match grammar::compile(tools) {
                Ok(compiled) => {
                    debug!(
                        "session {}: constrained decoding to {} tool(s) [{}]{}",
                        self.session.id,
                        compiled.names.len(),
                        compiled.names.join(", "),
                        if compiled.widened { " (schema partly widened)" } else { "" }
                    );
                    effective_grammar = Some(compiled.gbnf);
                }
                Err(e) => {
                    self.send(&Event::error("protocol", format!("tool schema: {e}")));
                    return;
                }
            }
        }

        // Loading is slow, blocking, and belongs here rather than in
        // CreateSession: a client that never generates should never have paid
        // for weights, and the bus thread must never wait on a disk.
        let loaded = match backend.load(
            &self.session.model,
            &self.session.blob,
            &self.session.digest,
            self.session.max_context,
        ) {
            Ok(loaded) => loaded,
            Err(e) => {
                self.send(&Event::error("backend-failed", format!("loading {}: {e}", self.session.model)));
                return;
            }
        };
        // The backend may have given us less context than we asked for — it
        // knows what fits and we do not. Believe it.
        let effective_ctx = self.session.max_context.min(loaded.n_ctx.max(1));

        let prompt_estimate = self.estimate_prompt_tokens();
        let max_tokens = self.params.max_tokens.unwrap_or(512) as u64;
        if prompt_estimate + max_tokens > effective_ctx as u64 {
            self.send(&Event::error(
                "policy-denied",
                format!(
                    "roughly {prompt_estimate} prompt tokens plus {max_tokens} of output exceeds this session's {effective_ctx} token context"
                ),
            ));
            return;
        }

        let reserve = prompt_estimate + max_tokens;
        if !self
            .daemon
            .policy
            .charge_tokens(&self.session.identity, &self.limits, reserve)
        {
            self.send(&Event::error(
                "rate-limited",
                format!(
                    "{} is over its {} tokens/minute allowance",
                    self.session.identity.key(),
                    self.limits.tokens_per_minute
                ),
            ));
            return;
        }

        let kv_bytes = reserve.saturating_mul(loaded.kv_bytes_per_token);
        match self.daemon.scheduler.reserve_kv(
            &self.session.id,
            &self.session.backend,
            self.session.class,
            kv_bytes,
        ) {
            Ok(evicted) => self.announce_evictions(&evicted),
            Err(e) => {
                self.send(&Event::error("rate-limited", e));
                return;
            }
        }

        let attachments: Vec<RawAttachment> = {
            let held = self.session.attachments.lock().unwrap();
            self.history
                .iter()
                .flat_map(|m| m.attachments.iter())
                .filter_map(|id| held.get(id).cloned())
                .collect()
        };
        if !attachments.is_empty() {
            let needed = if attachments.iter().any(|a| a.kind == "audio") { "audio-in" } else { "vision" };
            if !backend.can(needed) {
                self.send(&Event::error(
                    "attachment-unsupported",
                    format!("backend {} cannot {needed}", backend.name),
                ));
                return;
            }
        }
        let attachment_tokens: u64 = attachments.iter().map(estimate_attachment_tokens).sum();

        self.session.cancelled.store(false, Ordering::Relaxed);
        let slot = self.daemon.scheduler.admit(&self.session.id, self.session.class);

        let messages = self.history.clone();
        let params = self.params.clone();
        let tools = self.tools.clone();
        let session_id = self.session.id.clone();
        let model_id = self.session.model.clone();
        let begun = backend.begin(move |req_id| BackendRequest::Generate {
            req_id,
            model_id,
            session_id,
            messages,
            params,
            grammar: effective_grammar,
            tools,
            attachments,
        });
        let (req_id, events) = match begun {
            Ok(pair) => pair,
            Err(e) => {
                self.send(&Event::error("backend-failed", e));
                return;
            }
        };
        slot.attach(&backend.name, req_id);
        *self.session.current_req.lock().unwrap() = Some(req_id);

        let mut usage = Usage { attachment_tokens, ..Usage::default() };
        let mut emitted_tool_call = false;
        loop {
            match events.recv() {
                Ok(BackendEvent::Token { tok, .. }) => {
                    usage.completion_tokens += 1;
                    slot.charge(&self.session.id, 1);
                    if stream && !self.send_ok(&Event::Token { tok }) {
                        backend.cancel(req_id);
                        break;
                    }
                }
                Ok(BackendEvent::ToolCall { tool_call, .. }) => {
                    // Inert data. The daemon has no idea what this tool does
                    // and will not find out (§10).
                    self.history.push(Message {
                        role: "assistant".into(),
                        content: format!(
                            "{{\"tool_call\":{{\"id\":\"{}\",\"name\":\"{}\",\"arguments\":{}}}}}",
                            tool_call.id, tool_call.name, tool_call.arguments
                        ),
                        attachments: Vec::new(),
                        tool_call_id: Some(tool_call.id.clone()),
                    });
                    self.pending_tool_call = Some(tool_call.id.clone());
                    emitted_tool_call = true;
                    self.send(&Event::ToolCall { tool_call });
                }
                Ok(BackendEvent::Done { usage: backend_usage, finish_reason, .. }) => {
                    usage.prompt_tokens = backend_usage.prompt_tokens.max(prompt_estimate);
                    usage.completion_tokens =
                        backend_usage.completion_tokens.max(usage.completion_tokens);
                    let reason = finish_reason.or_else(|| {
                        emitted_tool_call.then(|| "tool_call".to_string())
                    });
                    self.send(&Event::Done { done: true, usage: usage.clone(), finish_reason: reason });
                    break;
                }
                Ok(BackendEvent::Error { code, message, .. }) => {
                    self.send(&Event::error(&code, message));
                    break;
                }
                Ok(other) => debug!("session {}: ignoring {other:?}", self.session.id),
                Err(_) => {
                    self.send(&Event::error(
                        "backend-failed",
                        format!("backend {} stopped answering", backend.name),
                    ));
                    break;
                }
            }
        }

        backend.finish(req_id);
        *self.session.current_req.lock().unwrap() = None;
        drop(slot);
        self.daemon.scheduler.mark_idle(&self.session.id);

        let actual = usage.prompt_tokens + usage.completion_tokens + usage.attachment_tokens;
        if actual > reserve {
            let _ = self.daemon.policy.charge_tokens(
                &self.session.identity,
                &self.limits,
                actual - reserve,
            );
        }
        let mut totals = self.session.usage.lock().unwrap();
        totals.prompt_tokens += usage.prompt_tokens;
        totals.completion_tokens += usage.completion_tokens;
        totals.attachment_tokens += usage.attachment_tokens;
    }

    fn embed(&self, inputs: Vec<String>) {
        if let Err(reason) = self.daemon.policy.check(&self.session.identity, CAP_EMBED) {
            self.daemon.audit.denied(&self.session.identity, CAP_EMBED, &reason);
            self.send(&Event::error("policy-denied", reason));
            return;
        }
        let backend = match self.daemon.backends.get(&self.session.backend) {
            Ok(backend) => backend,
            Err(e) => {
                self.send(&Event::error("backend-failed", e));
                return;
            }
        };
        if !backend.can("embed") {
            self.send(&Event::error(
                "attachment-unsupported",
                format!("backend {} does not embed", backend.name),
            ));
            return;
        }
        let estimate: u64 = inputs.iter().map(|i| estimate_tokens(i)).sum();
        if !self
            .daemon
            .policy
            .charge_tokens(&self.session.identity, &self.limits, estimate)
        {
            self.send(&Event::error("rate-limited", "over the tokens/minute allowance"));
            return;
        }

        let slot = self.daemon.scheduler.admit(&self.session.id, self.session.class);
        let model_id = self.session.model.clone();
        let Ok((req_id, events)) =
            backend.begin(move |req_id| BackendRequest::Embed { req_id, model_id, inputs })
        else {
            self.send(&Event::error("backend-failed", "could not start an embedding request"));
            return;
        };
        slot.attach(&backend.name, req_id);
        self.pump_simple(&backend, req_id, events);
    }

    fn tokenize(&self, text: String) {
        let backend = match self.daemon.backends.get(&self.session.backend) {
            Ok(backend) => backend,
            Err(e) => {
                self.send(&Event::error("backend-failed", e));
                return;
            }
        };
        let model_id = self.session.model.clone();
        let Ok((req_id, events)) =
            backend.begin(move |req_id| BackendRequest::Tokenize { req_id, model_id, text })
        else {
            self.send(&Event::error("backend-failed", "could not start a tokenize request"));
            return;
        };
        self.pump_simple(&backend, req_id, events);
    }

    /// Drain a one-shot request that answers with a single value.
    fn pump_simple(
        &self,
        backend: &Arc<Backend>,
        req_id: u64,
        events: std::sync::mpsc::Receiver<BackendEvent>,
    ) {
        loop {
            match events.recv() {
                Ok(BackendEvent::Vectors { vectors, .. }) => {
                    self.send(&Event::Vectors { vectors });
                }
                Ok(BackendEvent::Tokens { tokens, .. }) => {
                    self.send(&Event::Tokens { tokens });
                }
                Ok(BackendEvent::Done { usage, finish_reason, .. }) => {
                    self.send(&Event::Done { done: true, usage, finish_reason });
                    break;
                }
                Ok(BackendEvent::Error { code, message, .. }) => {
                    self.send(&Event::error(&code, message));
                    break;
                }
                Ok(_) => {}
                Err(_) => {
                    self.send(&Event::error("backend-failed", "backend stopped answering"));
                    break;
                }
            }
        }
        backend.finish(req_id);
    }

    fn announce_evictions(&self, evicted: &[String]) {
        for id in evicted {
            let Some(victim) = self.daemon.session(id) else { continue };
            let sink = victim.sink.lock().unwrap().clone();
            let Some(sink) = sink else { continue };
            let notice = Event::Notice {
                event: "context-evicted".into(),
                detail: "the scheduler reclaimed this session's KV cache; replay to continue".into(),
            };
            let mut guard = sink.lock().unwrap();
            let _ = frame::write_cbor(&mut *guard, &notice);
        }
    }

    fn estimate_prompt_tokens(&self) -> u64 {
        self.history.iter().map(|m| estimate_tokens(&m.content) + 4).sum()
    }

    /// Deliver an event, or note that the client has gone. Almost every call
    /// site has nothing useful to do about a dead socket — the read loop will
    /// discover it a moment later — so the failure is logged rather than
    /// propagated, and the streaming path uses [`Worker::send_ok`] instead.
    fn send(&self, event: &Event) {
        if !self.send_ok(event) {
            debug!("session {}: client is no longer reading", self.session.id);
        }
    }

    fn send_ok(&self, event: &Event) -> bool {
        let mut guard = self.sink.lock().unwrap();
        frame::write_cbor(&mut *guard, event).is_ok()
    }

    fn teardown(&mut self) {
        let usage = self.session.usage.lock().unwrap().clone();
        self.daemon.audit.session_end(
            &self.session.identity,
            &self.session.id,
            &self.session.model,
            usage.prompt_tokens,
            usage.completion_tokens,
            self.session.attachment_bytes.load(Ordering::Relaxed),
        );
        self.session.closed.store(true, Ordering::Relaxed);
        self.daemon.scheduler.release_kv(&self.session.id);
        self.daemon.policy.close_session(&self.session.identity);
        self.daemon.remove_session(&self.session.id);
        crate::dbusapi::unregister(&self.daemon, &self.session.object_path);
        if let Ok(backend) = self.daemon.backends.get(&self.session.backend) {
            backend.drop_cache(&self.session.id);
        }
        info!("session {} closed", self.session.id);
    }
}

fn kind_str(kind: AttachKind) -> &'static str {
    match kind {
        AttachKind::Image => "image",
        AttachKind::Audio => "audio",
    }
}

/// Four bytes to a token, the rule of thumb every English-language estimate
/// uses. It is only ever used for admission and budgeting; the authoritative
/// count comes back from the backend in `usage` and replaces it.
pub fn estimate_tokens(text: &str) -> u64 {
    (text.len() as u64).div_ceil(4)
}

/// Vision and audio tokens are the reason attachments need their own budget:
/// a 4-megapixel screenshot is worth thousands of tokens of KV cache and would
/// otherwise walk past a tokens-per-minute limit written for text.
fn estimate_attachment_tokens(attachment: &RawAttachment) -> u64 {
    match attachment.kind.as_str() {
        "image" => {
            let pixels =
                (attachment.w.unwrap_or(0) as u64).saturating_mul(attachment.h.unwrap_or(0) as u64);
            // One token per 28x28 patch, the common ViT tiling.
            pixels.div_ceil(784)
        }
        "audio" => {
            let samples = attachment.data.len() as u64 / 4;
            let rate = attachment.rate.unwrap_or(16_000).max(1) as u64;
            // 50 frames a second is the usual encoder rate.
            (samples * 50).div_ceil(rate)
        }
        _ => 0,
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_estimates_are_conservative_and_never_zero_for_text() {
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("a"), 1, "rounding up matters: a budget of zero admits anything");
        assert_eq!(estimate_tokens("abcd"), 1);
        assert_eq!(estimate_tokens("abcde"), 2);
    }

    fn image(w: u32, h: u32) -> RawAttachment {
        RawAttachment {
            id: "i".into(),
            kind: "image".into(),
            w: Some(w),
            h: Some(h),
            fmt: Some("rgba8".into()),
            rate: None,
            data: vec![0; (w * h * 4) as usize],
        }
    }

    /// The reason attachments have their own budget: a screenshot is worth
    /// thousands of tokens and would otherwise stroll past a limit written for
    /// prose.
    #[test]
    fn a_screenshot_costs_far_more_than_its_prompt_would_suggest() {
        let tokens = estimate_attachment_tokens(&image(1920, 1080));
        assert!(tokens > 2000, "a 1080p screenshot is {tokens} tokens");
        assert_eq!(estimate_attachment_tokens(&image(28, 28)), 1);
    }

    #[test]
    fn audio_is_costed_by_duration_not_by_bytes() {
        let one_second = RawAttachment {
            id: "a".into(),
            kind: "audio".into(),
            w: None,
            h: None,
            fmt: None,
            rate: Some(16_000),
            data: vec![0; 16_000 * 4],
        };
        assert_eq!(estimate_attachment_tokens(&one_second), 50);

        // The same duration at a higher sample rate is the same amount of
        // speech, so it must cost the same.
        let resampled = RawAttachment {
            rate: Some(48_000),
            data: vec![0; 48_000 * 4],
            ..one_second.clone()
        };
        assert_eq!(estimate_attachment_tokens(&resampled), 50);
    }

    #[test]
    fn an_unknown_attachment_kind_costs_nothing_rather_than_panicking() {
        let odd = RawAttachment {
            id: "x".into(),
            kind: "video".into(),
            w: None,
            h: None,
            fmt: None,
            rate: None,
            data: vec![0; 100],
        };
        assert_eq!(estimate_attachment_tokens(&odd), 0);
    }
}
