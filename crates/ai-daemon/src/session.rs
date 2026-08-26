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
use std::sync::{mpsc, Arc, Mutex};

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
///
/// Failing here is the caller's problem, not a line in the journal: at this
/// point the session is counted against its identity's limit and sitting in
/// the daemon's map, and only the caller knows how to give those back.
pub fn spawn(
    daemon: Arc<Daemon>,
    session: Arc<Session>,
    socket: UnixStream,
    limits: Limits,
) -> Result<(), String> {
    let name = format!("session-{}", session.id);
    std::thread::Builder::new()
        .name(name)
        .spawn(move || {
            let sink: Sink = match socket.try_clone() {
                Ok(clone) => Arc::new(Mutex::new(clone)),
                Err(e) => {
                    // Nothing to serve this session with, and it is already
                    // counted and registered — so retire it properly rather
                    // than leaving a row nobody will ever remove.
                    warn!("session {}: cannot dup its socket ({e}); closing", session.id);
                    retire(&daemon, &session);
                    return;
                }
            };
            *session.sink.lock().unwrap() = Some(sink.clone());

            let (sender, frames) = mpsc::sync_channel::<Frame>(0);
            let reader = std::thread::Builder::new()
                .name(format!("session-{}-read", session.id))
                .spawn({
                    let daemon = daemon.clone();
                    let session = session.clone();
                    move || read_socket(daemon, session, socket, sender)
                });
            if let Err(e) = reader {
                warn!("could not start a reader for session {}: {e}", session.id);
                retire(&daemon, &session);
                return;
            }

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
            worker.run(frames);
            worker.teardown();
        })
        .map(|_| ())
        .map_err(|e| format!("could not start a thread for session: {e}"))
}

/// Everything that must happen when a session stops existing, wherever that
/// was noticed — the worker finishing, the worker never starting, or
/// `CreateSession` giving up half way through building it.
///
/// One function because these must not drift: the count against the
/// identity's limit, the entry in the daemon's map, the object on the bus and
/// the audit record are four pieces of state that are only correct together.
pub fn retire(daemon: &Daemon, session: &Session) {
    let usage = session.usage.lock().unwrap().clone();
    daemon.audit.session_end(
        &session.identity,
        &session.id,
        &session.model,
        usage.prompt_tokens,
        usage.completion_tokens,
        session.attachment_bytes.load(Ordering::Relaxed),
    );
    session.closed.store(true, Ordering::Relaxed);
    daemon.scheduler.release_kv(&session.id);
    daemon.policy.close_session(&session.identity);
    daemon.remove_session(&session.id);
    crate::dbusapi::unregister(daemon, &session.object_path);
    if let Ok(backend) = daemon.backends.get(&session.backend) {
        backend.drop_cache(&session.id);
    }
    // Shut the socket, or the reader thread outlives us.
    //
    // The worker used to own the socket, so returning from `run` dropped it
    // and the client saw EOF. The reader thread owns it now, and it is blocked
    // in a read that only the client can end — so every fatal protocol exit
    // would otherwise leave a thread and this Session alive until the client
    // felt like disconnecting. The session count has already been given back
    // by then, so max_sessions does not bound it.
    let sink = session.sink.lock().unwrap().clone();
    if let Some(sink) = sink {
        let _ = sink.lock().unwrap().shutdown(std::net::Shutdown::Both);
    }
    info!("session {} closed", session.id);
}

/// Read the socket, and be the only thing that does.
///
/// This exists so that `Cancel` means something. The session used to read and
/// work on one thread, which reads the socket only *between* turns — so a
/// cancel sent during a generation sat unread in the socket buffer until the
/// generation it was cancelling had finished. Every effect of the cancel arm
/// then no-opped: `current_req` was already cleared, and the flag it set was
/// reset by the next turn before anything looked at it.
///
/// So the parse happens here, off the working thread, and a cancel is acted on
/// the moment it arrives. Everything else is handed across a rendezvous
/// channel — capacity zero, deliberately: the socket used to be the
/// backpressure and a buffer here would replace it with an allocation a client
/// controls. A frame waits until the worker is ready for it, exactly as it
/// waited in the kernel before.
fn read_socket(
    daemon: Arc<Daemon>,
    session: Arc<Session>,
    socket: UnixStream,
    frames: mpsc::SyncSender<Frame>,
) {
    let mut reader = BufReader::new(socket);
    loop {
        match frame::read_frame(&mut reader) {
            Ok(Some(Frame::Cbor(value))) => {
                // Peeked before forwarding, so a cancel never queues behind
                // work — including behind the generation it is cancelling.
                if let Ok(Request::Cancel) = value.deserialized::<Request>() {
                    debug!("session {}: cancel from the client", session.id);
                    cancel_in_flight(&daemon, &session);
                    continue;
                }
                if frames.send(Frame::Cbor(value)).is_err() {
                    return;
                }
            }
            Ok(Some(blob)) => {
                if frames.send(blob).is_err() {
                    return;
                }
            }
            Ok(None) => {
                debug!("session {}: client closed the socket", session.id);
                break;
            }
            Err(e) => {
                debug!("session {}: {e}", session.id);
                break;
            }
        }
    }
    // The client is gone. Anything still generating is generating for nobody,
    // and it holds a decode slot while it does it — which is how two abandoned
    // requests take out interactive capacity on an install that allows two.
    // A non-streaming request is the case that matters: nothing is written
    // until `done`, so there is no failing send to notice the disconnect.
    cancel_in_flight(&daemon, &session);
}

/// Stop whatever this session has in flight, from any thread.
///
/// The one shared implementation, because there are four ways to arrive here —
/// the client's `Cancel` frame, the client vanishing, `Session.Cancel` on the
/// bus, and `Session.Close` — and three of them used to do something
/// different, or nothing.
pub fn cancel_in_flight(daemon: &Daemon, session: &Session) {
    session.cancelled.store(true, Ordering::SeqCst);
    let current = *session.current_req.lock().unwrap();
    if let Some(req_id) = current {
        if let Ok(backend) = daemon.backends.get(&session.backend) {
            backend.cancel(req_id);
        }
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
    fn run(&mut self, frames: mpsc::Receiver<Frame>) {
        loop {
            if self.session.closed.load(Ordering::Relaxed) {
                return;
            }
            let request: Request = match frames.recv() {
                Err(_) => return, // the reader is gone, and so is the client
                Ok(Frame::Blob(_)) => {
                    self.send(&Event::error("protocol", "a BLOB arrived with no attachment to own it"));
                    return;
                }
                Ok(Frame::Cbor(value)) => match value.deserialized() {
                    Ok(request) => request,
                    Err(e) => {
                        self.send(&Event::error("protocol", format!("unrecognised request: {e}")));
                        continue;
                    }
                },
            };
            self.daemon.touch();
            if let Err(fatal) = self.dispatch(request, &frames) {
                if fatal {
                    return;
                }
            }
        }
    }

    /// `Err(true)` means the socket is no longer usable and the thread should
    /// stop; `Err(false)` means the request failed but the session lives.
    fn dispatch(&mut self, request: Request, frames: &mpsc::Receiver<Frame>) -> Result<(), bool> {
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
            Request::Attach { id, kind, meta, len } => self.attach(id, kind, meta, len, frames),
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
            // Handled by the reading thread the instant it arrives, which is
            // the only place it can be handled in time. Reaching here means a
            // cancel with nothing to cancel — the session was idle — and the
            // flag the reader set is cleared by the next turn.
            Request::Cancel => Ok(()),
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
        frames: &mpsc::Receiver<Frame>,
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
            match frames.recv() {
                Ok(Frame::Blob(mut chunk)) => payload.append(&mut chunk),
                Ok(Frame::Cbor(_)) => {
                    self.send(&Event::error("protocol", "attachment interrupted by a request frame"));
                    return Err(true);
                }
                Err(_) => return Err(true),
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
                if !raw.data.len().is_multiple_of(4) {
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
        // One attachment fitting is checked at config load; several of them in
        // one request is a client's choice and has to be checked here. They all
        // travel to the backend inside a single CBOR frame, so the sum is what
        // matters — and at the shipped budgets sixteen full-size images exceed
        // it, which would otherwise fail as a framing error on the backend
        // socket and reach the client as "backend-failed".
        let attachment_bytes: u64 = attachments.iter().map(|a| a.data.len() as u64).sum();
        if attachment_bytes > ai_daemon_proto::frame::MAX_ATTACHMENT_PAYLOAD {
            self.send(&Event::error(
                "policy-denied",
                format!(
                    "{} attachment(s) totalling {attachment_bytes} decoded bytes exceed the {} \
                     bytes one request can carry; send fewer, or smaller ones",
                    attachments.len(),
                    ai_daemon_proto::frame::MAX_ATTACHMENT_PAYLOAD
                ),
            ));
            return;
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
        let mut cancel_sent = false;
        loop {
            // The flag's reader. The reading thread cancels the backend
            // directly when it can, but a cancel that lands between `begin`
            // and the `current_req` store above finds nothing to cancel and
            // leaves only this flag behind — so the loop checks it too, and
            // the backend hears about it once either way.
            if !cancel_sent && self.session.cancelled.load(Ordering::SeqCst) {
                cancel_sent = true;
                backend.cancel(req_id);
            }
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
        retire(&self.daemon, &self.session);
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
    use std::time::Duration;

    /// A fatal protocol error must close the socket, not just stop serving it.
    ///
    /// The regression this pins: once the reader moved to its own thread, the
    /// worker returning no longer dropped the socket, so the reader stayed
    /// blocked in a read that only the client could end. Every fatal exit —
    /// a bare BLOB, a wrong protocol version, an interrupted attachment — left
    /// a thread and a Session alive for as long as the client cared to hold
    /// the other end, and teardown had already handed back the session count,
    /// so max_sessions did not bound it.
    ///
    /// Asserting on EOF rather than on a thread count: the property the client
    /// and the kernel can both see is the one worth pinning.
    #[test]
    fn a_fatal_protocol_error_closes_the_socket() {
        let dir = std::env::temp_dir()
            .join(format!("ai-daemon-session-eof-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut config = crate::config::Config::default();
        config.daemon.state_dir = dir.clone();
        config.policy.gate_group = String::new();
        let daemon = Daemon::new(config);

        let (ours, theirs) = UnixStream::pair().unwrap();
        let session = Arc::new(Session {
            id: "s-eof".into(),
            object_path: "/test/s-eof".into(),
            identity: crate::identity::Identity {
                class: crate::identity::Class::Native,
                uid: 1000,
                gid: 1000,
                pid: std::process::id() as i32,
                unit: None,
                app_id: None,
                exe: Some("test".into()),
            },
            model: "none".into(),
            digest: "sha256:0".into(),
            backend: "none".into(),
            local: true,
            class: crate::sched::Class::Interactive,
            max_context: 1024,
            created: std::time::Instant::now(),
            blob: dir.join("weights"),
            usage: Mutex::new(Usage::default()),
            attachment_bytes: std::sync::atomic::AtomicU64::new(0),
            attachments: Mutex::new(std::collections::HashMap::new()),
            current_req: Mutex::new(None),
            sink: Mutex::new(None),
            cancelled: std::sync::atomic::AtomicBool::new(false),
            closed: std::sync::atomic::AtomicBool::new(false),
        });
        daemon.insert_session(session.clone());

        spawn(
            daemon.clone(),
            session,
            ours,
            Limits {
                max_context: 1024,
                max_sessions: 4,
                tokens_per_minute: 1000,
                allowed_models: vec!["*".into()],
            },
        )
        .expect("the worker thread must start for this test to mean anything");

        // A BLOB with no attachment to own it: one of the fatal arms.
        let mut client = theirs;
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        frame::write_blob(&mut client, b"unowned").unwrap();

        // Drain whatever the daemon says, then require the close.
        let mut buffer = [0u8; 4096];
        let mut saw_eof = false;
        for _ in 0..16 {
            match std::io::Read::read(&mut client, &mut buffer) {
                Ok(0) => {
                    saw_eof = true;
                    break;
                }
                Ok(_) => continue,
                Err(e) => panic!("expected EOF, got {e}"),
            }
        }
        assert!(
            saw_eof,
            "the daemon finished with this session and left the socket open; \
             the reader thread is still blocked on it"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

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
