// SPDX-License-Identifier: Apache-2.0

//! Talking to provider plugins (§7).
//!
//! Every backend is a child process on the other end of a socketpair it
//! receives as fd 3. That is a deliberate cost: a shared library would be
//! faster to call and would also mean a fault in a vendor's GPU userspace
//! takes down the process holding every grant, every session and the audit
//! chain. Crash isolation is the feature.
//!
//! One socket carries every session assigned to that backend, demultiplexed by
//! `req_id`. A reader thread owns the read half and hands events to whichever
//! request is waiting; nothing else reads from the socket, so there is no way
//! for two requests to steal each other's tokens.

use std::collections::HashMap;
use std::io::{BufReader, BufWriter};
use std::os::unix::io::IntoRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ai_daemon_proto::backend::{BackendEvent, BackendInfo, BackendRequest};
use ai_daemon_proto::frame;
use ai_daemon_proto::BACKEND_PROTO;

use crate::config;
use crate::{debug, error, info, warn};

/// Device nodes a backend may legitimately claim. Anything else is either a
/// mistake or a backend trying to widen the unit's `DeviceAllow`, and the
/// daemon would rather say so at hello time than at load time.
const ALLOWED_DEVICE_PREFIXES: [&str; 2] = ["/dev/dri/", "/dev/accel/"];

#[derive(Debug, Clone)]
pub struct LoadedModel {
    pub model_id: String,
    pub kv_bytes_per_token: u64,
    pub n_ctx: u32,
}

pub struct Backend {
    pub name: String,
    pub info: BackendInfo,
    child: Mutex<Option<Child>>,
    writer: Mutex<BufWriter<UnixStream>>,
    /// Held across send-and-wait for load and unload. Deliberately not the
    /// writer lock: that one is taken by every token-path send, and holding it
    /// for the five minutes a load may take would stop the backend dead.
    control_op: Mutex<()>,
    inflight: Arc<Mutex<HashMap<u64, Sender<BackendEvent>>>>,
    control: Mutex<Receiver<BackendEvent>>,
    loaded: Mutex<HashMap<String, LoadedModel>>,
    next_req: AtomicU64,
    alive: Arc<AtomicBool>,
}

impl Backend {
    /// Spawn a backend and complete its handshake, or fail.
    ///
    /// A backend that cannot say hello in ten seconds is a backend that will
    /// not stream tokens either; failing here keeps a broken plugin from
    /// looking like a slow model.
    pub fn spawn(spec: &config::Backend) -> Result<Backend, String> {
        // A backend the daemon connects to rather than owns.
        //
        // This exists for the one case a child process cannot serve: a
        // provider that needs a network. The daemon runs with
        // PrivateNetwork=yes, and anything it forks inherits that namespace,
        // so a remote backend spawned here would have no network at all. It
        // runs as its own unit instead, with its own user, and this end is
        // just a socket — which also means it survives the daemon's idle exit
        // and is there again when the bus reactivates us.
        if let Some(path) = &spec.connect {
            let socket = UnixStream::connect(path).map_err(|e| {
                format!("connecting to backend {} at {}: {e}", spec.name, path.display())
            })?;
            return Backend::over(spec, socket, None);
        }

        if !spec.exec.exists() {
            return Err(format!("{} does not exist", spec.exec.display()));
        }
        let (ours, theirs) = UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
        let their_fd = theirs.into_raw_fd();

        let mut command = Command::new(&spec.exec);
        command
            .args(&spec.args)
            .stdin(Stdio::null())
            // The backend's stdout and stderr are the daemon's, so they reach
            // the journal under the daemon's unit. A backend that prints
            // prompt content is a backend that has broken the logging rule,
            // which is the sort of thing you want visible, not hidden.
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("AI_DAEMON_BACKEND_FD", "3");
        for (k, v) in &spec.env {
            command.env(k, v);
        }
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(their_fd, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // dup2 clears CLOEXEC on the new descriptor, which is what we
                // want; the original may be anywhere, so close it explicitly.
                if their_fd != 3 {
                    libc::close(their_fd);
                }
                Ok(())
            });
        }
        let child = command.spawn().map_err(|e| format!("spawning {}: {e}", spec.exec.display()))?;
        // SAFETY: the child now owns its dup; this side closes the original.
        unsafe {
            libc::close(their_fd);
        }

        Backend::over(spec, ours, Some(child))
    }

    /// The half that is the same however the socket was obtained: the reader
    /// thread, the channels, and the handshake.
    fn over(
        spec: &config::Backend,
        ours: UnixStream,
        child: Option<Child>,
    ) -> Result<Backend, String> {
        let read_half = ours.try_clone().map_err(|e| format!("dup socket: {e}"))?;
        let alive = Arc::new(AtomicBool::new(true));
        let inflight: Arc<Mutex<HashMap<u64, Sender<BackendEvent>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (control_tx, control_rx) = channel();

        {
            let alive = alive.clone();
            let inflight = inflight.clone();
            let name = spec.name.clone();
            std::thread::Builder::new()
                .name(format!("backend-{}", spec.name))
                .spawn(move || reader_loop(name, read_half, inflight, control_tx, alive))
                .map_err(|e| format!("reader thread: {e}"))?;
        }

        // Handshake before the struct exists, not after: a Backend that has
        // not said hello has no capabilities to report, and constructing one
        // that might never be filled in invites every later reader to wonder
        // whether `info` is real.
        let mut writer = BufWriter::new(ours);
        frame::write_cbor(&mut writer, &BackendRequest::Hello { proto: BACKEND_PROTO })
            .map_err(|e| format!("greeting backend {}: {e}", spec.name))?;
        let hello = control_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| format!("backend {} did not answer hello within 10s", spec.name))?;
        let info = match hello {
            BackendEvent::Hello { proto, info } => {
                if proto != BACKEND_PROTO {
                    return Err(format!(
                        "backend {} speaks protocol {proto}, this daemon speaks {BACKEND_PROTO}",
                        spec.name
                    ));
                }
                info
            }
            other => return Err(format!("backend {} answered hello with {other:?}", spec.name)),
        };

        for device in &info.devices {
            if !ALLOWED_DEVICE_PREFIXES.iter().any(|p| device.starts_with(p)) {
                return Err(format!(
                    "backend {} claims {device}, which is outside the device access this unit grants",
                    spec.name
                ));
            }
        }

        info!(
            "backend {}: {} {} — formats {:?}, capabilities {:?}, local={}",
            spec.name, info.name, info.version, info.formats, info.capabilities, info.local
        );

        Ok(Backend {
            name: spec.name.clone(),
            info,
            child: Mutex::new(child),
            writer: Mutex::new(writer),
            control_op: Mutex::new(()),
            inflight,
            control: Mutex::new(control_rx),
            loaded: Mutex::new(HashMap::new()),
            next_req: AtomicU64::new(1),
            alive,
        })
    }

    pub fn alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    pub fn can(&self, capability: &str) -> bool {
        self.info.capabilities.iter().any(|c| c == capability)
    }

    pub fn handles_format(&self, format: &str) -> bool {
        self.info.formats.iter().any(|f| f.eq_ignore_ascii_case(format))
    }

    pub fn loaded_model(&self, model_id: &str) -> Option<LoadedModel> {
        self.loaded.lock().unwrap().get(model_id).cloned()
    }

    pub fn loaded_models(&self) -> Vec<LoadedModel> {
        self.loaded.lock().unwrap().values().cloned().collect()
    }
    /// Make a model resident.
    ///
    /// Serialised against every other control operation on this backend, and
    /// the reply is checked against what was asked for. Both halves are load
    /// bearing.
    ///
    /// `Loaded`, `Unloaded` and `Hello` carry no request id — they are the one
    /// part of the protocol that is not correlated — so they all arrive on the
    /// single control channel and there is nothing in a reply that says which
    /// send it answers. `send` takes the writer lock and the wait takes the
    /// control lock, so without this mutex two threads interleave as A.send,
    /// B.send, A.wait, B.wait and each takes whichever reply lands first.
    /// `load(m1)` then returns the `kv_bytes_per_token` and `n_ctx` of m2, and
    /// every KV reservation for that session is wrong by the ratio between two
    /// models; worse, a load crossing an unload leaves `loaded` naming a model
    /// the backend has dropped, and the fast path below turns that one crossed
    /// reply into every later session on that model failing until restart.
    ///
    /// The alternative fix is a request id on the control operations, which is
    /// the better protocol and a breaking change to a surface documented as
    /// frozen at v1 and implemented by two shipped backends. Serialising costs
    /// throughput nobody is using — a desktop loads one or two models, and a
    /// second load waiting behind a first is the honest cost of the first.
    ///
    /// The checking is not redundant with the serialising. A control operation
    /// that times out leaves its reply to arrive later, and the next operation
    /// would otherwise take it.
    pub fn load(
        &self,
        model_id: &str,
        path: &Path,
        digest: &str,
        n_ctx: u32,
    ) -> Result<LoadedModel, String> {
        if let Some(existing) = self.loaded_model(model_id) {
            return Ok(existing);
        }
        let _serialised = self.control_op.lock().unwrap();
        // Again under the lock: two sessions opening the same model race here,
        // and the one that waited should find the other's work rather than ask
        // for it twice.
        if let Some(existing) = self.loaded_model(model_id) {
            return Ok(existing);
        }

        self.send(&BackendRequest::Load {
            model_id: model_id.to_string(),
            path: path.display().to_string(),
            digest: digest.to_string(),
            n_ctx,
        })?;
        // Loading multi-gigabyte weights from cold cache is genuinely slow;
        // five minutes is "the disk is broken", not "the model is big".
        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            match self.await_until(deadline)? {
                BackendEvent::Loaded { model_id: answered, kv_bytes_per_token, n_ctx } => {
                    if answered != model_id {
                        warn!(
                            "backend {}: discarding a stale reply about {answered} while loading {model_id}",
                            self.name
                        );
                        continue;
                    }
                    let loaded = LoadedModel {
                        model_id: answered.clone(),
                        kv_bytes_per_token,
                        n_ctx,
                    };
                    self.loaded.lock().unwrap().insert(answered, loaded.clone());
                    return Ok(loaded);
                }
                BackendEvent::Error { code, message, .. } => {
                    return Err(format!("{code}: {message}"))
                }
                other => {
                    warn!("backend {}: discarding {other:?} while loading {model_id}", self.name);
                    continue;
                }
            }
        }
    }

    pub fn unload(&self, model_id: &str) -> Result<(), String> {
        let _serialised = self.control_op.lock().unwrap();
        self.send(&BackendRequest::Unload { model_id: model_id.to_string() })?;
        let deadline = Instant::now() + Duration::from_secs(60);
        let outcome = loop {
            match self.await_until(deadline) {
                Ok(BackendEvent::Unloaded { model_id: answered }) => {
                    if answered != model_id {
                        warn!(
                            "backend {}: discarding a stale reply about {answered} while unloading {model_id}",
                            self.name
                        );
                        continue;
                    }
                    break Ok(());
                }
                Ok(BackendEvent::Error { code, message, .. }) => {
                    break Err(format!("{code}: {message}"))
                }
                Ok(other) => {
                    warn!("backend {}: discarding {other:?} while unloading {model_id}", self.name);
                    continue;
                }
                Err(e) => break Err(e),
            }
        };
        // Forgotten either way. After a failed or timed-out unload the backend's
        // state is exactly what we do not know, and of the two guesses only one
        // is safe: a redundant load costs a round trip, while a `loaded` entry
        // for a model the backend has dropped is served straight back out of
        // the fast path above and generates against a model that is not there.
        self.loaded.lock().unwrap().remove(model_id);
        outcome
    }

    /// Start a request and get the stream of events belonging to it.
    ///
    /// The caller must drain the receiver; dropping it mid-generation leaks
    /// the entry until the backend sends `done`, which is why every caller
    /// pairs this with [`Backend::finish`].
    pub fn begin(&self, make: impl FnOnce(u64) -> BackendRequest) -> Result<(u64, Receiver<BackendEvent>), String> {
        let req_id = self.next_req.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = channel();
        self.inflight.lock().unwrap().insert(req_id, tx);
        if let Err(e) = self.send(&make(req_id)) {
            self.inflight.lock().unwrap().remove(&req_id);
            return Err(e);
        }
        Ok((req_id, rx))
    }

    pub fn finish(&self, req_id: u64) {
        self.inflight.lock().unwrap().remove(&req_id);
    }

    pub fn cancel(&self, req_id: u64) {
        let _ = self.send(&BackendRequest::Cancel { req_id });
    }

    pub fn pause(&self, req_id: u64) {
        let _ = self.send(&BackendRequest::Pause { req_id });
    }

    pub fn resume(&self, req_id: u64) {
        let _ = self.send(&BackendRequest::Resume { req_id });
    }

    pub fn drop_cache(&self, session_id: &str) {
        let _ = self.send(&BackendRequest::DropCache { session_id: session_id.to_string() });
    }

    pub fn send(&self, request: &BackendRequest) -> Result<(), String> {
        if !self.alive() {
            return Err(format!("backend {} is not running", self.name));
        }
        let mut writer = self.writer.lock().unwrap();
        frame::write_cbor(&mut *writer, request)
            .map_err(|e| format!("writing to backend {}: {e}", self.name))
    }

    /// Wait for a control event, but never past `deadline` — so a loop that
    /// discards a stale reply cannot restart the clock each time round.
    fn await_until(&self, deadline: Instant) -> Result<BackendEvent, String> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!("backend {} did not answer in time", self.name));
        }
        self.control
            .lock()
            .unwrap()
            .recv_timeout(remaining)
            .map_err(|_| format!("backend {} did not answer in time", self.name))
    }

    pub fn shutdown(&self) {
        // A backend we merely dialled is not ours to stop.
        //
        // It is another unit, with its own lifecycle, and it may be serving
        // something else the moment after this daemon idles out. Sending it
        // `Shutdown` would be asking a service we do not own to die, and the
        // daemon exiting is not a reason for it to. Closing our end is the
        // whole of our side of the goodbye: the peer sees EOF and forgets the
        // connection, which is what it should do either way.
        if self.child.lock().unwrap().is_none() {
            return;
        }
        let _ = self.send(&BackendRequest::Shutdown);
        let mut guard = self.child.lock().unwrap();
        let Some(child) = guard.as_mut() else { return };
        for _ in 0..50 {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(_) => break,
            }
        }
        warn!("backend {} did not exit on request; killing", self.name);
        let _ = child.kill();
        let _ = child.wait();
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn reader_loop(
    name: String,
    socket: UnixStream,
    inflight: Arc<Mutex<HashMap<u64, Sender<BackendEvent>>>>,
    control: Sender<BackendEvent>,
    alive: Arc<AtomicBool>,
) {
    let mut reader = BufReader::new(socket);
    loop {
        let event: BackendEvent = match frame::read_typed(&mut reader) {
            Ok(Some(event)) => event,
            Ok(None) => {
                info!("backend {name}: closed its socket");
                break;
            }
            Err(e) => {
                error!("backend {name}: protocol error ({e}); dropping the backend");
                break;
            }
        };
        // Exhaustive, deliberately: no `_` arm.
        //
        // There used to be one, and it silently routed anything new to the
        // control channel — where it is neither delivered to the request that
        // asked for it nor recognised by the load/unload that is waiting
        // there. Adding a variant then compiled cleanly and lost every event
        // of that kind. Listing them all means the next variant does not
        // build until somebody has decided which channel it belongs on.
        let routed = match &event {
            BackendEvent::Token { req_id, .. }
            | BackendEvent::ToolCall { req_id, .. }
            | BackendEvent::ToolCalls { req_id, .. }
            | BackendEvent::Media { req_id, .. }
            | BackendEvent::Vectors { req_id, .. }
            | BackendEvent::Tokens { req_id, .. }
            | BackendEvent::Done { req_id, .. } => Some(*req_id),
            BackendEvent::Error { req_id, .. } => *req_id,
            // These answer a control operation, not a request: they carry no
            // req_id because there is only ever one of them outstanding.
            BackendEvent::Hello { .. }
            | BackendEvent::Loaded { .. }
            | BackendEvent::Unloaded { .. } => None,
        };
        match routed {
            Some(req_id) => {
                let sender = inflight.lock().unwrap().get(&req_id).cloned();
                match sender {
                    Some(tx) => {
                        if tx.send(event).is_err() {
                            debug!("backend {name}: req {req_id} abandoned by its session");
                        }
                    }
                    // A cancelled request's tail. Expected, not an error.
                    None => debug!("backend {name}: event for unknown req {req_id}"),
                }
            }
            None => {
                let _ = control.send(event);
            }
        }
    }
    alive.store(false, Ordering::Relaxed);
    // Dropping every sender wakes each waiting session with a disconnect,
    // which they report as `backend-failed` rather than hanging forever.
    inflight.lock().unwrap().clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_daemon_proto::frame;

    /// A Backend wired to a socketpair instead of a child process, so a test
    /// can script exactly what the far end says and when. Everything except
    /// the spawn is the real thing: the same reader thread, the same channels,
    /// the same locks.
    fn backend_on(socket: UnixStream) -> Backend {
        let read_half = socket.try_clone().unwrap();
        let alive = Arc::new(AtomicBool::new(true));
        let inflight: Arc<Mutex<HashMap<u64, Sender<BackendEvent>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (control_tx, control_rx) = channel();
        {
            let alive = alive.clone();
            let inflight = inflight.clone();
            std::thread::spawn(move || {
                reader_loop("test".into(), read_half, inflight, control_tx, alive)
            });
        }
        Backend {
            name: "test".into(),
            info: BackendInfo {
                name: "test".into(),
                version: "0".into(),
                formats: vec!["mock".into()],
                quantizations: Vec::new(),
                devices: Vec::new(),
                device_memory: None,
                capabilities: vec!["generate".into()],
                local: true,
            },
            child: Mutex::new(None),
            writer: Mutex::new(BufWriter::new(socket)),
            control_op: Mutex::new(()),
            inflight,
            control: Mutex::new(control_rx),
            loaded: Mutex::new(HashMap::new()),
            next_req: AtomicU64::new(1),
            alive,
        }
    }

    /// The scripted far end: read one request, send the given replies.
    fn peer(socket: UnixStream, replies: Vec<BackendEvent>) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let _request: Option<BackendRequest> = frame::read_typed(&mut reader).unwrap();
            let mut writer = socket;
            for reply in replies {
                frame::write_cbor(&mut writer, &reply).unwrap();
            }
        })
    }

    /// The crossed reply, made deterministic. `Loaded` carries no request id,
    /// so a reply about another model is indistinguishable from ours except by
    /// the name inside it — and taking it means the session runs with another
    /// model's kv_bytes_per_token and context window.
    #[test]
    fn a_reply_about_another_model_is_not_taken_as_ours() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let backend = backend_on(ours);
        let scripted = peer(
            theirs,
            vec![
                BackendEvent::Loaded {
                    model_id: "other-model".into(),
                    kv_bytes_per_token: 999_999,
                    n_ctx: 128,
                },
                BackendEvent::Loaded {
                    model_id: "wanted".into(),
                    kv_bytes_per_token: 4096,
                    n_ctx: 8192,
                },
            ],
        );

        let loaded = backend
            .load("wanted", std::path::Path::new("/dev/null"), "sha256:0", 8192)
            .unwrap();
        assert_eq!(loaded.model_id, "wanted");
        assert_eq!(loaded.kv_bytes_per_token, 4096, "another model's budget would mis-charge every reservation");
        assert_eq!(loaded.n_ctx, 8192);
        assert!(backend.loaded_model("other-model").is_none(), "and it must not be cached under the wrong name");
        scripted.join().unwrap();
    }

    #[test]
    fn an_unload_reply_about_another_model_is_not_taken_as_ours() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let backend = backend_on(ours);
        backend.loaded.lock().unwrap().insert(
            "keep".into(),
            LoadedModel { model_id: "keep".into(), kv_bytes_per_token: 1, n_ctx: 1 },
        );
        let scripted = peer(
            theirs,
            vec![
                BackendEvent::Unloaded { model_id: "keep".into() },
                BackendEvent::Unloaded { model_id: "drop".into() },
            ],
        );

        backend.unload("drop").unwrap();
        assert!(
            backend.loaded_model("keep").is_some(),
            "a stale reply naming another model must not evict it"
        );
        scripted.join().unwrap();
    }

    /// The amplifier. A failed unload leaves the backend's state unknown, and
    /// the load fast path will hand out whatever `loaded` still says — so an
    /// entry that survives a failed unload becomes every later session on that
    /// model generating against a model the backend does not have.
    #[test]
    fn a_failed_unload_still_forgets_the_model() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let backend = backend_on(ours);
        backend.loaded.lock().unwrap().insert(
            "doomed".into(),
            LoadedModel { model_id: "doomed".into(), kv_bytes_per_token: 1, n_ctx: 1 },
        );
        let scripted = peer(
            theirs,
            vec![BackendEvent::Error {
                req_id: None,
                code: "backend-failed".into(),
                message: "no".into(),
            }],
        );

        assert!(backend.unload("doomed").is_err());
        assert!(
            backend.loaded_model("doomed").is_none(),
            "the fast path would serve this straight back out"
        );
        scripted.join().unwrap();
    }

    /// Two threads asking for the same model must not both ask the backend.
    #[test]
    fn a_concurrent_load_of_one_model_is_asked_for_once() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let backend = Arc::new(backend_on(ours));
        let requests = Arc::new(AtomicU64::new(0));

        let counter = requests.clone();
        let scripted = std::thread::spawn(move || {
            let mut reader = BufReader::new(theirs.try_clone().unwrap());
            let mut writer = theirs;
            // Answer only the first request; a second would hang the test,
            // which is the point being made.
            let _first: Option<BackendRequest> = frame::read_typed(&mut reader).unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(100));
            frame::write_cbor(
                &mut writer,
                &BackendEvent::Loaded {
                    model_id: "shared".into(),
                    kv_bytes_per_token: 64,
                    n_ctx: 2048,
                },
            )
            .unwrap();
        });

        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let backend = backend.clone();
                    scope.spawn(move || {
                        backend
                            .load("shared", std::path::Path::new("/dev/null"), "sha256:0", 2048)
                            .unwrap()
                    })
                })
                .collect();
            for handle in handles {
                let loaded = handle.join().unwrap();
                assert_eq!(loaded.model_id, "shared");
                assert_eq!(loaded.kv_bytes_per_token, 64);
            }
        });
        assert_eq!(requests.load(Ordering::SeqCst), 1, "the second caller should find the first's work");
        scripted.join().unwrap();
    }

    /// A backend the daemon connected to is a service it does not own, and
    /// telling it to shut down when this daemon idles out would take it away
    /// from whoever else is using it. The distinction is `child`: spawned
    /// backends have one, dialled ones do not.
    ///
    /// Asserted by *absence of a frame*, not by EOF. The fixture's reader
    /// thread holds a dup of the same socket, so dropping the Backend never
    /// closes the far end and waiting for EOF would time out whatever the
    /// code did — a test that fails for its own reasons proves nothing about
    /// the code, and this one nearly did.
    fn nothing_was_sent(peer: UnixStream) -> Result<(), String> {
        peer.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let mut peer = peer;
        let mut buffer = [0u8; 64];
        loop {
            return match std::io::Read::read(&mut peer, &mut buffer) {
                Ok(0) => Ok(()),
                Ok(n) => Err(format!("{n} bytes arrived: {:?}", &buffer[..n])),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    Ok(())
                }
                // The test harness's own timer signal lands here and is not
                // the backend saying anything. Reported as a failure once,
                // which is the double being wrong about the code again.
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => Err(format!("reading the peer end: {e}")),
            };
        }
    }

    #[test]
    fn a_backend_we_did_not_spawn_is_not_told_to_shut_down() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let backend = backend_on(ours);
        assert!(backend.child.lock().unwrap().is_none(), "the fixture is a dialled backend");

        backend.shutdown();

        if let Err(what) = nothing_was_sent(theirs) {
            panic!("a daemon that did not start this backend sent it something: {what}");
        }
    }

    /// The other direction, so the test above cannot pass by the daemon never
    /// sending `Shutdown` to anything. A backend with a child is one this
    /// daemon started, and stopping it politely before killing it is the whole
    /// point of the frame.
    #[test]
    fn a_backend_we_did_spawn_is_told_to_shut_down() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let mut backend = backend_on(ours);
        // Any process will do: shutdown only reaps it. `true` has already
        // exited by the time we wait, which is the fast path through the loop.
        let child = std::process::Command::new("true")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn true");
        *backend.child.get_mut().unwrap() = Some(child);

        backend.shutdown();

        theirs.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut reader = BufReader::new(theirs);
        match frame::read_typed::<_, BackendRequest>(&mut reader) {
            Ok(Some(BackendRequest::Shutdown)) => {}
            other => panic!("expected a Shutdown frame, got {other:?}"),
        }
    }
}
