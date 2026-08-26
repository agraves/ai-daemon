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
use std::time::Duration;

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
    child: Mutex<Child>,
    writer: Mutex<BufWriter<UnixStream>>,
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
        self.send(&BackendRequest::Load {
            model_id: model_id.to_string(),
            path: path.display().to_string(),
            digest: digest.to_string(),
            n_ctx,
        })?;
        // Loading multi-gigabyte weights from cold cache is genuinely slow;
        // five minutes is "the disk is broken", not "the model is big".
        match self.await_control(Duration::from_secs(300))? {
            BackendEvent::Loaded { model_id, kv_bytes_per_token, n_ctx } => {
                let loaded = LoadedModel { model_id: model_id.clone(), kv_bytes_per_token, n_ctx };
                self.loaded.lock().unwrap().insert(model_id, loaded.clone());
                Ok(loaded)
            }
            BackendEvent::Error { code, message, .. } => Err(format!("{code}: {message}")),
            other => Err(format!("unexpected reply to load: {other:?}")),
        }
    }

    pub fn unload(&self, model_id: &str) -> Result<(), String> {
        self.send(&BackendRequest::Unload { model_id: model_id.to_string() })?;
        match self.await_control(Duration::from_secs(60))? {
            BackendEvent::Unloaded { model_id } => {
                self.loaded.lock().unwrap().remove(&model_id);
                Ok(())
            }
            BackendEvent::Error { code, message, .. } => Err(format!("{code}: {message}")),
            other => Err(format!("unexpected reply to unload: {other:?}")),
        }
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

    fn await_control(&self, timeout: Duration) -> Result<BackendEvent, String> {
        self.control
            .lock()
            .unwrap()
            .recv_timeout(timeout)
            .map_err(|_| format!("backend {} did not answer within {timeout:?}", self.name))
    }

    pub fn shutdown(&self) {
        let _ = self.send(&BackendRequest::Shutdown);
        let mut child = self.child.lock().unwrap();
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
        let routed = match &event {
            BackendEvent::Token { req_id, .. }
            | BackendEvent::ToolCall { req_id, .. }
            | BackendEvent::Vectors { req_id, .. }
            | BackendEvent::Tokens { req_id, .. }
            | BackendEvent::Done { req_id, .. } => Some(*req_id),
            BackendEvent::Error { req_id, .. } => *req_id,
            _ => None,
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
