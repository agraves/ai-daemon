//! Everything the daemon is, in one place the D-Bus layer and the session
//! threads can both hold.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ai_daemon_proto::backend::RawAttachment;
use ai_daemon_proto::frame::Usage;
use ai_daemon_proto::manifest::Manifest;

use crate::audit::Audit;
use crate::backend::Backend;
use crate::config::Config;
use crate::identity::Identity;
use crate::policy::PolicyEngine;
use crate::registry::Registry;
use crate::sched::{Class, Preemptor, Scheduler};
use crate::{error, info, warn};

/// Live backends, spawned on demand and respawned if they die.
///
/// Lazy because a desktop that has not asked for inference today should not be
/// holding a CUDA context; the daemon is bus-activated for the same reason.
pub struct Backends {
    specs: Vec<crate::config::Backend>,
    live: Mutex<HashMap<String, Arc<Backend>>>,
    /// Models an admin has pinned resident (§8), by model name.
    pinned: Mutex<HashSet<String>>,
}

impl Backends {
    pub fn new(specs: Vec<crate::config::Backend>) -> Backends {
        Backends {
            specs: specs.into_iter().filter(|s| s.enabled).collect(),
            live: Mutex::new(HashMap::new()),
            pinned: Mutex::new(HashSet::new()),
        }
    }

    pub fn configured(&self) -> Vec<String> {
        self.specs.iter().map(|s| s.name.clone()).collect()
    }

    pub fn get(&self, name: &str) -> Result<Arc<Backend>, String> {
        {
            let live = self.live.lock().unwrap();
            if let Some(backend) = live.get(name) {
                if backend.alive() {
                    return Ok(backend.clone());
                }
            }
        }
        let spec = self
            .specs
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| format!("no backend named {name:?} is configured"))?;
        let backend = Arc::new(Backend::spawn(spec)?);
        self.live.lock().unwrap().insert(name.to_string(), backend.clone());
        Ok(backend)
    }

    /// Pick the backend that should serve `manifest`: the one it names, or the
    /// first configured backend that reads the format and offers `capability`.
    pub fn for_manifest(&self, manifest: &Manifest, capability: &str) -> Result<Arc<Backend>, String> {
        if !manifest.backend.is_empty() {
            let backend = self.get(&manifest.backend)?;
            if !backend.can(capability) {
                return Err(format!(
                    "backend {} cannot {capability}",
                    manifest.backend
                ));
            }
            return Ok(backend);
        }
        let mut last_error = String::from("no backend is configured");
        for spec in &self.specs {
            match self.get(&spec.name) {
                Ok(backend) => {
                    if backend.handles_format(&manifest.format) && backend.can(capability) {
                        return Ok(backend);
                    }
                    last_error = format!(
                        "backend {} handles {:?} and can {:?}",
                        spec.name, backend.info.formats, backend.info.capabilities
                    );
                }
                Err(e) => {
                    warn!("backend {}: {e}", spec.name);
                    last_error = e;
                }
            }
        }
        Err(format!(
            "no backend reads {} with capability {capability} ({last_error})",
            manifest.format
        ))
    }

    pub fn live(&self) -> Vec<Arc<Backend>> {
        self.live.lock().unwrap().values().cloned().collect()
    }

    pub fn pin(&self, model: &str, pinned: bool) {
        let mut set = self.pinned.lock().unwrap();
        if pinned {
            set.insert(model.to_string());
        } else {
            set.remove(model);
        }
    }

    pub fn is_pinned(&self, model: &str) -> bool {
        self.pinned.lock().unwrap().contains(model)
    }

    pub fn shutdown(&self) {
        for backend in self.live.lock().unwrap().values() {
            backend.shutdown();
        }
    }
}

impl Preemptor for Backends {
    fn set_paused(&self, backend: &str, req_id: u64, paused: bool) {
        if let Some(handle) = self.live.lock().unwrap().get(backend) {
            if paused {
                handle.pause(req_id);
            } else {
                handle.resume(req_id);
            }
        }
    }

    fn drop_cache(&self, backend: &str, session: &str) {
        if let Some(handle) = self.live.lock().unwrap().get(backend) {
            handle.drop_cache(session);
        }
    }
}

/// A session as the rest of the daemon sees it. The socket and the message
/// history live on the session's own thread; this is the part D-Bus and the
/// scheduler are allowed to touch.
pub struct Session {
    pub id: String,
    pub object_path: String,
    pub identity: Identity,
    pub model: String,
    pub digest: String,
    pub backend: String,
    pub local: bool,
    pub class: Class,
    pub max_context: u32,
    pub created: Instant,
    /// The verified weights file. Held so the session thread can load the
    /// model without going back to the registry, and so a model removed
    /// mid-session does not change what this session is running.
    pub blob: std::path::PathBuf,
    pub usage: Mutex<Usage>,
    pub attachment_bytes: AtomicU64,
    pub attachments: Mutex<HashMap<String, RawAttachment>>,
    /// The client end of the data socket, kept so another session's thread
    /// can deliver an out-of-band notice (a `context-evicted`, say) without
    /// waking this one.
    pub sink: Mutex<Option<crate::session::Sink>>,
    /// The backend request currently streaming, if any. `Session.Cancel()`
    /// over D-Bus reaches into this rather than racing the session thread.
    pub current_req: Mutex<Option<u64>>,
    pub cancelled: AtomicBool,
    pub closed: AtomicBool,
}

impl Session {
    pub fn state(&self) -> &'static str {
        if self.closed.load(Ordering::Relaxed) {
            "closed"
        } else if self.current_req.lock().unwrap().is_some() {
            "generating"
        } else {
            "idle"
        }
    }
}

pub struct Daemon {
    pub config: Config,
    /// Set once the bus is up. Session threads use the blocking object server
    /// through this to unregister themselves; the async one belongs to the
    /// executor thread and is not theirs to touch.
    pub bus: Mutex<Option<zbus::blocking::Connection>>,
    pub policy: Arc<PolicyEngine>,
    pub registry: Arc<Registry>,
    pub scheduler: Arc<Scheduler>,
    pub audit: Arc<Audit>,
    pub backends: Arc<Backends>,
    pub sessions: Mutex<HashMap<String, Arc<Session>>>,
    next_session: AtomicU64,
    last_activity: Mutex<Instant>,
    pub started: Instant,
}

impl Daemon {
    pub fn new(config: Config) -> Arc<Daemon> {
        let state_dir = config.daemon.state_dir.clone();
        let _ = std::fs::create_dir_all(&state_dir);
        let policy = Arc::new(PolicyEngine::new(config.clone(), &state_dir));
        let registry = Arc::new(Registry::new(&state_dir, config.aliases.clone()));
        let scheduler = Arc::new(Scheduler::new(&config.scheduler));
        let audit = Arc::new(Audit::new(&state_dir));
        let backends = Arc::new(Backends::new(config.backends.clone()));
        scheduler.set_preemptor(backends.clone());
        Arc::new(Daemon {
            config,
            bus: Mutex::new(None),
            policy,
            registry,
            scheduler,
            audit,
            backends,
            sessions: Mutex::new(HashMap::new()),
            next_session: AtomicU64::new(1),
            last_activity: Mutex::new(Instant::now()),
            started: Instant::now(),
        })
    }

    pub fn touch(&self) {
        *self.last_activity.lock().unwrap() = Instant::now();
    }

    pub fn idle_for(&self) -> Duration {
        self.last_activity.lock().unwrap().elapsed()
    }

    pub fn next_session_id(&self) -> String {
        format!("s{}", self.next_session.fetch_add(1, Ordering::Relaxed))
    }

    pub fn session(&self, id: &str) -> Option<Arc<Session>> {
        self.sessions.lock().unwrap().get(id).cloned()
    }

    pub fn insert_session(&self, session: Arc<Session>) {
        self.touch();
        self.sessions.lock().unwrap().insert(session.id.clone(), session);
    }

    pub fn remove_session(&self, id: &str) -> Option<Arc<Session>> {
        self.touch();
        self.sessions.lock().unwrap().remove(id)
    }

    pub fn session_list(&self) -> Vec<Arc<Session>> {
        let mut list: Vec<Arc<Session>> = self.sessions.lock().unwrap().values().cloned().collect();
        list.sort_by_key(|s| s.created);
        list
    }

    /// Housekeeping: unload models nothing is using, and exit when the machine
    /// has stopped asking (§4). Bus activation brings us back.
    pub fn spawn_janitor(self: &Arc<Self>) {
        let daemon = self.clone();
        std::thread::Builder::new()
            .name("janitor".into())
            .spawn(move || loop {
                std::thread::sleep(Duration::from_secs(5));
                daemon.unload_idle_models();
                let idle_exit = daemon.config.daemon.idle_exit_seconds;
                if idle_exit == 0 {
                    continue;
                }
                let no_sessions = daemon.sessions.lock().unwrap().is_empty();
                let no_models = daemon
                    .backends
                    .live()
                    .iter()
                    .all(|b| b.loaded_models().is_empty());
                if no_sessions && no_models && daemon.idle_for() > Duration::from_secs(idle_exit) {
                    info!("idle for {idle_exit}s with no sessions and no models; exiting");
                    daemon.backends.shutdown();
                    std::process::exit(0);
                }
            })
            .map(|_| ())
            .unwrap_or_else(|e| error!("could not start the janitor thread: {e}"));
    }

    fn unload_idle_models(&self) {
        let timeout = self.config.daemon.model_idle_unload_seconds;
        if timeout == 0 {
            return;
        }
        if self.idle_for() < Duration::from_secs(timeout) {
            return;
        }
        let in_use: HashSet<String> = self
            .sessions
            .lock()
            .unwrap()
            .values()
            .map(|s| s.model.clone())
            .collect();
        for backend in self.backends.live() {
            for loaded in backend.loaded_models() {
                if in_use.contains(&loaded.model_id) || self.backends.is_pinned(&loaded.model_id) {
                    continue;
                }
                info!("unloading {} from {} after {timeout}s idle", loaded.model_id, backend.name);
                if let Err(e) = backend.unload(&loaded.model_id) {
                    warn!("unload {}: {e}", loaded.model_id);
                }
            }
        }
    }
}
