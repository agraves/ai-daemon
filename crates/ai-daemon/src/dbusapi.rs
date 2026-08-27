// SPDX-License-Identifier: Apache-2.0

//! The D-Bus control plane (§3, §12).
//!
//! Control traffic goes here and nothing else does. D-Bus gives us activation,
//! introspection and — the part that matters — a peer identity we did not have
//! to invent: the bus daemon already knows which process is on the other end
//! and will tell us. The throughput cost is irrelevant for "list the models"
//! and unacceptable for "stream a token", which is why the data plane is a
//! socket and the fd for it is the last thing `CreateSession` says.
//!
//! ## About the name
//!
//! The target is `org.freedesktop.AI1`, and this is not it. That namespace is
//! earned by taking the spec through freedesktop review, not claimed by
//! shipping under it, and shipping under it early would poison exactly the
//! standardisation this design exists to attempt. So the daemon owns
//! `io.github.agraves.AIDaemon1` until then, and will keep answering to it as
//! a compatibility alias afterwards.

use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ai_daemon_proto::frame::Usage;
use ai_daemon_proto::manifest::Manifest;
use zbus::interface;
use zbus::object_server::ObjectServer;
use zbus::zvariant::{OwnedValue, Value};

use crate::identity::{Class, Identity};
use crate::install;
use crate::policy::{Decision, CAP_MODEL_ADMIN, Limits};
use crate::registry::Store;
use crate::sched;
use crate::session;
use crate::state::{Daemon, Session};
use crate::unblock::unblock;
use crate::{info, warn};

pub const BUS_NAME: &str = "io.github.agraves.AIDaemon1";
pub const MANAGER_PATH: &str = "/io/github/agraves/AIDaemon1/Manager";

pub fn session_path(id: &str) -> String {
    format!("/io/github/agraves/AIDaemon1/session/{id}")
}

pub struct Manager {
    pub daemon: Arc<Daemon>,
}

/// May this caller speak for an application?
///
/// Exact names, and that is the whole point of this function existing rather
/// than a `starts_with` at the call site. It used to be a prefix test — the
/// real portal ships as `xdg-desktop-portal.service` and desktops add
/// `-gtk`, `-gnome` and `-kde` variants, so a prefix looked like the tidy way
/// to cover them. It is not: an unprivileged user can write
/// `~/.config/systemd/user/xdg-desktop-portal-anything.service`, and every
/// process they start under it would have been believed when it claimed to be
/// any application on the machine. The grant this function hands out is "name
/// any app you like", which is not a thing to hand out on a prefix.
///
/// The suffix is optional in the configured name purely so an administrator
/// can write `ai-daemon-portal` or `ai-daemon-portal.service` and mean the
/// same unit. Everything else must match to the character.
pub(crate) fn is_trusted_introducer(allowed: &[String], unit: Option<&str>, exe: Option<&str>) -> bool {
    let matches = |candidate: &str, name: &str| {
        candidate == name || candidate.strip_suffix(".service") == Some(name)
    };
    allowed.iter().any(|name| {
        let name = name.trim().trim_end_matches(".service");
        !name.is_empty()
            && (unit.is_some_and(|unit| matches(unit, name))
                || exe.is_some_and(|exe| matches(exe, name)))
    })
}

/// Narrow a caller's own limits to what it asked for, never past them.
///
/// This is what makes a session fd a *delegable* capability rather than just
/// a handle. §5's model is a supervisor opening a session under narrow policy
/// and passing the fd into a sandboxed child over `SCM_RIGHTS` — "the child
/// can think and can do nothing else" — and that is only safe if the
/// supervisor can hand over strictly less than it holds. Without attenuation
/// a session carries the *caller's* full allowance, so handing the fd to a
/// child hands the child everything the parent had, and `ai-run --no-tools`
/// would be a suggestion rather than a fact.
///
/// Every field here can only take away. The `min`s and the `&&` are the whole
/// mechanism, and they are why this can be exposed to any caller without a
/// permission check: asking for less than you are allowed needs no authority,
/// and asking for more silently gets you what you were already allowed.
///
/// Enforced for the life of the fd, not the request: the limits land on the
/// `Session`, which every turn reads. A child cannot widen them later because
/// there is no method that widens them at all.
fn attenuate(mut limits: Limits, options: &HashMap<String, OwnedValue>) -> Limits {
    if let Some(v) = options.get("max_tokens_per_minute").and_then(|v| u64::try_from(v.clone()).ok())
    {
        if v < limits.tokens_per_minute {
            // Recorded rather than just lowered. The identity's bucket is
            // shared by all of its sessions and already exists, so writing a
            // smaller number here would narrow nothing — the session needs a
            // bucket of its own, and this is what tells the worker to build
            // one.
            limits.session_rate = Some(v);
            limits.tokens_per_minute = v;
        }
    }
    if let Some(v) = options.get("max_sessions").and_then(|v| u32::try_from(v.clone()).ok()) {
        limits.max_sessions = limits.max_sessions.min(v);
    }
    if let Some(v) = options.get("daily_spend").and_then(|v| f64::try_from(v.clone()).ok()) {
        let asked = crate::policy::to_micros(v);
        // Zero means "no ceiling" everywhere else, so a caller asking for zero
        // is asking for no ceiling — which is a widening and is ignored. A
        // caller that genuinely wants to spend nothing asks for a very small
        // number, and gets refused on its first priced request.
        if asked > 0 {
            limits.daily_spend_micros = if limits.daily_spend_micros == 0 {
                asked
            } else {
                limits.daily_spend_micros.min(asked)
            };
        }
    }
    if options
        .get("no_tools")
        .and_then(|v| bool::try_from(v.clone()).ok())
        .unwrap_or(false)
    {
        limits.no_tools = true;
    }
    if let Some(models) = options
        .get("allowed_models")
        .and_then(|v| Vec::<String>::try_from(v.clone()).ok())
    {
        // The intersection, and `*` on either side means "whatever the other
        // one says". A caller cannot add a model it was not already permitted.
        limits.allowed_models = if limits.allowed_models.iter().any(|m| m == "*") {
            models
        } else {
            models
                .into_iter()
                .filter(|m| m == "*" || limits.allowed_models.iter().any(|a| a == m))
                .collect()
        };
    }
    if let Some(text) = options.get("prelude").and_then(|v| String::try_from(v.clone()).ok()) {
        // Appended, not replaced. A caller may add an instruction the child
        // cannot remove; it may not delete one the administrator wrote.
        if !text.trim().is_empty() {
            if limits.prelude.trim().is_empty() {
                limits.prelude = text;
            } else {
                limits.prelude = format!("{}\n{}", limits.prelude, text);
            }
        }
    }
    if options
        .get("mark_provenance")
        .and_then(|v| bool::try_from(v.clone()).ok())
        .unwrap_or(false)
    {
        // Only ever on: turning marking off is a widening.
        limits.mark_provenance = true;
    }
    limits
}

#[interface(name = "io.github.agraves.AIDaemon1.Manager")]
impl Manager {
    /// Every model this caller can see, system store plus their own.
    async fn list_models(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<Vec<HashMap<String, OwnedValue>>> {
        let uid = self.credentials(&header, connection).await.ok().map(|(uid, _)| uid);
        let mut out = Vec::new();
        for (manifest, store) in self.daemon.registry.list(uid) {
            out.push(model_dict(&manifest, store, self.daemon.backends.is_pinned(&manifest.name)));
        }
        Ok(out)
    }

    /// Alias or name in, concrete model name out. Apps should ask for
    /// `default`/`fast`/`embed` and let the machine's owner decide (§6).
    async fn resolve(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        alias: String,
    ) -> zbus::fdo::Result<String> {
        let uid = self.credentials(&header, connection).await.ok().map(|(uid, _)| uid);
        self.daemon
            .registry
            .resolve(&alias, uid)
            .map(|r| r.manifest.name)
            .map_err(zbus::fdo::Error::Failed)
    }

    async fn list_aliases(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<HashMap<String, String>> {
        let uid = self.credentials(&header, connection).await.ok().map(|(uid, _)| uid);
        Ok(self.daemon.registry.aliases(uid).into_iter().collect())
    }

    /// Create a session and hand back its object and its data socket.
    ///
    /// Deliberately cheap: identity, limits, a socketpair, a thread. No policy
    /// prompt and no weights are touched here, because both can take a long
    /// time and the bus thread is shared by every other caller on the machine.
    async fn create_session(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(object_server)] object_server: &ObjectServer,
        model: String,
        options: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<(zbus::zvariant::OwnedObjectPath, zbus::zvariant::OwnedFd)> {
        let identity = self.identity_of(&header, connection, &options).await?;
        if let Err(reason) = self.daemon.policy.gate(&identity) {
            self.daemon.audit.denied(&identity, "gate", &reason);
            return Err(zbus::fdo::Error::AccessDenied(reason));
        }
        let limits = self.daemon.policy.limits_for(&identity);

        let resolved = self
            .daemon
            .registry
            .resolve(&model, Some(identity.uid))
            .map_err(zbus::fdo::Error::Failed)?;

        if !limits.permits_model(&resolved.manifest.name) {
            let reason = format!(
                "{} may not use {}",
                identity.key(),
                resolved.manifest.name
            );
            self.daemon.audit.denied(&identity, "generate", &reason);
            return Err(zbus::fdo::Error::AccessDenied(reason));
        }

        self.daemon
            .policy
            .open_session(&identity, &limits)
            .map_err(zbus::fdo::Error::AccessDenied)?;
        // Armed from here to the last line. Everything below can fail, and
        // most of it fails only under resource exhaustion — which is exactly
        // when the accounting it would corrupt is the thing protecting the
        // daemon. sched.rs's Slot makes the same argument for decode slots.
        let mut slot = SessionSlot {
            daemon: &self.daemon,
            identity: &identity,
            session: None,
            armed: true,
        };

        // Narrowed to what the caller asked for, before anything is opened.
        // Everything downstream reads the session's limits, so this is the one
        // place that decides what the fd is worth for the rest of its life.
        let limits = attenuate(limits, &options);

        let class = options
            .get("priority")
            .and_then(|v| String::try_from(v.clone()).ok())
            .map(|s| sched::Class::parse(&s))
            .unwrap_or(sched::Class::Interactive);

        let requested_ctx = options
            .get("max_context")
            .and_then(|v| u32::try_from(v.clone()).ok())
            .unwrap_or(limits.max_context);
        let max_context = requested_ctx
            .min(limits.max_context)
            .min(if resolved.manifest.requirements.max_ctx == 0 {
                u32::MAX
            } else {
                resolved.manifest.requirements.max_ctx
            });

        // Spawning a backend that has not run yet means waiting for its
        // handshake, so it goes off the bus thread like everything else that
        // can take longer than a message round trip.
        let daemon = self.daemon.clone();
        let manifest = resolved.manifest.clone();
        let backend = match unblock(move || daemon.backends.for_manifest(&manifest, "generate")).await {
            Ok(Ok(backend)) => backend,
            Ok(Err(e)) => {
                self.daemon.policy.close_session(&identity);
                return Err(zbus::fdo::Error::Failed(e));
            }
            Err(()) => {
                self.daemon.policy.close_session(&identity);
                return Err(zbus::fdo::Error::Failed("backend startup panicked".into()));
            }
        };

        let (daemon_end, client_end) = UnixStream::pair()
            .map_err(|e| zbus::fdo::Error::Failed(format!("socketpair: {e}")))?;

        let id = self.daemon.next_session_id();
        let path = session_path(&id);
        // Built here rather than at the return: it is fallible, and a fallible
        // step after the worker has started is one the guard has already been
        // disarmed for.
        let object_path = zbus::zvariant::OwnedObjectPath::try_from(path.clone())
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        let session = Arc::new(Session {
            id: id.clone(),
            object_path: path.clone(),
            identity: identity.clone(),
            model: resolved.manifest.name.clone(),
            digest: resolved.manifest.digest.clone(),
            backend: backend.name.clone(),
            // The intersection, computed once. Order follows the manifest so
            // a client reading the hello sees the model's own vocabulary.
            capabilities: resolved
                .manifest
                .capabilities
                .iter()
                .filter(|claim| backend.can(claim))
                .cloned()
                .collect(),
            local: backend.info.local,
            class,
            max_context,
            created: std::time::Instant::now(),
            blob: resolved.blob.clone(),
            usage: Mutex::new(Usage::default()),
            attachment_bytes: AtomicU64::new(0),
            attachments: Mutex::new(HashMap::new()),
            current_req: Mutex::new(None),
            sink: Mutex::new(None),
            cancelled: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        });

        self.daemon.audit.session_start(
            &identity,
            &id,
            &resolved.manifest.name,
            &resolved.manifest.digest,
            backend.info.local,
        );
        self.daemon.insert_session(session.clone());
        // The guard owns it from here: a failure below now gives back the
        // count, the map entry, the bus object and a closing audit record.
        slot.session = Some(session.clone());

        object_server
            .at(path.as_str(), SessionObject { daemon: self.daemon.clone(), session: session.clone() })
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("registering the session object: {e}")))?;

        session::spawn(self.daemon.clone(), session, daemon_end, limits)
            .map_err(zbus::fdo::Error::Failed)?;

        info!(
            "session {id}: {} ({}) on {} via {} ({}, {})",
            identity.key(),
            identity.display(),
            resolved.manifest.name,
            backend.name,
            class.as_str(),
            match resolved.store {
                Store::System => "system store",
                Store::User => "user store",
            }
        );

        let fd = zbus::zvariant::OwnedFd::from(std::os::fd::OwnedFd::from(client_end));
        slot.disarm();
        Ok((object_path, fd))
    }

    fn list_sessions(&self) -> Vec<HashMap<String, OwnedValue>> {
        self.daemon
            .session_list()
            .iter()
            .map(|s| {
                let usage = s.usage.lock().unwrap().clone();
                dict([
                    ("id", str_value(&s.id)),
                    ("path", str_value(&s.object_path)),
                    ("identity", str_value(&s.identity.key())),
                    ("class", str_value(s.identity.class.as_str())),
                    ("model", str_value(&s.model)),
                    ("backend", str_value(&s.backend)),
                    ("priority", str_value(s.class.as_str())),
                    ("state", str_value(s.state())),
                    ("local", Value::Bool(s.local).try_into().unwrap()),
                    ("prompt_tokens", Value::U64(usage.prompt_tokens).try_into().unwrap()),
                    ("completion_tokens", Value::U64(usage.completion_tokens).try_into().unwrap()),
                    (
                        "attachment_bytes",
                        Value::U64(s.attachment_bytes.load(Ordering::Relaxed)).try_into().unwrap(),
                    ),
                ])
            })
            .collect()
    }

    /// Every remembered decision, so a user can see what they agreed to (§5).
    /// What each identity has spent in the rolling day, and against what.
    ///
    /// Not admin-gated: it says how much *you* are costing, in a currency the
    /// administrator named, and hiding that from the people it applies to
    /// would make a budget something you can only discover by exceeding it.
    fn spend(&self) -> Vec<(String, String, String)> {
        self.daemon
            .policy
            .spend_report()
            .into_iter()
            .map(|(identity, spent, ceiling)| {
                (
                    identity,
                    crate::policy::render_micros(spent),
                    if ceiling == 0 {
                        "no ceiling".to_string()
                    } else {
                        crate::policy::render_micros(ceiling)
                    },
                )
            })
            .collect()
    }

    /// The meter: per identity, tokens and money over the rolling day.
    ///
    /// Rows are (identity, tokens, spent micros, ceiling micros), heaviest
    /// first. Micros rather than rendered strings, unlike `Spend`, because
    /// this is the method a status-bar widget polls and a widget formats for
    /// its own space; `aidctl meter` renders the same rows for a terminal.
    fn usage(&self) -> Vec<(String, u64, u64, u64)> {
        self.daemon.policy.usage_report()
    }

    fn list_grants(&self) -> Vec<(String, String, String, u64, String)> {
        self.daemon
            .policy
            .list_grants()
            .into_iter()
            .map(|g| {
                (
                    g.identity,
                    g.capability,
                    match g.decision {
                        Decision::Allow => "allow".to_string(),
                        Decision::Deny => "deny".to_string(),
                    },
                    g.decided_at,
                    g.via,
                )
            })
            .collect()
    }

    async fn set_grant(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        identity: String,
        capability: String,
        allow: bool,
    ) -> zbus::fdo::Result<()> {
        self.require_admin(&header, connection).await?;
        if !crate::policy::ALL_CAPABILITIES.contains(&capability.as_str()) {
            return Err(zbus::fdo::Error::InvalidArgs(format!(
                "no such capability {capability:?}"
            )));
        }
        self.daemon.policy.set_grant(
            &identity,
            &capability,
            if allow { Decision::Allow } else { Decision::Deny },
            "admin",
        );
        Ok(())
    }

    /// Forget every grant for an identity. Live sessions it already holds are
    /// closed too — a revocation that leaves the current conversation running
    /// is not a revocation.
    async fn revoke(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        identity: String,
    ) -> zbus::fdo::Result<u32> {
        self.require_admin(&header, connection).await?;
        let removed = self.daemon.policy.revoke(&identity) as u32;
        for session in self.daemon.session_list() {
            if session.identity.key() == identity {
                close_session(&self.daemon, &session);
            }
        }
        Ok(removed)
    }

    /// Install a model. The fetch happens in `ai-daemon-fetch`, which has a
    /// network and no access to prompts; the digest is verified here, in the
    /// process that has prompts and no network (§9).
    async fn install_model(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        source: String,
        digest: String,
        name: String,
        options: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<String> {
        self.require_admin(&header, connection).await?;
        let options = install::Options {
            format: options.get("format").and_then(|v| String::try_from(v.clone()).ok()),
            backend: options.get("backend").and_then(|v| String::try_from(v.clone()).ok()),
            license: options.get("license").and_then(|v| String::try_from(v.clone()).ok()),
            max_ctx: options.get("max_ctx").and_then(|v| u32::try_from(v.clone()).ok()),
            capabilities: options
                .get("capabilities")
                .and_then(|v| Vec::<String>::try_from(v.clone()).ok()),
        };
        let daemon = self.daemon.clone();
        // Downloading gigabytes must not happen on the bus thread. It also
        // talks to systemd over the same connection this method arrived on,
        // so blocking here would deadlock rather than merely stall.
        let installed = unblock(move || install::install(&daemon, &source, &digest, &name, options))
            .await
            .map_err(|_| zbus::fdo::Error::Failed("the installer panicked".into()))?
            .map_err(zbus::fdo::Error::Failed)?;
        Ok(installed)
    }

    async fn remove_model(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        name: String,
    ) -> zbus::fdo::Result<()> {
        self.require_admin(&header, connection).await?;
        self.daemon.registry.remove(&name).map_err(zbus::fdo::Error::Failed)
    }

    async fn set_alias(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        alias: String,
        target: String,
    ) -> zbus::fdo::Result<()> {
        self.require_admin(&header, connection).await?;
        self.daemon.registry.resolve(&target, None).map_err(zbus::fdo::Error::Failed)?;
        self.daemon.registry.set_alias(&alias, &target).map_err(zbus::fdo::Error::Failed)
    }

    /// Keep a model resident regardless of idle unloading (§8).
    async fn pin_model(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        model: String,
        pinned: bool,
    ) -> zbus::fdo::Result<()> {
        self.require_admin(&header, connection).await?;
        let resolved = self
            .daemon
            .registry
            .resolve(&model, None)
            .map_err(zbus::fdo::Error::Failed)?;
        self.daemon.backends.pin(&resolved.manifest.name, pinned);
        if pinned {
            // Loading weights is minutes of disk, not microseconds of bus.
            let daemon = self.daemon.clone();
            // Read before the closure: `self` is borrowed for the method body and
            // the closure outlives it.
            let fallback_ctx = self.daemon.config.policy.max_context;
            unblock(move || {
                let backend = daemon.backends.for_manifest(&resolved.manifest, "generate")?;
                // A pinned load with no stated context takes the policy
                // default rather than a floor: pinning exists to have the
                // model warm for real sessions, and warming it at 512 tokens
                // means the first real session reloads it.
                let ctx = match resolved.manifest.requirements.default_ctx {
                    0 => fallback_ctx,
                    stated => stated,
                };
                backend.load(
                    &resolved.manifest.name,
                    &resolved.blob,
                    &resolved.manifest.digest,
                    ctx,
                )?;
                Ok::<(), String>(())
            })
            .await
            .map_err(|_| zbus::fdo::Error::Failed("pinning panicked".into()))?
            .map_err(zbus::fdo::Error::Failed)?;
        }
        Ok(())
    }

    /// Everything an operator wants when they ask "what is it doing".
    fn status(&self) -> HashMap<String, OwnedValue> {
        let (kv_used, kv_budget) = self.daemon.scheduler.kv_used();
        let backends: Vec<String> = self
            .daemon
            .backends
            .live()
            .iter()
            .map(|b| {
                format!(
                    "{} {} [{}] models={}",
                    b.name,
                    b.info.version,
                    b.info.capabilities.join(","),
                    b.loaded_models().len()
                )
            })
            .collect();
        let running: Vec<String> = self
            .daemon
            .scheduler
            .running()
            .into_iter()
            .map(|(s, class, paused)| format!("{s} {class}{}", if paused { " paused" } else { "" }))
            .collect();
        dict([
            ("version", str_value(env!("CARGO_PKG_VERSION"))),
            ("uptime_seconds", Value::U64(self.daemon.started.elapsed().as_secs()).try_into().unwrap()),
            ("idle_seconds", Value::U64(self.daemon.idle_for().as_secs()).try_into().unwrap()),
            ("sessions", Value::U32(self.daemon.sessions.lock().unwrap().len() as u32).try_into().unwrap()),
            ("kv_used_bytes", Value::U64(kv_used).try_into().unwrap()),
            ("kv_budget_bytes", Value::U64(kv_budget).try_into().unwrap()),
            ("consent_mode", str_value(&format!("{:?}", self.daemon.config.policy.consent).to_lowercase())),
            ("backends", Value::Array(backends.into()).try_into().unwrap()),
            ("running", Value::Array(running.into()).try_into().unwrap()),
            (
                "audit_log",
                str_value(
                    &self
                        .daemon
                        .audit
                        .path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "journal only".into()),
                ),
            ),
        ])
    }

    #[zbus(property)]
    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    #[zbus(property)]
    fn data_protocol(&self) -> u32 {
        ai_daemon_proto::DATA_PROTO
    }

    #[zbus(property)]
    fn backends(&self) -> Vec<String> {
        self.daemon.backends.configured()
    }
}

impl Manager {
    async fn credentials(
        &self,
        header: &zbus::message::Header<'_>,
        connection: &zbus::Connection,
    ) -> zbus::fdo::Result<(u32, i32)> {
        let sender = header
            .sender()
            .ok_or_else(|| zbus::fdo::Error::Failed("the message has no sender".into()))?;
        let proxy = zbus::fdo::DBusProxy::new(connection).await?;
        let creds = proxy
            .get_connection_credentials(zbus::names::BusName::Unique(sender.to_owned()))
            .await?;
        let uid = creds
            .unix_user_id()
            .ok_or_else(|| zbus::fdo::Error::Failed("the bus would not name the caller's uid".into()))?;
        let pid = creds.process_id().unwrap_or(0) as i32;
        Ok((uid, pid))
    }

    async fn identity_of(
        &self,
        header: &zbus::message::Header<'_>,
        connection: &zbus::Connection,
        options: &HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<Identity> {
        let (uid, pid) = self.credentials(header, connection).await?;
        let mut identity = Identity::from_pid_uid(pid, uid, uid, Class::Native);

        // A portal may speak for an app; nothing else may. The check is on who
        // is calling, not on what they claim to be calling for (§13).
        if let Some(app_id) = options.get("portal_app_id").and_then(|v| String::try_from(v.clone()).ok()) {
            // The unit carries this, not the executable: the portal runs as
            // the user, so its /proc entry is unreadable to us, while its
            // cgroup is world-readable and is not something it can choose.
            // The exe arm is a fallback for machines with no systemd user
            // session, and it is second for that reason.
            //
            // The list is configuration, not a constant, because there are two
            // implementations of this job — xdg-desktop-portal once the
            // interface is accepted upstream, ai-daemon-portal until then —
            // and an empty list is how a machine with no desktop turns the
            // whole path off.
            let allowed = &self.daemon.config.policy.portal_units;
            let looks_like_portal = is_trusted_introducer(
                allowed,
                identity.unit.as_deref(),
                identity.exe.as_deref(),
            );
            if !looks_like_portal {
                warn!(
                    "{} asserted portal_app_id={app_id} without being a portal; ignoring the claim",
                    identity.key()
                );
                return Err(zbus::fdo::Error::AccessDenied(
                    "only xdg-desktop-portal may assert an application identity".into(),
                ));
            }
            identity.class = Class::Portal;
            identity.app_id = Some(app_id);
            return Ok(identity);
        }

        // The OpenAI-compat shim introduces its own callers the same way, and
        // is trusted far less for it: everything it speaks for is Class::Shim,
        // the lowest-trust class in §5, because the programs behind it were
        // written for a server that had no policy at all.
        //
        // By uid, not by executable name: the daemon runs as its own user and
        // cannot read /proc/<pid>/exe for a process it does not own, so an exe
        // check here would refuse the real shim on every machine. The shim's
        // uid is the package's, and nothing else has it.
        let shim_user = self.daemon.config.policy.shim_user.trim();
        let is_shim = (!shim_user.is_empty()
            && crate::identity::uid_of_user(shim_user)
                .is_some_and(|shim_uid| identity.uid == shim_uid))
            || identity
                .unit
                .as_deref()
                .is_some_and(|unit| unit == "ai-daemon-shim.service");

        // Naming a client is gated on its own, not as a side effect of also
        // sending a peer pid.
        //
        // The first version only read shim_client inside the block below, so a
        // caller sending the name alone had it quietly dropped — safe, but
        // silent, and silence is the wrong answer to somebody trying to pick
        // their own identity. It is refused the way portal_app_id is, and for
        // the same reason: the attempt belongs in the log.
        if options.contains_key("shim_client") && !is_shim {
            warn!(
                "{} tried to name an HTTP client without being the shim; refusing",
                identity.key()
            );
            return Err(zbus::fdo::Error::AccessDenied(
                "only ai-daemon-shim may name an HTTP caller".into(),
            ));
        }

        if let Some(pid) = options.get("shim_peer_pid").and_then(|v| u32::try_from(v.clone()).ok()) {
            if !is_shim {
                warn!(
                    "{} asserted shim_peer_pid={pid} without being the shim; ignoring the claim",
                    identity.key()
                );
                return Err(zbus::fdo::Error::AccessDenied(
                    "only ai-daemon-shim may introduce an HTTP caller".into(),
                ));
            }
            let peer_uid = options
                .get("shim_peer_uid")
                .and_then(|v| u32::try_from(v.clone()).ok())
                .unwrap_or(identity.uid);
            identity = Identity::from_pid_uid(pid as i32, peer_uid, peer_uid, Class::Shim);
            // Whether the kernel named that peer, or the shim is describing
            // itself because loopback TCP would not say. Recorded rather than
            // inferred: the two produce identical-looking pids and only the
            // shim knows which it sent.
            identity.attested = options
                .get("shim_peer_attested")
                .and_then(|v| bool::try_from(v.clone()).ok())
                .unwrap_or(false);
            // A name the shim vouched for, from a token its caller presented.
            //
            // Taken only from the shim, checked above, and never from the
            // caller: the whole point is that the HTTP client does not get to
            // say who it is to the daemon. It stays Class::Shim — a shared
            // secret over loopback is not peer credentials and the trust class
            // should not move — but the grant, the rate limit and the
            // revocation are now per agent instead of shared by every HTTP
            // client on the machine.
            identity.client = options
                .get("shim_client")
                .and_then(|v| String::try_from(v.clone()).ok())
                .map(|name| name.trim().to_string())
                .filter(|name| {
                    !name.is_empty()
                        && name.len() <= 64
                        // Keyed on this, printed in prompts, written to the
                        // audit log: a name with a colon or a newline in it
                        // could forge a different identity's key or a second
                        // audit line.
                        && name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
                });
        }
        Ok(identity)
    }

    async fn require_admin(
        &self,
        header: &zbus::message::Header<'_>,
        connection: &zbus::Connection,
    ) -> zbus::fdo::Result<Identity> {
        let (uid, pid) = self.credentials(header, connection).await?;
        let identity = Identity::from_pid_uid(pid, uid, uid, Class::Native);
        // polkit may open a dialog and take as long as the user does, and the
        // question is asked over this same bus connection — so this must not
        // run on the bus thread, or the reply would need the thread it is
        // blocking in order to arrive.
        let policy = self.daemon.policy.clone();
        let subject = identity.clone();
        let outcome = unblock(move || policy.check(&subject, CAP_MODEL_ADMIN))
            .await
            .map_err(|_| zbus::fdo::Error::Failed("the authorisation check panicked".into()))?;
        match outcome {
            Ok(()) => Ok(identity),
            Err(reason) => {
                self.daemon.audit.denied(&identity, CAP_MODEL_ADMIN, &reason);
                Err(zbus::fdo::Error::AccessDenied(reason))
            }
        }
    }
}

/// Undoes a half-built session.
///
/// `CreateSession` takes a slot against the caller's `max_sessions` and then
/// does five more things that can fail: a socketpair, a session id, a bus
/// object, a worker thread. Every one of those used to return without giving
/// the slot back, and two of them left the session in the daemon's map with no
/// thread to serve it and an audit record saying it had started and never
/// ended — visible in `aidctl sessions` forever.
///
/// They are all resource-exhaustion paths, so they fire together, and after
/// `max_sessions` of them that identity is refused until the daemon restarts
/// even though nothing is actually open. Explicit cleanup at each `?` would
/// work today and would not survive the next step somebody adds in the middle,
/// which is the argument sched.rs's Slot already makes for decode slots.
struct SessionSlot<'a> {
    daemon: &'a Arc<Daemon>,
    identity: &'a Identity,
    /// Set once the session exists and is in the map; before that there is
    /// nothing to undo but the count.
    session: Option<Arc<Session>>,
    armed: bool,
}

impl SessionSlot<'_> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SessionSlot<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        match &self.session {
            // retire gives back the count as part of undoing everything else,
            // so the two branches are not doing different amounts of work.
            Some(session) => {
                warn!("session {} was abandoned before it began serving", session.id);
                session::retire(self.daemon, session);
            }
            None => self.daemon.policy.close_session(self.identity),
        }
    }
}

pub struct SessionObject {
    pub daemon: Arc<Daemon>,
    pub session: Arc<Session>,
}

#[interface(name = "io.github.agraves.AIDaemon1.Session")]
impl SessionObject {
    /// Stop the current generation. The session survives; its context does.
    fn cancel(&self) {
        session::cancel_in_flight(&self.daemon, &self.session);
    }

    fn close(&self) {
        close_session(&self.daemon, &self.session);
    }

    #[zbus(property)]
    fn identity(&self) -> String {
        self.session.identity.key()
    }

    #[zbus(property)]
    fn model(&self) -> String {
        self.session.model.clone()
    }

    #[zbus(property)]
    fn digest(&self) -> String {
        self.session.digest.clone()
    }

    #[zbus(property)]
    fn backend(&self) -> String {
        self.session.backend.clone()
    }

    /// False when the model runs somewhere other than this machine. Stated on
    /// every session rather than inferred, so a client can refuse (§7).
    #[zbus(property)]
    fn local(&self) -> bool {
        self.session.local
    }

    #[zbus(property)]
    fn priority(&self) -> String {
        self.session.class.as_str().to_string()
    }

    #[zbus(property)]
    fn state(&self) -> String {
        self.session.state().to_string()
    }

    #[zbus(property)]
    fn prompt_tokens(&self) -> u64 {
        self.session.usage.lock().unwrap().prompt_tokens
    }

    #[zbus(property)]
    fn completion_tokens(&self) -> u64 {
        self.session.usage.lock().unwrap().completion_tokens
    }

    #[zbus(property)]
    fn attachment_bytes(&self) -> u64 {
        self.session.attachment_bytes.load(Ordering::Relaxed)
    }
}

/// End a session from outside its own thread.
///
/// Shutting the socket down is what actually stops it: the thread is blocked
/// in `read`, and a flag it will not look at until the next frame is not a
/// close.
///
/// Cancelling is separate from closing and both are needed. Shutting the
/// socket stops the session *accepting* work; it does not stop the generation
/// already running, which would carry on to its token limit holding a decode
/// slot for a client that has been told the session is over.
pub fn close_session(daemon: &Daemon, session: &Arc<Session>) {
    session.closed.store(true, Ordering::Relaxed);
    session::cancel_in_flight(daemon, session);
    let sink = session.sink.lock().unwrap().clone();
    if let Some(sink) = sink {
        let _ = sink.lock().unwrap().shutdown(std::net::Shutdown::Both);
    }
}

/// Take a session's object off the bus. Called from the session thread as it
/// tears down, which is why it goes through the blocking connection.
pub fn unregister(daemon: &Daemon, path: &str) {
    let connection = daemon.bus.lock().unwrap().clone();
    let Some(connection) = connection else { return };
    let object_server = connection.object_server();
    match object_server.remove::<SessionObject, _>(path) {
        Ok(_) => {}
        Err(e) => warn!("could not unregister {path}: {e}"),
    }
}

fn model_dict(manifest: &Manifest, store: Store, pinned: bool) -> HashMap<String, OwnedValue> {
    dict([
        ("name", str_value(&manifest.name)),
        ("digest", str_value(&manifest.digest)),
        ("format", str_value(&manifest.format)),
        ("quantization", str_value(&manifest.quantization)),
        ("license", str_value(&manifest.license)),
        ("backend", str_value(&manifest.backend)),
        ("source", str_value(&manifest.source)),
        (
            "store",
            str_value(match store {
                Store::System => "system",
                Store::User => "user",
            }),
        ),
        ("pinned", Value::Bool(pinned).try_into().unwrap()),
        (
            "weights_bytes",
            Value::U64(manifest.requirements.weights_bytes).try_into().unwrap(),
        ),
        ("default_ctx", Value::U32(manifest.requirements.default_ctx).try_into().unwrap()),
        ("max_ctx", Value::U32(manifest.requirements.max_ctx).try_into().unwrap()),
        (
            "capabilities",
            Value::Array(manifest.capabilities.clone().into()).try_into().unwrap(),
        ),
    ])
}

fn dict<const N: usize>(entries: [(&str, OwnedValue); N]) -> HashMap<String, OwnedValue> {
    entries.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

fn str_value(text: &str) -> OwnedValue {
    Value::Str(text.into()).try_into().expect("a string is always convertible")
}

#[cfg(test)]
mod tests {
    /// The list of who may speak for an application is a privilege grant, and
    /// these are the shapes it must and must not accept.
    mod introducers {
        use super::super::is_trusted_introducer;

        fn allowed() -> Vec<String> {
            crate::config::default_portal_units()
        }

        #[test]
        fn the_shipped_portals_are_recognised_by_unit() {
            for unit in [
                "xdg-desktop-portal.service",
                "xdg-desktop-portal-gnome.service",
                "ai-daemon-portal.service",
            ] {
                assert!(
                    is_trusted_introducer(&allowed(), Some(unit), None),
                    "{unit} should be trusted"
                );
            }
        }

        /// The reason this is exact rather than a prefix.
        ///
        /// An unprivileged user can put any name they like in
        /// ~/.config/systemd/user, so a prefix test hands "assert any
        /// application identity on this machine" to anybody who can write a
        /// file in their own home directory.
        #[test]
        fn a_unit_that_merely_starts_with_a_trusted_name_is_not_trusted() {
            for impostor in [
                "xdg-desktop-portal-evil.service",
                "xdg-desktop-portalx.service",
                "ai-daemon-portal-mine.service",
                "app-flatpak-xdg-desktop-portal-1.scope",
            ] {
                assert!(
                    !is_trusted_introducer(&allowed(), Some(impostor), None),
                    "{impostor} must not be trusted"
                );
            }
        }

        #[test]
        fn the_executable_arm_is_exact_too() {
            assert!(is_trusted_introducer(&allowed(), None, Some("ai-daemon-portal")));
            assert!(!is_trusted_introducer(&allowed(), None, Some("ai-daemon-portal-evil")));
        }

        /// Emptying the list is how a machine with no desktop turns the whole
        /// path off, so it has to actually turn it off.
        #[test]
        fn an_empty_list_trusts_nothing() {
            assert!(!is_trusted_introducer(&[], Some("xdg-desktop-portal.service"), None));
            assert!(!is_trusted_introducer(
                &["".to_string(), "  ".to_string()],
                Some("xdg-desktop-portal.service"),
                None
            ));
        }

        /// An administrator writing either spelling means the same unit.
        #[test]
        fn the_service_suffix_is_optional_in_the_configured_name() {
            let with = vec!["ai-daemon-portal.service".to_string()];
            assert!(is_trusted_introducer(&with, Some("ai-daemon-portal.service"), None));
            assert!(is_trusted_introducer(&with, Some("ai-daemon-portal"), None));
        }
    }

    use super::*;
    use crate::identity::Class;
    use crate::policy::Limits;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ai-daemon-slot-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn daemon_in(dir: &std::path::Path) -> Arc<Daemon> {
        let mut config = crate::config::Config::default();
        config.daemon.state_dir = dir.to_path_buf();
        config.policy.gate_group = String::new();
        Daemon::new(config)
    }

    fn identity() -> Identity {
        Identity {
            class: Class::Native,
            uid: 4001,
            gid: 4001,
            pid: std::process::id() as i32,
            unit: None,
            app_id: None,
            exe: Some("test".into()),
            client: None,
            attested: false,
        }
    }

    fn one_session_only() -> Limits {
        Limits {
            max_context: 1024,
            max_sessions: 1,
            tokens_per_minute: 1000,
            daily_spend_micros: 0,
            prelude: String::new(),
            mark_provenance: false,
            no_tools: false,
            session_rate: None,
            allowed_models: vec!["*".into()],
        }
    }

    /// The leak. CreateSession takes a slot against max_sessions and then does
    /// several things that can fail; every one of them used to return without
    /// giving it back, so after max_sessions failures the identity was refused
    /// until the daemon restarted even though nothing was open. They are all
    /// resource-exhaustion paths, so they fail together.
    #[test]
    fn abandoning_a_half_built_session_gives_the_slot_back() {
        let dir = scratch("count");
        let daemon = daemon_in(&dir);
        let who = identity();
        let limits = one_session_only();

        daemon.policy.open_session(&who, &limits).unwrap();
        assert!(
            daemon.policy.open_session(&who, &limits).is_err(),
            "the limit is one, so the second must be refused"
        );

        // Fail before the session object even exists — the socketpair path.
        {
            let _slot = SessionSlot { daemon: &daemon, identity: &who, session: None, armed: true };
        }

        daemon
            .policy
            .open_session(&who, &limits)
            .expect("the abandoned slot must be available again");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// And a slot that was disarmed is a session that really is open, so it
    /// must still count. Without this the guard would just disable the limit.
    #[test]
    fn a_session_that_started_keeps_its_slot() {
        let dir = scratch("armed");
        let daemon = daemon_in(&dir);
        let who = identity();
        let limits = one_session_only();

        daemon.policy.open_session(&who, &limits).unwrap();
        {
            let mut slot =
                SessionSlot { daemon: &daemon, identity: &who, session: None, armed: true };
            slot.disarm();
        }
        assert!(
            daemon.policy.open_session(&who, &limits).is_err(),
            "a session that is actually running must still count against the limit"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Failing after the session is in the map left a phantom: no worker
    /// thread, no teardown, visible in list_sessions forever, holding an audit
    /// record that said it had started and never ended.
    #[test]
    fn abandoning_after_insertion_leaves_no_phantom() {
        let dir = scratch("phantom");
        let daemon = daemon_in(&dir);
        let who = identity();
        let limits = one_session_only();
        daemon.policy.open_session(&who, &limits).unwrap();

        let session = Arc::new(Session {
            id: "s-phantom".into(),
            object_path: "/test/s-phantom".into(),
            identity: who.clone(),
            model: "none".into(),
            digest: "sha256:0".into(),
            backend: "none".into(),
            capabilities: vec!["generate".into()],
            local: true,
            class: sched::Class::Interactive,
            max_context: 1024,
            created: std::time::Instant::now(),
            blob: dir.join("weights"),
            usage: Mutex::new(Usage::default()),
            attachment_bytes: AtomicU64::new(0),
            attachments: Mutex::new(HashMap::new()),
            current_req: Mutex::new(None),
            sink: Mutex::new(None),
            cancelled: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        });
        daemon.audit.session_start(&who, "s-phantom", "none", "sha256:0", true);
        daemon.insert_session(session.clone());
        assert_eq!(daemon.session_list().len(), 1);

        {
            let _slot = SessionSlot {
                daemon: &daemon,
                identity: &who,
                session: Some(session),
                armed: true,
            };
        }

        assert!(daemon.session_list().is_empty(), "it must not linger in list_sessions");
        assert!(daemon.session("s-phantom").is_none());
        daemon
            .policy
            .open_session(&who, &limits)
            .expect("and the slot must come back with it");

        // Every start gets an end, so an auditor never sees a session that
        // began and did not finish.
        let audit = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert_eq!(audit.matches("\"event\":\"session-start\"").count(), 1, "{audit}");
        assert_eq!(audit.matches("\"event\":\"session-end\"").count(), 1, "{audit}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
