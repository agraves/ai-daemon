//! Grants, capabilities, limits, and the consent path (§5).
//!
//! Two things are deliberately separate here and are easy to confuse:
//!
//! * The **`ai` group** decides which *humans* may talk to the daemon at all.
//!   It is enforced by the mode on the socket, not by this file, because Unix
//!   groups are per-user and cannot answer a per-app question.
//! * The **grant table** below decides which *apps* may do what. This is the
//!   thing the localhost pattern has never had.
//!
//! Neither substitutes for the other, and a portal-mediated app bypasses the
//! group entirely — the portal connects on its behalf.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::{Config, Consent};
use crate::identity::Identity;
use crate::{info, warn};

/// Capabilities are coarse in v1, on purpose: a permission a user cannot hold
/// in their head is a permission they click through.
pub const CAP_GENERATE: &str = "generate";
pub const CAP_GENERATE_TOOLS: &str = "generate-tools";
pub const CAP_EMBED: &str = "embed";
pub const CAP_MODEL_ADMIN: &str = "model-admin";
/// Producing an image or a clip (§11). Separate from `generate` because a
/// user may reasonably let an app write text and not let it synthesise a
/// voice, and a permission that cannot be withheld on its own is not one.
pub const CAP_GENERATE_MEDIA: &str = "generate-media";

pub const ALL_CAPABILITIES: [&str; 5] = [
    CAP_GENERATE,
    CAP_GENERATE_TOOLS,
    CAP_GENERATE_MEDIA,
    CAP_EMBED,
    CAP_MODEL_ADMIN,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub identity: String,
    pub capability: String,
    pub decision: Decision,
    /// Seconds since the epoch. Written so `aidctl grants` can say when the
    /// user agreed to something they have since forgotten about.
    pub decided_at: u64,
    /// How the decision was reached: `polkit`, `config`, `admin`, `default`.
    pub via: String,
}

/// Effective limits for one identity: config defaults, then any `[[identity]]`
/// rule, applied in that order.
#[derive(Debug, Clone)]
pub struct Limits {
    pub max_context: u32,
    pub max_sessions: u32,
    pub tokens_per_minute: u64,
    /// Micro-units of currency per rolling day; zero means no ceiling.
    ///
    /// Integer micros rather than a float, because money that accumulates in
    /// f64 accumulates error too, and a ceiling that drifts is a ceiling
    /// nobody can reconcile against a bill. The config takes a decimal for
    /// ergonomics and it is converted once, here.
    pub daily_spend_micros: u64,
    /// Text prepended to every turn that the client cannot remove.
    pub prelude: String,
    /// Tag each part of a prompt with where it came from.
    pub mark_provenance: bool,
    pub allowed_models: Vec<String>,
}

impl Limits {
    pub fn permits_model(&self, model: &str) -> bool {
        self.allowed_models.iter().any(|m| m == "*" || m == model)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct GrantFile {
    #[serde(default)]
    grants: Vec<Grant>,
}

/// A rolling day. Not a calendar day: a calendar boundary needs a timezone,
/// and "the CI runner gets $2 a day" is a rate, not a date.
const SPEND_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// A decimal in the config becomes an integer here, once.
fn to_micros(units: f64) -> u64 {
    if !units.is_finite() || units <= 0.0 {
        return 0;
    }
    (units * 1_000_000.0).round() as u64
}

/// Micros back to something a person reads, to three decimal places — enough
/// for a tenth of a cent, which is the granularity these prices come in.
pub fn render_micros(micros: u64) -> String {
    format!("{:.3}", micros as f64 / 1_000_000.0)
}

/// Token bucket per identity. Refills continuously rather than per window, so
/// a client cannot burst the whole minute's allowance at the boundary.
///
/// Capacity is the per-minute rate, and deliberately not "one full turn".
///
/// That was tried. An agent resends its whole conversation every request, so
/// one turn can reserve most of a context window, and a rate below that
/// refuses the first legitimate turn — which is a real problem and this is not
/// the fix for it. Sizing the bucket to hold a turn makes every limit smaller
/// than a context window unenforceable: an administrator who writes
/// `tokens_per_minute = 50` means it, and would get a bucket of eight thousand.
/// The two cannot both be true, and enforcement is the one worth keeping.
///
/// What the daemon owes the other case is a *diagnosis* rather than a silent
/// accommodation, and `PolicyEngine::new` gives one: an identity whose
/// allowance is below one turn is named at startup, because otherwise the only
/// symptom is a 429 the client cannot act on — waiting does not help, the next
/// request is the same size.
struct Bucket {
    tokens: f64,
    capacity: f64,
    per_second: f64,
    last: Instant,
}

impl Bucket {
    fn new(per_minute: u64) -> Bucket {
        let capacity = per_minute.max(1) as f64;
        Bucket { tokens: capacity, capacity, per_second: capacity / 60.0, last: Instant::now() }
    }

    fn take(&mut self, n: u64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.per_second).min(self.capacity);
        if self.tokens >= n as f64 {
            self.tokens -= n as f64;
            true
        } else {
            false
        }
    }
}

pub struct PolicyEngine {
    config: Config,
    path: PathBuf,
    state: Mutex<PolicyState>,
    /// Set once the system bus connection exists, so consent can reach polkit.
    /// Absent in tests and in `consent = "deny"` installs, both of which
    /// resolve without asking anyone.
    polkit: Mutex<Option<zbus::blocking::Connection>>,
}

struct PolicyState {
    grants: HashMap<(String, String), Grant>,
    buckets: HashMap<String, Bucket>,
    sessions: HashMap<String, u32>,
    /// What each identity has spent, and when. Pruned to the window on every
    /// touch, so it holds a day of requests rather than a history.
    spend: HashMap<String, Vec<(Instant, u64)>>,
}

impl PolicyEngine {
    pub fn new(config: Config, state_dir: &Path) -> PolicyEngine {
        let path = state_dir.join("grants.json");
        let grants = load_grants(&path);
        info!("policy: {} remembered grant(s), consent mode {:?}", grants.len(), config.policy.consent);
        // An allowance that cannot cover one turn is a configuration that
        // refuses every turn, and the client cannot tell.
        //
        // The daemon reserves prompt plus max_tokens before generating, and
        // both are bounded by the context window — so an identity whose
        // per-minute allowance is below its context can be refused before its
        // first request, with a 429 that waiting does not fix because the next
        // request is the same size. It reads as "the service is busy" and is
        // actually "this will never work".
        //
        // Named here rather than worked around: an administrator who writes a
        // small number may mean it, and the bucket honours it. What they
        // should not have to do is discover the consequence from a client's
        // error message.
        let warn_if_starved = |who: &str, per_minute: u64, context: u32| {
            if per_minute < context as u64 {
                warn!(
                    "policy: {who} allows {per_minute} tokens/minute against a {context}-token \
                     context — one full turn reserves more than that, so requests near the \
                     window will be refused before they start. Raise tokens_per_minute above \
                     max_context, or lower max_context, if that is not intended."
                );
            }
        };
        warn_if_starved("the default", config.policy.tokens_per_minute, config.policy.max_context);
        for rule in &config.identities {
            let per_minute = rule.tokens_per_minute.unwrap_or(config.policy.tokens_per_minute);
            let context = rule.max_context.unwrap_or(config.policy.max_context);
            warn_if_starved(&rule.identity, per_minute, context);
        }
        PolicyEngine {
            config,
            path,
            state: Mutex::new(PolicyState {
                grants,
                buckets: HashMap::new(),
                sessions: HashMap::new(),
                spend: HashMap::new(),
            }),
            polkit: Mutex::new(None),
        }
    }

    /// The outer gate (section 4). Answers only "may this human use local
    /// inference", which is all a Unix group is capable of answering.
    ///
    /// Portal-introduced apps skip it, and that is deliberate: the portal
    /// connects on the app's behalf under its own credentials, so the gate has
    /// already been passed by the time an app id exists.
    pub fn gate(&self, identity: &Identity) -> Result<(), String> {
        let group = self.config.policy.gate_group.trim();
        if group.is_empty() || identity.class == crate::identity::Class::Portal {
            return Ok(());
        }
        let Some(gid) = crate::identity::gid_of_group(group) else {
            return Err(format!(
                "the {group} group does not exist on this machine, so nobody is permitted to use the daemon; \
                 create it (sysusers.d does this on install) or clear policy.gate_group"
            ));
        };
        // Note there is no root exception. Root can add itself to the group,
        // and the audit record should show that it did, rather than the daemon
        // quietly treating uid 0 as a member of everything.
        if crate::identity::groups_of_pid(identity.pid).contains(&gid) {
            Ok(())
        } else {
            Err(format!(
                "{} is not in the {group} group, which is the machine's gate on using local inference at all",
                identity.key()
            ))
        }
    }

    pub fn attach_bus(&self, conn: zbus::blocking::Connection) {
        *self.polkit.lock().unwrap() = Some(conn);
    }

    pub fn limits_for(&self, identity: &Identity) -> Limits {
        let defaults = &self.config.policy;
        let mut limits = Limits {
            max_context: defaults.max_context,
            max_sessions: defaults.max_sessions,
            tokens_per_minute: defaults.tokens_per_minute,
            daily_spend_micros: to_micros(defaults.daily_spend),
            prelude: defaults.prelude.clone(),
            mark_provenance: defaults.mark_provenance,
            allowed_models: defaults.allowed_models.clone(),
        };
        if let Some(rule) = self.config.rule_for(&identity.key()) {
            if let Some(v) = rule.max_context {
                limits.max_context = v;
            }
            if let Some(v) = rule.max_sessions {
                limits.max_sessions = v;
            }
            if let Some(v) = rule.tokens_per_minute {
                limits.tokens_per_minute = v;
            }
            if let Some(v) = rule.daily_spend {
                limits.daily_spend_micros = to_micros(v);
            }
            if let Some(v) = &rule.prelude {
                limits.prelude = v.clone();
            }
            if let Some(v) = rule.mark_provenance {
                limits.mark_provenance = v;
            }
            if let Some(v) = &rule.allowed_models {
                limits.allowed_models = v.clone();
            }
        }
        limits
    }

    /// Decide whether `identity` may use `capability`, asking the user if the
    /// answer is not already known.
    ///
    /// The order is: an explicit `[[identity]]` rule wins outright (an admin
    /// wrote it down); then a remembered grant; then consent. Config beats
    /// memory so that revoking in config actually revokes, rather than being
    /// shadowed by a grant the user clicked through last month.
    pub fn check(&self, identity: &Identity, capability: &str) -> Result<(), String> {
        if let Some(rule) = self.config.rule_for(&identity.key()) {
            if !rule.capabilities.is_empty() {
                return if rule.capabilities.iter().any(|c| c == capability) {
                    Ok(())
                } else {
                    Err(format!(
                        "{} is not granted {capability} by configuration",
                        identity.key()
                    ))
                };
            }
        }

        let key = (identity.key(), capability.to_string());
        if let Some(grant) = self.state.lock().unwrap().grants.get(&key) {
            return match grant.decision {
                Decision::Allow => Ok(()),
                // Say that this came out of the table rather than out of
                // polkit, because the two are indistinguishable from the
                // caller's side and the difference decides what to do next.
                // A remembered refusal is consulted *before* polkit and
                // short-circuits it, so an administrator who reads this as a
                // live answer will write a polkit rule, watch it change
                // nothing, and have no reason to suspect a cache.
                Decision::Deny => Err(format!(
                    "{} was denied {capability} by a decision remembered from {} — \
                     `aidctl grants` lists it and `aidctl revoke {}` clears it; \
                     until then it is answered here and polkit is not consulted",
                    identity.key(),
                    grant.via,
                    identity.key()
                )),
            };
        }

        // model-admin is never granted by a first-contact prompt on the
        // generate path; it goes to polkit as an admin action regardless of
        // consent mode, because "install this model" is a machine-wide act.
        let (decision, via) = if capability == CAP_MODEL_ADMIN {
            // Machine-wide, so it goes to polkit whatever the consent mode
            // says. An install that chose `consent = "allow"` for convenience
            // has not thereby made "install any weights you like" free.
            match self.ask_polkit(identity, "io.github.agraves.aidaemon.model-admin") {
                Ok(true) => (Decision::Allow, "polkit"),
                Ok(false) => (Decision::Deny, "polkit"),
                Err(e) => return Err(self.unreachable(identity, capability, &e)),
            }
        } else {
            match self.config.policy.consent {
                Consent::Deny => (Decision::Deny, "default"),
                Consent::Allow => (Decision::Allow, "config"),
                Consent::Polkit => {
                    let action = match capability {
                        CAP_EMBED => "io.github.agraves.aidaemon.embed",
                        CAP_GENERATE_TOOLS => "io.github.agraves.aidaemon.generate-tools",
                        CAP_GENERATE_MEDIA => "io.github.agraves.aidaemon.generate-media",
                        _ => "io.github.agraves.aidaemon.generate",
                    };
                    match self.ask_polkit(identity, action) {
                        Ok(true) => (Decision::Allow, "polkit"),
                        Ok(false) => (Decision::Deny, "polkit"),
                        Err(e) => return Err(self.unreachable(identity, capability, &e)),
                    }
                }
            }
        };

        let grant = Grant {
            identity: identity.key(),
            capability: capability.to_string(),
            decision,
            decided_at: now_secs(),
            via: via.to_string(),
        };
        info!(
            "policy: {} {} {capability} (via {via})",
            grant.identity,
            if decision == Decision::Allow { "granted" } else { "denied" }
        );
        self.remember(grant);

        match decision {
            Decision::Allow => Ok(()),
            Decision::Deny => Err(format!("{} may not {capability}", identity.key())),
        }
    }

    /// `Ok(answer)` is what the user (or an administrator's rule) said.
    /// `Err(reason)` means nobody could be asked, which is a different thing
    /// and must not be recorded as if somebody had answered.
    fn ask_polkit(&self, identity: &Identity, action: &str) -> Result<bool, String> {
        let guard = self.polkit.lock().unwrap();
        let Some(conn) = guard.as_ref() else {
            return Err("the daemon has no bus connection to reach polkit on".into());
        };
        crate::polkit::check_authorization(conn, identity, action)
    }

    /// Refuse, loudly, without remembering it.
    ///
    /// A machine with no polkit cannot ask the user, and refusing is the only
    /// answer that does not invent consent on their behalf. But writing that
    /// refusal into the grant table would make a daemon that happened to start
    /// before its authority deny that application forever, with no way for the
    /// user to see why — so this decides, and forgets.
    fn unreachable(&self, identity: &Identity, capability: &str, reason: &str) -> String {
        warn!(
            "policy: cannot ask anyone whether {} may {capability} ({reason}); refusing without recording a decision",
            identity.key()
        );
        format!("{} may not {capability}: no authority could be reached ({reason})", identity.key())
    }

    fn remember(&self, grant: Grant) {
        let mut state = self.state.lock().unwrap();
        state
            .grants
            .insert((grant.identity.clone(), grant.capability.clone()), grant);
        let snapshot: Vec<Grant> = state.grants.values().cloned().collect();
        drop(state);
        if let Err(e) = save_grants(&self.path, &snapshot) {
            warn!("policy: could not persist grants to {}: {e}", self.path.display());
        }
    }

    pub fn set_grant(&self, identity: &str, capability: &str, decision: Decision, via: &str) {
        self.remember(Grant {
            identity: identity.to_string(),
            capability: capability.to_string(),
            decision,
            decided_at: now_secs(),
            via: via.to_string(),
        });
    }

    pub fn list_grants(&self) -> Vec<Grant> {
        let mut grants: Vec<Grant> = self.state.lock().unwrap().grants.values().cloned().collect();
        grants.sort_by(|a, b| (&a.identity, &a.capability).cmp(&(&b.identity, &b.capability)));
        grants
    }

    /// Forget everything about an identity. Sessions it already holds are the
    /// caller's problem to close — revocation of a live capability is a
    /// session operation, not a policy one.
    pub fn revoke(&self, identity: &str) -> usize {
        let mut state = self.state.lock().unwrap();
        let before = state.grants.len();
        state.grants.retain(|(id, _), _| id != identity);
        state.buckets.remove(identity);
        let removed = before - state.grants.len();
        let snapshot: Vec<Grant> = state.grants.values().cloned().collect();
        drop(state);
        let _ = save_grants(&self.path, &snapshot);
        info!("policy: revoked {removed} grant(s) for {identity}");
        removed
    }

    /// Charge tokens against the identity's rate limit. `false` means the
    /// caller has spent its minute.
    pub fn charge_tokens(&self, identity: &Identity, limits: &Limits, n: u64) -> bool {
        let mut state = self.state.lock().unwrap();
        state
            .buckets
            .entry(identity.key())
            .or_insert_with(|| Bucket::new(limits.tokens_per_minute))
            .take(n)
    }

    /// What a request cost, in micro-units of currency.
    ///
    /// Priced from the administrator's table, because nothing else can price
    /// it: no endpoint publishes a rate the daemon could read, and a guessed
    /// one produces a ceiling nobody can reconcile with an invoice. A model
    /// with no entry is free, which is correct for a local one and is why this
    /// whole mechanism is inert on a machine that never configured a remote
    /// provider.
    pub fn price_of(&self, model: &str, prompt_tokens: u64, completion_tokens: u64) -> u64 {
        // An exact name beats the catch-all, so a wildcard can set a floor
        // without overriding the one model somebody costed properly.
        let price = self
            .config
            .prices
            .iter()
            .find(|p| p.model == model)
            .or_else(|| self.config.prices.iter().find(|p| p.model == "*"));
        let Some(price) = price else { return 0 };
        let micros = |per_mtok: f64, tokens: u64| -> u64 {
            if !per_mtok.is_finite() || per_mtok <= 0.0 {
                return 0;
            }
            // Rounded up. A fractional micro is a millionth of a currency
            // unit, and rounding it away would let a long run of small
            // requests spend for ever against a ceiling that never moves.
            (per_mtok * tokens as f64).ceil().max(0.0) as u64
        };
        micros(price.input_per_mtok, prompt_tokens)
            .saturating_add(micros(price.output_per_mtok, completion_tokens))
    }

    /// Record what a finished request cost. Returns the day's running total.
    ///
    /// Charged after the fact rather than reserved before it, because the cost
    /// is not known until the tokens exist. So a single request can carry the
    /// total past the ceiling — it cannot be refused halfway through on a
    /// price nobody could compute yet — and the next one is refused. The
    /// alternative is estimating, and an estimate wrong in the permissive
    /// direction is a ceiling that does not hold.
    pub fn charge_spend(&self, identity: &Identity, micros: u64) -> u64 {
        let mut state = self.state.lock().unwrap();
        let entry = state.spend.entry(identity.key()).or_default();
        let now = Instant::now();
        entry.retain(|(at, _)| now.duration_since(*at) < SPEND_WINDOW);
        if micros > 0 {
            entry.push((now, micros));
        }
        entry.iter().map(|(_, m)| *m).sum()
    }

    /// Has this identity already spent its day, on something that costs?
    ///
    /// The model matters, and getting that wrong is what the verification
    /// caught: a ceiling checked without it refused a local model to an
    /// identity that had spent its allowance on a hosted one. A spend cap is
    /// about a bill. A local model does not send one, so refusing it is not
    /// the spend cap's business — the token limit is what bounds local work,
    /// and it is still there.
    pub fn spend_permits(
        &self,
        identity: &Identity,
        limits: &Limits,
        model: &str,
    ) -> Result<(), String> {
        if limits.daily_spend_micros == 0 {
            return Ok(());
        }
        // Priced at one token of each, to ask "does this model cost anything
        // at all" without knowing yet how large the request will be.
        if self.price_of(model, 1, 1) == 0 {
            return Ok(());
        }
        let spent = self.spent_by(&identity.key());
        if spent >= limits.daily_spend_micros {
            return Err(format!(
                "{} has spent {} of its {} daily allowance; the window is a rolling 24 hours, \
                 so this clears as the oldest requests age out",
                identity.key(),
                render_micros(spent),
                render_micros(limits.daily_spend_micros)
            ));
        }
        Ok(())
    }

    /// What an identity has spent inside the window.
    pub fn spent_by(&self, key: &str) -> u64 {
        let mut state = self.state.lock().unwrap();
        let Some(entry) = state.spend.get_mut(key) else { return 0 };
        let now = Instant::now();
        entry.retain(|(at, _)| now.duration_since(*at) < SPEND_WINDOW);
        entry.iter().map(|(_, m)| *m).sum()
    }

    /// Everyone who has spent anything in the window, with their ceiling.
    ///
    /// Reported rather than left to be discovered at the refusal: "how much
    /// have I spent today" is the first question anybody asks after setting a
    /// cap, and an answer that only arrives when the cap bites is not one.
    pub fn spend_report(&self) -> Vec<(String, u64, u64)> {
        let keys: Vec<String> = self.state.lock().unwrap().spend.keys().cloned().collect();
        let mut rows: Vec<(String, u64, u64)> = keys
            .into_iter()
            .map(|key| {
                let spent = self.spent_by(&key);
                let ceiling = self
                    .config
                    .rule_for(&key)
                    .and_then(|rule| rule.daily_spend)
                    .map(to_micros)
                    .unwrap_or_else(|| to_micros(self.config.policy.daily_spend));
                (key, spent, ceiling)
            })
            .filter(|(_, spent, ceiling)| *spent > 0 || *ceiling > 0)
            .collect();
        // Biggest spender first: that is who somebody is looking for.
        rows.sort_by_key(|row| std::cmp::Reverse(row.1));
        rows
    }

    pub fn open_session(&self, identity: &Identity, limits: &Limits) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        let count = state.sessions.entry(identity.key()).or_insert(0);
        if *count >= limits.max_sessions {
            return Err(format!(
                "{} already holds {} of {} permitted sessions",
                identity.key(),
                count,
                limits.max_sessions
            ));
        }
        *count += 1;
        Ok(())
    }

    pub fn close_session(&self, identity: &Identity) {
        let mut state = self.state.lock().unwrap();
        if let Some(count) = state.sessions.get_mut(&identity.key()) {
            *count = count.saturating_sub(1);
        }
    }
}

fn load_grants(path: &Path) -> HashMap<(String, String), Grant> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return HashMap::new();
    };
    match serde_json::from_str::<GrantFile>(&text) {
        Ok(file) => file
            .grants
            .into_iter()
            .map(|g| ((g.identity.clone(), g.capability.clone()), g))
            .collect(),
        Err(e) => {
            warn!("policy: {} is unreadable ({e}); starting with no grants", path.display());
            HashMap::new()
        }
    }
}

/// Write via a temporary file and rename, so a crash mid-write leaves the old
/// grant table rather than an empty one. An empty grant table fails closed,
/// but it also silently forgets what the user agreed to, and that is its own
/// kind of wrong.
fn save_grants(path: &Path, grants: &[Grant]) -> std::io::Result<()> {
    let mut sorted = grants.to_vec();
    sorted.sort_by(|a, b| (&a.identity, &a.capability).cmp(&(&b.identity, &b.capability)));
    let text = serde_json::to_string_pretty(&GrantFile { grants: sorted })
        .map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Class;

    fn identity(uid: u32) -> Identity {
        Identity {
            class: Class::Native,
            uid,
            gid: uid,
            pid: std::process::id() as i32,
            unit: None,
            app_id: None,
            exe: Some("aidctl".into()),
            client: None,
        }
    }

    fn engine(consent: Consent, dir: &Path) -> PolicyEngine {
        let mut config = Config::default();
        config.policy.consent = consent;
        config.policy.gate_group = String::new();
        PolicyEngine::new(config, dir)
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ai-daemon-policy-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_bucket_refills_continuously_rather_than_at_a_window_edge() {
        // 6000 a minute is 100 a second, so a fifth of a second is worth 20.
        let mut bucket = Bucket::new(6000);
        assert!(bucket.take(6000), "the first minute's worth is available up front");
        assert!(!bucket.take(50), "and then it is spent");
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            bucket.take(10),
            "a continuous refill means a client does not wait for a window boundary"
        );
        assert!(!bucket.take(6000), "but the refill is a trickle, not a reset");
    }

    /// A small allowance means a small allowance.
    ///
    /// This was briefly not true: the bucket was sized to hold one full
    /// context window so an agent's first turn could never be refused, which
    /// made every limit below a window unenforceable — 50 a minute became
    /// eight thousand. An administrator who writes a small number means it,
    /// and the diagnosis for the other case belongs in the log at startup, not
    /// in the arithmetic here.
    #[test]
    fn a_tight_allowance_refuses_a_request_larger_than_itself() {
        let mut bucket = Bucket::new(50);
        assert!(
            !bucket.take(500),
            "a request ten times the whole minute must not be admitted"
        );
        assert!(bucket.take(50), "while what the limit does permit still goes through");
    }

    /// Refusing and *remembering* the refusal are different things. A daemon
    /// that started before its authority did would otherwise deny that
    /// application forever, with nothing in the grant table explaining why.
    #[test]
    fn an_unreachable_polkit_refuses_without_recording_a_decision() {
        let dir = scratch("polkit");
        let policy = engine(Consent::Polkit, &dir);
        let error = policy.check(&identity(1000), CAP_GENERATE).unwrap_err();
        assert!(error.contains("no authority could be reached"), "{error}");
        assert!(
            policy.list_grants().is_empty(),
            "a machine that cannot ask the user must not answer for them, in either direction"
        );

        // And the next attempt asks again rather than reading back its own
        // shrug from last time.
        assert!(policy.check(&identity(1000), CAP_GENERATE).is_err());
        assert!(policy.list_grants().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn grants_survive_a_restart() {
        let dir = scratch("persist");
        {
            let policy = engine(Consent::Allow, &dir);
            policy.check(&identity(1000), CAP_GENERATE).unwrap();
        }
        let policy = engine(Consent::Deny, &dir);
        assert!(
            policy.check(&identity(1000), CAP_GENERATE).is_ok(),
            "the remembered grant outlives the process that recorded it"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An administrator writing a rule down must beat a dialog the user
    /// clicked through last month, or revoking in configuration silently does
    /// nothing.
    #[test]
    fn a_configured_rule_overrides_a_remembered_grant() {
        let dir = scratch("override");
        let policy = engine(Consent::Allow, &dir);
        policy.check(&identity(1000), CAP_GENERATE).unwrap();

        let mut config = Config::default();
        config.policy.consent = Consent::Allow;
        config.policy.gate_group = String::new();
        config.identities.push(crate::config::IdentityRule {
            identity: identity(1000).key(),
            capabilities: vec![CAP_EMBED.to_string()],
            max_context: None,
            max_sessions: None,
            tokens_per_minute: None,
            daily_spend: None,
            prelude: None,
            mark_provenance: None,
            allowed_models: None,
        });
        let policy = PolicyEngine::new(config, &dir);
        assert!(policy.check(&identity(1000), CAP_EMBED).is_ok());
        assert!(
            policy.check(&identity(1000), CAP_GENERATE).is_err(),
            "configuration is the stronger statement"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn model_admin_never_falls_out_of_a_permissive_consent_mode() {
        let dir = scratch("admin");
        let policy = engine(Consent::Allow, &dir);
        assert!(policy.check(&identity(1000), CAP_GENERATE).is_ok());
        assert!(
            policy.check(&identity(1000), CAP_MODEL_ADMIN).is_err(),
            "installing a model is machine-wide and goes to polkit regardless"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn revocation_forgets_every_capability_for_one_identity_only() {
        let dir = scratch("revoke");
        let policy = engine(Consent::Allow, &dir);
        policy.check(&identity(1000), CAP_GENERATE).unwrap();
        policy.check(&identity(1000), CAP_EMBED).unwrap();
        policy.check(&identity(1001), CAP_GENERATE).unwrap();

        assert_eq!(policy.revoke(&identity(1000).key()), 2);
        assert_eq!(policy.list_grants().len(), 1);
        assert_eq!(policy.list_grants()[0].identity, identity(1001).key());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_session_cap_is_per_identity_and_releases() {
        let dir = scratch("sessions");
        let policy = engine(Consent::Allow, &dir);
        let limits = Limits {
            max_context: 4096,
            max_sessions: 2,
            tokens_per_minute: 100,
            daily_spend_micros: 0,
            prelude: String::new(),
            mark_provenance: false,
            allowed_models: vec!["*".into()],
        };
        policy.open_session(&identity(1000), &limits).unwrap();
        policy.open_session(&identity(1000), &limits).unwrap();
        assert!(policy.open_session(&identity(1000), &limits).is_err());
        policy.open_session(&identity(1001), &limits).unwrap();

        policy.close_session(&identity(1000));
        assert!(policy.open_session(&identity(1000), &limits).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_model_allow_list_is_checked_after_alias_resolution() {
        let limits = Limits {
            max_context: 4096,
            max_sessions: 2,
            tokens_per_minute: 100,
            daily_spend_micros: 0,
            prelude: String::new(),
            mark_provenance: false,
            allowed_models: vec!["small".into()],
        };
        assert!(limits.permits_model("small"));
        assert!(
            !limits.permits_model("default"),
            "otherwise an app dodges the list by asking for an alias"
        );
    }

    #[test]
    fn the_gate_refuses_when_the_group_does_not_exist() {
        let dir = scratch("gate");
        let mut config = Config::default();
        config.policy.gate_group = "definitely-not-a-real-group".into();
        let policy = PolicyEngine::new(config, &dir);
        let error = policy.gate(&identity(1000)).unwrap_err();
        assert!(error.contains("does not exist"), "{error}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_portal_introduced_app_is_past_the_gate_already() {
        let dir = scratch("gate-portal");
        let mut config = Config::default();
        config.policy.gate_group = "definitely-not-a-real-group".into();
        let policy = PolicyEngine::new(config, &dir);
        let mut app = identity(1000);
        app.class = Class::Portal;
        app.app_id = Some("org.gnome.Newelle".into());
        assert!(
            policy.gate(&app).is_ok(),
            "the portal connected on its behalf and has already passed the gate"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
