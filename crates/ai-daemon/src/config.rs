//! `/etc/ai-daemon/config.toml` and its drop-ins.
//!
//! Everything here has a default that produces a working, closed-by-default
//! service, so an install with no config file at all still starts and still
//! refuses callers it has not been told about. The one setting with no safe
//! default is which backends may run, and that ships as a packaged drop-in
//! rather than being inferred.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub daemon: Daemon,
    pub policy: Policy,
    pub scheduler: Scheduler,
    pub attachments: Attachments,
    /// Alias -> model name (§6). Overridable per user by their own store.
    pub aliases: BTreeMap<String, String>,
    #[serde(rename = "backend")]
    pub backends: Vec<Backend>,
    /// Per-identity overrides, keyed by the identity string `aidctl grants`
    /// prints. A missing entry means the `[policy]` defaults apply.
    #[serde(rename = "identity")]
    pub identities: Vec<IdentityRule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Daemon {
    pub state_dir: PathBuf,
    pub runtime_dir: PathBuf,
    /// Exit after this long with no sessions and no loaded models. Zero
    /// disables idle exit, which is what you want when debugging and never
    /// what you want in production (§4).
    pub idle_exit_seconds: u64,
    /// Unload a model this long after its last session closed (§8).
    pub model_idle_unload_seconds: u64,
    /// Where `ai-daemon-fetch` and `ai-daemon-decode` live. Separate from
    /// `$PATH` on purpose: these are private helpers, not commands.
    pub libexec_dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    /// How a first-contact request from an unknown identity is decided:
    ///
    /// * `polkit` — ask polkit, which asks the user. The install default.
    /// * `deny` — refuse; only identities granted out-of-band may proceed.
    ///   Correct for headless machines with no agent to render a dialog.
    /// * `allow` — grant on first contact and record it. This is the
    ///   localhost free-for-all with an audit log, and it is here so that a
    ///   test rig can be honest about choosing it (§5).
    pub consent: Consent,
    /// The coarse outer gate from section 4: which *humans* may talk to the
    /// daemon at all. Empty disables it.
    ///
    /// The design describes this as the mode on a native data socket. There is
    /// no listening socket here — sessions arrive as descriptors passed over
    /// D-Bus, which is strictly better, since the bus names the peer for us —
    /// so the same check lives in the daemon instead: is the caller in this
    /// group. It answers nothing about *which app*; that is the grant table's
    /// job, and confusing the two is the mistake this comment exists to stop.
    pub gate_group: String,
    /// The user the OpenAI-compatible shim runs as. A caller with this uid is
    /// allowed to introduce the HTTP client behind it (§5, §12) — and only
    /// that: everything it speaks for lands in the lowest trust class.
    ///
    /// Matched on uid rather than on the executable because a daemon running
    /// as its own user cannot read another user's `/proc/<pid>/exe`, so an
    /// exe check would be a check that quietly never passes.
    pub shim_user: String,
    pub max_context: u32,
    pub max_sessions: u32,
    pub tokens_per_minute: u64,
    /// Model names, or `*`. Checked after alias resolution, so a policy cannot
    /// be dodged by asking for `default`.
    pub allowed_models: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Consent {
    Polkit,
    Deny,
    Allow,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Scheduler {
    /// Global ceiling on KV cache across all sessions (§8). VRAM is not
    /// cgroup-controllable, so this is the daemon's own accounting and the
    /// only thing standing between two apps and an OOM.
    pub kv_budget_bytes: u64,
    pub max_concurrent_interactive: u32,
    pub max_concurrent_background: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Attachments {
    pub max_bytes: u64,
    /// Vision tokens are KV-expensive and would otherwise walk straight past
    /// the token rate limit (§11).
    pub max_pixels: u64,
    pub max_samples: u64,
    pub max_per_session: u32,
    /// Accept encoded media at all. When false, clients must decode; when
    /// true, `ai-daemon-decode` does it in a confined child.
    pub allow_encoded: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    pub name: String,
    pub exec: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Extra environment for the child, e.g. a device selection variable.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRule {
    pub identity: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub max_context: Option<u32>,
    #[serde(default)]
    pub max_sessions: Option<u32>,
    #[serde(default)]
    pub tokens_per_minute: Option<u64>,
    #[serde(default)]
    pub allowed_models: Option<Vec<String>>,
}

fn yes() -> bool {
    true
}

impl Default for Daemon {
    fn default() -> Self {
        Daemon {
            state_dir: PathBuf::from("/var/lib/ai-daemon"),
            runtime_dir: PathBuf::from("/run/ai-daemon"),
            idle_exit_seconds: 900,
            model_idle_unload_seconds: 600,
            libexec_dir: PathBuf::from("/usr/lib/ai-daemon"),
        }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            consent: Consent::Polkit,
            gate_group: "ai".to_string(),
            shim_user: "ai-daemon-shim".to_string(),
            max_context: 8192,
            max_sessions: 4,
            tokens_per_minute: 12_000,
            allowed_models: vec!["*".to_string()],
        }
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Scheduler {
            kv_budget_bytes: 2 * 1024 * 1024 * 1024,
            max_concurrent_interactive: 2,
            max_concurrent_background: 1,
        }
    }
}

impl Default for Attachments {
    fn default() -> Self {
        Attachments {
            max_bytes: 16 * 1024 * 1024,
            max_pixels: 4 * 1024 * 1024,
            max_samples: 16 * 60 * 1000,
            max_per_session: 16,
            allow_encoded: true,
        }
    }
}

impl Config {
    /// Load `path`, then every `*.conf` in `<path>.d/` in name order. A later
    /// file replaces whole tables; there is no deep merge, because a half-
    /// merged `[policy]` is a policy nobody wrote.
    pub fn load(path: &Path) -> Result<Config, String> {
        let mut text = String::new();
        if path.exists() {
            text = std::fs::read_to_string(path)
                .map_err(|e| format!("{}: {e}", path.display()))?;
        }
        let mut config: Config = toml::from_str(&text)
            .map_err(|e| format!("{}: {e}", path.display()))?;

        let dropin_dir = PathBuf::from(format!("{}.d", path.display()));
        if let Ok(entries) = std::fs::read_dir(&dropin_dir) {
            let mut files: Vec<PathBuf> = entries
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "conf"))
                .collect();
            files.sort();
            for file in files {
                let text = std::fs::read_to_string(&file)
                    .map_err(|e| format!("{}: {e}", file.display()))?;
                let dropin: Config = toml::from_str(&text)
                    .map_err(|e| format!("{}: {e}", file.display()))?;
                config.merge(dropin, &text);
            }
        }
        Ok(config)
    }

    /// Replace only the tables the drop-in actually mentions. We check the
    /// raw text for the table header rather than comparing against defaults,
    /// so a drop-in that deliberately restates a default still wins.
    fn merge(&mut self, other: Config, raw: &str) {
        let mentions = |table: &str| {
            raw.lines().any(|l| {
                let l = l.trim();
                l.starts_with(&format!("[{table}]")) || l.starts_with(&format!("[[{table}]]"))
            })
        };
        if mentions("daemon") {
            self.daemon = other.daemon;
        }
        if mentions("policy") {
            self.policy = other.policy;
        }
        if mentions("scheduler") {
            self.scheduler = other.scheduler;
        }
        if mentions("attachments") {
            self.attachments = other.attachments;
        }
        if mentions("aliases") {
            self.aliases.extend(other.aliases);
        }
        // Lists accumulate: a drop-in adds a backend or an identity rule, it
        // does not silently disown the ones already declared.
        self.backends.extend(other.backends);
        self.identities.extend(other.identities);
    }

    pub fn rule_for(&self, identity: &str) -> Option<&IdentityRule> {
        self.identities.iter().find(|r| r.identity == identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_config_still_produces_a_closed_service() {
        let config = Config::load(Path::new("/nonexistent/ai-daemon.toml")).unwrap();
        assert_eq!(config.policy.consent, Consent::Polkit, "the default must ask, not assume");
        assert_eq!(config.policy.gate_group, "ai");
        assert!(config.backends.is_empty(), "no backend is enabled by inference");
        assert!(config.policy.max_context > 0);
    }

    #[test]
    fn an_unknown_key_is_an_error_rather_than_a_silent_no_op() {
        let error = toml::from_str::<Config>("[policy]\nconsnet = \"allow\"\n").unwrap_err();
        assert!(error.to_string().contains("consnet"), "{error}");
    }

    #[test]
    fn a_drop_in_replaces_whole_tables_and_accumulates_lists() {
        let dir = std::env::temp_dir().join(format!("ai-daemon-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("config.toml.d")).unwrap();
        let main = dir.join("config.toml");
        std::fs::write(
            &main,
            "[policy]\nconsent = \"deny\"\nmax_context = 1024\n\
             [[backend]]\nname = \"mock\"\nexec = \"/x\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("config.toml.d/10-more.conf"),
            "[[backend]]\nname = \"llamacpp\"\nexec = \"/y\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("config.toml.d/20-policy.conf"),
            "[policy]\nconsent = \"allow\"\n",
        )
        .unwrap();

        let config = Config::load(&main).unwrap();
        assert_eq!(config.policy.consent, Consent::Allow, "the drop-in wins");
        assert_eq!(
            config.policy.max_context,
            Policy::default().max_context,
            "replacing a table means the whole table, not a merge of two authors' halves"
        );
        let names: Vec<&str> = config.backends.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, vec!["mock", "llamacpp"], "lists accumulate");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_identity_rule_is_found_by_its_key() {
        let config: Config = toml::from_str(
            "[[identity]]\nidentity = \"exe:aidctl@1000\"\ntokens_per_minute = 50\n",
        )
        .unwrap();
        assert_eq!(config.rule_for("exe:aidctl@1000").unwrap().tokens_per_minute, Some(50));
        assert!(config.rule_for("exe:aidctl@1001").is_none());
    }
}
