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
    /// How long a backend may say nothing at all before the daemon gives up on
    /// the request (§7). The outer net for a backend that has stopped existing
    /// in every way except closing its socket.
    ///
    /// Time the daemon itself spent holding the request paused does not count
    /// against it — see `session::wait_for_event`, which is where that
    /// distinction is made and where getting it wrong killed healthy work.
    ///
    /// Configurable because it is a number, not a law: a first token on a
    /// cold, large model on a slow disk is a real reason to raise it, and the
    /// verification lowers it so a test can reach it in seconds.
    pub backend_silence_seconds: u64,
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
    /// Which callers may assert an application identity for somebody else.
    ///
    /// Matched against the caller's systemd unit, and against its executable
    /// name where that is readable. Exact names, not prefixes — see
    /// [`crate::dbusapi::is_trusted_introducer`], which is where the reason
    /// lives and where a prefix test was a real privilege hole. Only the
    /// `.service` suffix is optional in what is written here.
    ///
    /// A list rather than a single hardcoded name because there are two
    /// implementations of the same job — xdg-desktop-portal once
    /// `org.freedesktop.portal.AI` is accepted upstream, and
    /// `ai-daemon-portal` until then — because the desktop ships `-gtk`,
    /// `-gnome` and `-kde` variants that a prefix would have covered and an
    /// exact list must name, and because a distro that ships another has
    /// somewhere to say so that is not a patch.
    ///
    /// Emptying this list turns portal identity off entirely, which is a
    /// reasonable thing for a machine with no desktop to do. Adding to it is
    /// granting a process the right to name any app it likes, so it is an
    /// administrator's decision and lives beside `shim_user` for the same
    /// reason.
    pub portal_units: Vec<String>,
    pub max_context: u32,
    pub max_sessions: u32,
    pub tokens_per_minute: u64,
    /// Model names, or `*`. Checked after alias resolution, so a policy cannot
    /// be dodged by asking for `default`.
    pub allowed_models: Vec<String>,
}

/// Who may speak for an application, out of the box.
///
/// Exact unit names, not prefixes. A prefix would be tidier — the desktop
/// variants differ only by a suffix — and it would also mean any user could
/// write `~/.config/systemd/user/xdg-desktop-portal-anything.service` and be
/// believed about every application on the machine. So the variants are
/// listed one by one, and a distro that ships another says so in config.
pub fn default_portal_units() -> Vec<String> {
    [
        "xdg-desktop-portal",
        "xdg-desktop-portal-gtk",
        "xdg-desktop-portal-gnome",
        "xdg-desktop-portal-kde",
        "xdg-desktop-portal-lxqt",
        "xdg-desktop-portal-wlr",
        "xdg-desktop-portal-hyprland",
        "ai-daemon-portal",
    ]
    .iter()
    .map(|name| name.to_string())
    .collect()
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
    /// Spawn this. The usual case: the backend is a child of the daemon and
    /// dies with it.
    #[serde(default)]
    pub exec: PathBuf,
    /// Or connect here instead.
    ///
    /// A backend that needs a network cannot be a child of this daemon —
    /// `PrivateNetwork=yes` means anything it forks has no network at all, by
    /// design (§9). So a remote provider runs as its own unit, with its own
    /// user and its own network, and the daemon reaches it over a socket
    /// rather than owning it. Exactly one of `exec` and `connect` may be set.
    #[serde(default)]
    pub connect: Option<PathBuf>,
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
            backend_silence_seconds: 900,
        }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            consent: Consent::Polkit,
            gate_group: "ai".to_string(),
            shim_user: "ai-daemon-shim".to_string(),
            portal_units: default_portal_units(),
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
        // Lists accumulate while merging and are collapsed here, so that
        // redeclaring a name overrides it rather than appending a twin that
        // nothing will ever reach.
        config.backends = last_wins(std::mem::take(&mut config.backends), |b| b.name.clone());
        config.identities =
            last_wins(std::mem::take(&mut config.identities), |r| r.identity.clone());
        config.validate()?;
        Ok(config)
    }

    /// Refuse a configuration the wire cannot carry.
    ///
    /// The attachment budgets are the admin's to set and a vision model is
    /// exactly the reason to raise them — but a decoded attachment reaches the
    /// backend inside one CBOR frame, so there is a ceiling no configuration
    /// can lift. Left unchecked, exceeding it surfaced much later as a framing
    /// error on the backend socket, reported to the client as a backend
    /// failure: a diagnosis pointing at the wrong component, on a
    /// configuration the daemon had accepted without a word.
    ///
    /// Refusing at load says it once, to the person who can act on it.
    fn validate(&self) -> Result<(), String> {
        let ceiling = ai_daemon_proto::frame::MAX_ATTACHMENT_PAYLOAD;
        // Worst case per attachment: RGBA is four bytes a pixel, PCM is four
        // bytes a sample.
        for backend in &self.backends {
            let named = !backend.exec.as_os_str().is_empty();
            match (named, backend.connect.is_some()) {
                (false, false) => {
                    return Err(format!(
                        "backend {:?} says neither exec nor connect, so there is nothing to talk to",
                        backend.name
                    ))
                }
                (true, true) => {
                    return Err(format!(
                        "backend {:?} says both exec and connect; it is one or the other",
                        backend.name
                    ))
                }
                _ => {}
            }
            // Neither reaches a process the daemon did not start. Refused
            // rather than ignored: a setting that silently does nothing is
            // how an administrator comes to believe an environment variable
            // selected a device.
            if backend.connect.is_some() && (!backend.args.is_empty() || !backend.env.is_empty()) {
                return Err(format!(
                    "backend {:?} sets args or env alongside connect, and neither can apply to a \
                     process this daemon does not start",
                    backend.name
                ));
            }
        }
        let widest_image = self.attachments.max_pixels.saturating_mul(4);
        if widest_image > ceiling {
            return Err(format!(
                "attachments.max_pixels = {} allows a {widest_image} byte image, and a decoded \
                 attachment travels to the backend in one frame capped at {ceiling} bytes; \
                 the most pixels that can fit is {}",
                self.attachments.max_pixels,
                ceiling / 4
            ));
        }
        let longest_audio = self.attachments.max_samples.saturating_mul(4);
        if longest_audio > ceiling {
            return Err(format!(
                "attachments.max_samples = {} allows a {longest_audio} byte clip, and a decoded \
                 attachment travels to the backend in one frame capped at {ceiling} bytes; \
                 the most samples that can fit is {}",
                self.attachments.max_samples,
                ceiling / 4
            ));
        }
        Ok(())
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
        // Lists accumulate here and are de-duplicated once every file has been
        // read; see `last_wins`. A drop-in adds a backend or an identity rule
        // without disowning the others, and replaces one that shares its name.
        self.backends.extend(other.backends);
        self.identities.extend(other.identities);
    }

    /// At most one rule can match, because `last_wins` has already collapsed
    /// the list, so first-match and last-match are the same answer.
    pub fn rule_for(&self, identity: &str) -> Option<&IdentityRule> {
        self.identities.iter().find(|r| r.identity == identity)
    }
}

/// Collapse a list so that a repeated key keeps the last value at the first
/// position.
///
/// The last value, because that is what every other part of this file already
/// does — a drop-in replaces `[policy]`, and a repeated alias key overwrites
/// through the map — and because the alternative is the one that bites. Both
/// consumers of these lists take the first match: `rule_for` is a `find`, and
/// `Backends` scans its specs in order. So an admin landing a drop-in that
/// re-declares an identity to tighten its rate limit appended a rule nothing
/// would ever consult, and was told nothing. A tightening that reports success
/// and changes nothing is the failure the policy engine refuses one level
/// down; the loader should not be creating it.
///
/// Backends have the same shape with a sharper edge: `enabled = false` in a
/// drop-in used to append a disabled twin, which construction filtered away
/// while the enabled original kept running — so there was no way to turn a
/// packaged backend off, and no error saying so.
///
/// The first *position*, because order is meaningful for backends —
/// `for_manifest` picks the first one that can serve a model — and a drop-in
/// changing a backend's settings should not also silently reorder which
/// backend is preferred.
fn last_wins<T, K>(items: Vec<T>, key: impl Fn(&T) -> K) -> Vec<T>
where
    K: Ord,
{
    let mut positions: BTreeMap<K, usize> = BTreeMap::new();
    let mut kept: Vec<Option<T>> = Vec::with_capacity(items.len());
    for item in items {
        match positions.get(&key(&item)) {
            Some(&at) => kept[at] = Some(item),
            None => {
                positions.insert(key(&item), kept.len());
                kept.push(Some(item));
            }
        }
    }
    kept.into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped config and the compiled default must agree about who may
    /// speak for an application.
    ///
    /// Two lists of the same eight unit names, in two files, and nothing was
    /// stopping them drifting: an install that never wrote a config would
    /// trust one set and an administrator reading /etc/ai-daemon/config.toml
    /// would believe another. For a key whose whole job is granting the right
    /// to name any app on the machine, "the documentation and the behaviour
    /// disagree" is the failure mode, not a tidiness complaint — a stale
    /// *description* of this key is what prompted this test.
    #[test]
    fn the_shipped_config_agrees_with_the_compiled_default_about_portals() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/config/config.toml");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        let shipped: Config = toml::from_str(&text)
            .unwrap_or_else(|e| panic!("the shipped config does not parse: {e}"));

        assert_eq!(
            shipped.policy.portal_units,
            default_portal_units(),
            "packaging/config/config.toml and default_portal_units() disagree \
             about who may assert an application identity"
        );
        // And it is not a prefix list, whatever any comment says: every name
        // must be one is_trusted_introducer actually accepts.
        for name in &shipped.policy.portal_units {
            assert!(
                crate::dbusapi::is_trusted_introducer(
                    &shipped.policy.portal_units,
                    Some(&format!("{name}.service")),
                    None
                ),
                "{name} is listed but would not be trusted"
            );
        }
    }

    fn backend_toml(body: &str) -> Result<Config, String> {
        let text = format!("[[backend]]\nname = \"x\"\n{body}");
        toml::from_str::<Config>(&text)
            .map_err(|e| e.to_string())
            .and_then(|config| config.validate().map(|()| config))
    }

    /// The two ways of reaching a backend are alternatives, not a pair. A spec
    /// with both is a spec whose author expected one of them to matter and
    /// cannot be told which.
    #[test]
    fn a_backend_says_exec_or_connect_and_not_both() {
        assert!(backend_toml("exec = \"/bin/true\"\n").is_ok());
        assert!(backend_toml("connect = \"/run/x.sock\"\n").is_ok());

        let both = backend_toml("exec = \"/bin/true\"\nconnect = \"/run/x.sock\"\n")
            .expect_err("both should be refused");
        assert!(both.contains("one or the other"), "unhelpful: {both}");

        let neither = backend_toml("").expect_err("neither should be refused");
        assert!(neither.contains("nothing to talk to"), "unhelpful: {neither}");
    }

    /// Refused rather than ignored. A setting that silently does nothing is
    /// how an administrator comes to believe an environment variable selected
    /// a device.
    #[test]
    fn args_and_env_are_refused_beside_connect() {
        let with_env = backend_toml(
            "connect = \"/run/x.sock\"\nenv = { CUDA_VISIBLE_DEVICES = \"1\" }\n",
        )
        .expect_err("env should be refused");
        assert!(with_env.contains("does not start"), "unhelpful: {with_env}");

        let with_args = backend_toml("connect = \"/run/x.sock\"\nargs = [\"--gpu\"]\n")
            .expect_err("args should be refused");
        assert!(with_args.contains("does not start"), "unhelpful: {with_args}");
    }

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

    /// The shipped defaults must not be a configuration the daemon refuses.
    #[test]
    fn the_defaults_are_carryable() {
        Config::default().validate().expect("the built-in defaults must load");
    }

    /// The week it breaks: an admin raises the pixel budget for a document
    /// vision model. It used to be accepted in silence and then fail as a
    /// framing error attributed to the backend.
    #[test]
    fn a_pixel_budget_the_wire_cannot_carry_is_refused_at_load() {
        let mut config = Config::default();
        config.attachments.max_pixels = 17_000_000;
        let error = config.validate().unwrap_err();
        assert!(error.contains("max_pixels"), "{error}");
        assert!(error.contains("one frame"), "it must name the real limit: {error}");
    }

    #[test]
    fn an_audio_budget_the_wire_cannot_carry_is_refused_at_load() {
        let mut config = Config::default();
        config.attachments.max_samples = 40_000_000;
        let error = config.validate().unwrap_err();
        assert!(error.contains("max_samples"), "{error}");
    }

    /// The finding, in the shape an admin hits it: a packaged main file, a
    /// local drop-in that tightens one identity and turns one backend off.
    /// Both used to be appended after the originals and never reached — the
    /// rate limit stayed loose and the backend kept running, silently.
    #[test]
    fn a_drop_in_overrides_what_the_main_file_declared() {
        let dir = std::env::temp_dir().join(format!("ai-daemon-dropin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("config.toml.d")).unwrap();
        let main = dir.join("config.toml");
        std::fs::write(
            &main,
            r#"
[[identity]]
identity = "unit:app@1000"
tokens_per_minute = 100
capabilities = ["generate", "embed"]

[[backend]]
name = "llamacpp"
exec = "/usr/lib/ai-daemon/backends/llamacpp"

[[backend]]
name = "mock"
exec = "/usr/lib/ai-daemon/backends/mock"
"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("config.toml.d/50-tighten.conf"),
            r#"
[[identity]]
identity = "unit:app@1000"
tokens_per_minute = 10
capabilities = ["generate"]

[[backend]]
name = "llamacpp"
exec = "/usr/lib/ai-daemon/backends/llamacpp"
enabled = false
"#,
        )
        .unwrap();

        let config = Config::load(&main).unwrap();

        let rule = config.rule_for("unit:app@1000").expect("the rule must still exist");
        assert_eq!(rule.tokens_per_minute, Some(10), "the tightening must be what applies");
        assert_eq!(rule.capabilities, vec!["generate"], "and so must the narrower capabilities");
        assert_eq!(config.identities.len(), 1, "one identity declared twice is one rule");

        let names: Vec<&str> = config.backends.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, vec!["llamacpp", "mock"], "the main file's ordering is preserved");
        let llamacpp = config.backends.iter().find(|b| b.name == "llamacpp").unwrap();
        assert!(!llamacpp.enabled, "a drop-in must be able to turn a packaged backend off");

        // And the disable must survive into what actually runs.
        let live = crate::state::Backends::new(config.backends.clone());
        assert_eq!(live.configured(), vec!["mock".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_repeated_key_keeps_the_last_value_at_the_first_position() {
        let collapsed = last_wins(
            vec![("a", 1), ("b", 2), ("a", 3), ("c", 4), ("b", 5)],
            |(k, _)| k.to_string(),
        );
        assert_eq!(collapsed, vec![("a", 3), ("b", 5), ("c", 4)]);
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
