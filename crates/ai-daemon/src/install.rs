// SPDX-License-Identifier: Apache-2.0

//! Installing a model, across the network boundary (§6, §9).
//!
//! The split this implements is the load-bearing privacy claim of the whole
//! design, so it is worth stating plainly:
//!
//! * `ai-daemon-fetch` has a network. It is spawned per install, lives for one
//!   download, writes only into the staging directory, and never sees a
//!   prompt, a session, or the model store.
//! * `ai-daemon` has prompts. It has `PrivateNetwork=yes`, verifies the digest
//!   of what landed in staging, and moves it into the store itself.
//!
//! Neither half can be talked into doing the other's job, and the daemon does
//! not trust the helper's report of what it downloaded — only the bytes.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ai_daemon_proto::manifest::{Manifest, Requirements, REMOTE_FORMAT};
use serde::Deserialize;

use crate::state::Daemon;
use crate::{info, warn};

#[derive(Debug, Default, Deserialize)]
struct FetchReport {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    bytes: u64,
    /// What the helper computed. Recorded for the log and then ignored: the
    /// daemon hashes the file itself.
    #[serde(default)]
    digest: String,
}

/// What the caller can say about a model the registry cannot work out itself.
///
/// Everything here is a claim the daemon then polices: the format is checked
/// against the file magic, the backend must exist, and the capability list is
/// intersected with what the backend offers. None of it is taken on trust.
#[derive(Debug, Default)]
pub struct Options {
    /// The largest context this model can serve, if the administrator knows.
    ///
    /// Stated rather than detected, and that is a §7 decision rather than
    /// laziness: reading a GGUF header means a weight parser in the process
    /// that holds every prompt, and the backend already does that job. Absent
    /// means unknown, which is treated as no ceiling — not as 4096.
    pub max_ctx: Option<u32>,
    pub format: Option<String>,
    pub backend: Option<String>,
    pub license: Option<String>,
    pub capabilities: Option<Vec<String>>,
}

pub fn install(
    daemon: &Daemon,
    source: &str,
    digest: &str,
    name: &str,
    options: Options,
) -> Result<String, String> {
    if name.is_empty() || !name.chars().all(is_name_char) || name.starts_with('.') {
        return Err(format!("{name:?} is not usable as a model name"));
    }
    // A model that lives on somebody else's machine. Handled before anything
    // else because every step below — fetch, hash, verify, move into the
    // content-addressed store — is about bytes, and there are none.
    if let Some(endpoint_model) = source.strip_prefix("remote:") {
        return install_remote(daemon, endpoint_model, name, options);
    }
    if !digest.starts_with("sha256:") {
        return Err("a sha256 digest is required; installing unverified weights is not offered".into());
    }

    let staging = daemon.registry.staging_dir();
    std::fs::create_dir_all(&staging).map_err(|e| format!("staging directory: {e}"))?;
    let target = staging.join(format!("{name}.part"));
    let _ = std::fs::remove_file(&target);

    let helper: PathBuf = daemon.config.daemon.libexec_dir.join("ai-daemon-fetch");
    if !helper.exists() {
        return Err(format!("{} is not installed", helper.display()));
    }

    info!("install: fetching {name} from {source}");
    let report = match fetch_via_systemd(daemon, &staging, name, source, digest, &target) {
        Ok(report) => report,
        Err(SystemdUnavailable) => fetch_directly(&helper, source, digest, &target)?,
    };

    if !report.ok {
        let _ = std::fs::remove_file(&target);
        return Err(if report.error.is_empty() {
            "the fetch helper failed without saying why".into()
        } else {
            report.error
        });
    }
    if report.digest != digest {
        warn!("install: the helper reported {} for {name}; verifying independently", report.digest);
    }
    let landed = if report.path.is_empty() { target.clone() } else { PathBuf::from(&report.path) };

    let format = options.format.unwrap_or_else(|| "gguf".to_string());
    // A four-byte magic check, not a header parse: enough to catch a file that
    // is not what it was called, and nowhere near enough to be a new attack
    // surface in the privileged process. Reading weight headers stays the
    // backend's job (§7).
    if format == "gguf" {
        match magic(&landed) {
            Ok(magic) if &magic == b"GGUF" => {}
            Ok(_) => {
                let _ = std::fs::remove_file(&landed);
                return Err(format!("{name} was declared gguf but does not start with the GGUF magic"));
            }
            Err(e) => return Err(format!("reading {}: {e}", landed.display())),
        }
    }

    let manifest = Manifest {
        name: name.to_string(),
        digest: digest.to_string(),
        format,
        quantization: guess_quantization(source),
        license: options.license.unwrap_or_default(),
        requirements: Requirements {
            weights_bytes: report.bytes,
            // Both from one number: an administrator saying "this is a 32k
            // model" means both that it can go that high and that there is no
            // reason to open it lower.
            default_ctx: options.max_ctx.unwrap_or(0),
            max_ctx: options.max_ctx.unwrap_or(0),
            ..Requirements::default()
        },
        template: Default::default(),
        backend: options.backend.unwrap_or_default(),
        capabilities: options.capabilities.unwrap_or_else(|| vec!["generate".into()]),
        source: source.to_string(),
    };
    if let Err(e) = servable(daemon, &manifest) {
        let _ = std::fs::remove_file(&landed);
        return Err(e);
    }
    let installed = daemon.registry.accept_staged(&landed, manifest, digest)?;
    Ok(installed.name)
}

/// A model cannot grant what its backend cannot do.
///
/// Half of what `Manifest::capabilities` has always been documented to mean,
/// enforced at the moment the claim is written down rather than discovered per
/// request afterwards. An install that would have produced a model claiming
/// `vision` against a backend that cannot see is refused here, where the
/// person who typed it is still watching, instead of at 3am by whoever sent
/// the first screenshot.
///
/// Refusing rather than silently narrowing the list: an administrator who
/// asked for `--capability vision` and got a text model would have no way to
/// tell, and the manifest would then quietly disagree with what they believe
/// they installed.
/// The policy vocabulary, which is not this one.
///
/// `aidctl grant` takes `generate-tools`; `aidctl install --capability` takes
/// `tools`. The two lists sit four lines apart in the same `--help`, they
/// overlap on `generate` and `embed`, and nothing marks which is which — so
/// `--capability generate-tools` is the natural thing to type and produced a
/// refusal that listed `"tools"` inside a backend's capability array without
/// saying that was the word wanted. Naming the confusion is cheaper than
/// letting each person rediscover it.
const POLICY_ONLY: [(&str, &str); 2] =
    [("generate-tools", "tools"), ("generate-media", "image-out` or `audio-out")];

fn servable(daemon: &Daemon, manifest: &Manifest) -> Result<(), String> {
    for capability in &manifest.capabilities {
        if let Some((_, model_word)) = POLICY_ONLY.iter().find(|(p, _)| p == capability) {
            return Err(format!(
                "{capability:?} is a policy capability, not a model capability. Policy \
                 capabilities are what `aidctl grant` takes and describe what an *identity* \
                 may ask for; `--capability` describes what a *model* is, and for this one \
                 the word is `{model_word}`."
            ));
        }
        // for_manifest resolves the same way a session will, so what is
        // checked here is what will actually serve it — including a named
        // backend that does not exist, which is worth catching at install too.
        if let Err(e) = daemon.backends.for_manifest(manifest, capability) {
            return Err(format!(
                "{} was declared {capability:?} and no configured backend serves that for a \
                 {} model ({e}). Install it without that capability, or configure a backend \
                 that has it.",
                manifest.name, manifest.format
            ));
        }
    }
    Ok(())
}

/// Register a model served by a remote provider.
///
/// Nothing is downloaded and nothing is verified, because there is nothing
/// here to verify — the integrity of a remote model is the endpoint's promise,
/// not this machine's measurement, and pretending otherwise by manufacturing a
/// digest would be worse than saying so. What the daemon *can* guarantee is
/// that the user is told: the backend serving this declares `local: false`,
/// which reaches the consent prompt, `GetInfo`, and every audit record.
fn install_remote(
    daemon: &Daemon,
    endpoint_model: &str,
    name: &str,
    options: Options,
) -> Result<String, String> {
    if endpoint_model.is_empty() || !endpoint_model.chars().all(|c| is_name_char(c) || c == '/' || c == ':') {
        return Err(format!("{endpoint_model:?} is not usable as a remote model identifier"));
    }
    if let Some(format) = &options.format {
        if format != REMOTE_FORMAT {
            return Err(format!(
                "a remote: source is format {REMOTE_FORMAT:?}, not {format:?}"
            ));
        }
    }
    // Must resolve to a backend that is actually configured, and it must be a
    // remote one. Otherwise the model installs cleanly and fails at first use,
    // which is the worst place to learn the endpoint was never wired up.
    let asked = options.backend.clone().unwrap_or_default();
    let serving = daemon.backends.remote_provider(&asked).ok_or_else(|| {
        if asked.is_empty() {
            "no remote provider is configured; a remote: model needs a backend with a connect \
             socket (see /etc/ai-daemon/remote.toml)"
                .to_string()
        } else {
            format!("backend {asked:?} is not a configured remote provider")
        }
    })?;

    let manifest = Manifest {
        name: name.to_string(),
        // Not a hash and not shaped like one. See Manifest::digest.
        digest: format!("remote:{endpoint_model}"),
        format: REMOTE_FORMAT.to_string(),
        quantization: String::new(),
        license: options.license.unwrap_or_default(),
        // No weights, so no weight bytes and no VRAM on this machine. Leaving
        // these zero is what keeps the scheduler from reserving budget for a
        // model that occupies none of it.
        requirements: Requirements {
            default_ctx: options.max_ctx.unwrap_or(0),
            max_ctx: options.max_ctx.unwrap_or(0),
            ..Requirements::default()
        },
        template: Default::default(),
        backend: serving.clone(),
        capabilities: options.capabilities.unwrap_or_else(|| vec!["generate".into()]),
        source: format!("remote:{endpoint_model}"),
    };
    servable(daemon, &manifest)?;
    warn!(
        "install: {name} is served by {serving} and is NOT local — prompts sent to it leave this machine"
    );
    let installed = daemon.registry.register_remote(manifest)?;
    Ok(installed.name)
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'
}

/// Marker for "there is no systemd here to ask", which is a real situation —
/// a container, a development run — and not a failure to report to the caller.
struct SystemdUnavailable;

/// The correct path: ask PID 1 for a process that has a network.
///
/// The daemon runs with `PrivateNetwork=yes`, and a child it forks inherits
/// that namespace, so spawning the helper ourselves would produce a downloader
/// with no network at all. The unit has to be started *by systemd* to land in
/// a namespace that has one — which is also what makes the split in §9 real
/// rather than decorative.
fn fetch_via_systemd(
    daemon: &Daemon,
    staging: &Path,
    name: &str,
    source: &str,
    digest: &str,
    target: &Path,
) -> Result<FetchReport, SystemdUnavailable> {
    let connection = daemon.bus.lock().unwrap().clone().ok_or(SystemdUnavailable)?;

    // The instance name is ours, not the caller's: a URL in a unit name would
    // be an injection surface, so the job travels as a file and the instance
    // is only an identifier.
    let job_id = format!("{name}-{}", crate::policy::now_secs());
    let job_path = staging.join(format!("{job_id}.job"));
    let report_path = staging.join(format!("{job_id}.report"));
    let job = serde_json::json!({
        "source": source,
        "output": target.display().to_string(),
        "digest": digest,
    });
    if std::fs::write(&job_path, job.to_string()).is_err() {
        return Err(SystemdUnavailable);
    }
    let _ = std::fs::remove_file(&report_path);

    let unit = format!("ai-daemon-fetch@{job_id}.service");
    if let Err(e) = connection.call_method(
        Some("org.freedesktop.systemd1"),
        "/org/freedesktop/systemd1",
        Some("org.freedesktop.systemd1.Manager"),
        "StartUnit",
        &(unit.as_str(), "replace"),
    ) {
        warn!(
            "install: systemd would not start {unit} ({e}); falling back to fetching in this \
             process's own network namespace, which is weaker than the split section 9 describes"
        );
        let _ = std::fs::remove_file(&job_path);
        return Err(SystemdUnavailable);
    }

    // Poll for the report rather than the unit's state: the report is what we
    // actually need, and a unit that succeeded without writing one has failed
    // as far as this caller is concerned.
    let deadline = Instant::now() + Duration::from_secs(3600);
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(&report_path) {
            let _ = std::fs::remove_file(&job_path);
            let _ = std::fs::remove_file(&report_path);
            return Ok(serde_json::from_str(&text).unwrap_or(FetchReport {
                ok: false,
                error: "the fetch helper wrote an unreadable report".into(),
                ..FetchReport::default()
            }));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let _ = std::fs::remove_file(&job_path);
    Ok(FetchReport {
        ok: false,
        error: format!("{unit} did not finish within an hour"),
        ..FetchReport::default()
    })
}

/// The fallback, for when there is no systemd to ask. Correct wherever the
/// daemon is not namespaced away from the network, and loudly not the design
/// wherever it is.
fn fetch_directly(
    helper: &Path,
    source: &str,
    digest: &str,
    target: &Path,
) -> Result<FetchReport, String> {
    let output = Command::new(helper)
        .arg("--source")
        .arg(source)
        .arg("--output")
        .arg(target)
        .arg("--expect-digest")
        .arg(digest)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("running the fetch helper: {e}"))?;
    serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("the fetch helper said something unreadable: {e}"))
}

fn magic(path: &Path) -> std::io::Result<[u8; 4]> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut buf = [0u8; 4];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

fn guess_quantization(source: &str) -> String {
    let lower = source.to_ascii_lowercase();
    for candidate in ["q4_k_m", "q4_k_s", "q5_k_m", "q6_k", "q8_0", "f16", "bf16", "f32"] {
        if lower.contains(candidate) {
            return candidate.to_string();
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_model_name_cannot_escape_the_manifest_directory() {
        for bad in ["../etc/passwd", "a/b", ".hidden", "", "name with spaces", "x;y"] {
            assert!(
                bad.is_empty() || !bad.chars().all(is_name_char) || bad.starts_with('.'),
                "{bad:?} would be accepted as a model name"
            );
        }
        for good in ["llama-3.1-8b-q4", "mock_small", "qwen2.5-0.5b"] {
            assert!(good.chars().all(is_name_char) && !good.starts_with('.'), "{good:?}");
        }
    }

    #[test]
    fn quantization_is_read_out_of_the_name_when_it_is_there() {
        assert_eq!(guess_quantization("Llama-3.1-8B-Instruct-Q4_K_M.gguf"), "q4_k_m");
        assert_eq!(guess_quantization("model-f16.gguf"), "f16");
        assert_eq!(guess_quantization("model.gguf"), "");
    }
}
