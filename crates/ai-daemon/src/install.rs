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

use ai_daemon_proto::manifest::{Manifest, Requirements};
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
        requirements: Requirements { weights_bytes: report.bytes, ..Requirements::default() },
        template: Default::default(),
        backend: options.backend.unwrap_or_default(),
        capabilities: options.capabilities.unwrap_or_else(|| vec!["generate".into()]),
        source: source.to_string(),
    };
    let installed = daemon.registry.accept_staged(&landed, manifest, digest)?;
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
