//! ai-daemon-fetch — the only part of this project allowed near a network.
//!
//! §9 is the load-bearing privacy claim of the design: the process that
//! touches prompts has no network, and the process that touches the network
//! never sees a prompt. This is the second half. It is spawned per download,
//! lives for one, writes to one path inside the daemon's staging directory,
//! and exits.
//!
//! It does not verify anything. It reports a digest for the log, but the
//! daemon re-hashes the bytes itself, because a helper that could be talked
//! into lying about a digest would be a helper that could install any weights
//! it liked.
//!
//! TLS is curl's, deliberately. Linking a TLS stack and an HTTP client into
//! this project would add a large dependency surface to do a job the base
//! system already does well, and `curl` is a dependency the package can
//! declare and the distro already audits.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};

#[derive(Debug, serde::Deserialize)]
struct Job {
    source: String,
    output: PathBuf,
    #[serde(default)]
    digest: String,
}

fn main() {
    let mut source = String::new();
    let mut output = PathBuf::new();
    let mut expected = String::new();
    let mut job_file: Option<PathBuf> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            // How the systemd unit is invoked: a unit file cannot carry a
            // caller-supplied URL as an argument without the instance name
            // becoming an injection surface, so the job is a file the daemon
            // wrote and this helper reads.
            "--job" => job_file = args.next().map(PathBuf::from),
            "--source" => source = args.next().unwrap_or_default(),
            "--output" => output = PathBuf::from(args.next().unwrap_or_default()),
            "--expect-digest" => expected = args.next().unwrap_or_default(),
            "--version" | "-V" => {
                println!("ai-daemon-fetch {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            other => fail(&format!("unknown argument {other:?}")),
        }
    }
    if let Some(path) = &job_file {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) => fail(&format!("reading the job file {}: {e}", path.display())),
        };
        match serde_json::from_str::<Job>(&text) {
            Ok(job) => {
                source = job.source;
                output = job.output;
                expected = job.digest;
            }
            Err(e) => fail(&format!("the job file is unreadable: {e}")),
        }
    }
    if source.is_empty() || output.as_os_str().is_empty() {
        fail("--source and --output are both required, or --job naming a file with them");
    }

    match fetch(&source, &output) {
        Ok(bytes) => {
            let digest = match digest_file(&output) {
                Ok(digest) => digest,
                Err(e) => {
                    let _ = std::fs::remove_file(&output);
                    fail(&format!("hashing what was fetched: {e}"));
                }
            };
            // Reported, not enforced. Saying so here rather than pretending
            // otherwise is the point: the daemon does not trust this number.
            if !expected.is_empty() && expected != digest {
                eprintln!("<4>ai-daemon-fetch: got {digest}, caller expected {expected}");
            }
            report(&format!(
                "{{\"ok\":true,\"path\":{},\"bytes\":{bytes},\"digest\":{}}}",
                json_string(&output.display().to_string()),
                json_string(&digest)
            ));
        }
        Err(e) => {
            let _ = std::fs::remove_file(&output);
            fail(&e);
        }
    }
}

/// A failed local copy, explained.
///
/// This unit runs with `ProtectHome=yes` — it is the one process in the
/// project with a network, and a home directory is the last thing it should be
/// able to read. The consequence is that `file:///home/…`, which is the most
/// natural thing to type and which `--help` advertises without qualification,
/// cannot ever work: every home is empty in this namespace, so the copy fails
/// with a bare ENOENT or EACCES naming a file the user can plainly see.
///
/// The sandbox is right and stays. Saying so is the fix.
fn local_copy_error(path: &str, e: &std::io::Error) -> String {
    let base = format!("copying {path}: {e}");
    if path.starts_with("/home/") || path.starts_with("/root/") {
        return format!(
            "{base}\n\
             this helper runs with ProtectHome=yes and cannot read home directories, \
             so a file:// source under one is never visible to it regardless of its \
             permissions; stage the file somewhere outside /home (/var/cache, /srv \
             and /tmp all work) and install from there, or serve it over https://"
        );
    }
    base
}

fn fetch(source: &str, output: &Path) -> Result<u64, String> {
    if let Some(path) = source.strip_prefix("file://").or_else(|| {
        source.starts_with('/').then_some(source)
    }) {
        let bytes = std::fs::copy(path, output).map_err(|e| local_copy_error(path, &e))?;
        return Ok(bytes);
    }
    if let Some(reference) = source.strip_prefix("oci://") {
        return fetch_oci(reference, output);
    }
    if source.starts_with("https://") {
        return curl(source, output, &[]);
    }
    if source.starts_with("http://") {
        // Plain HTTP for weights means an unauthenticated party chooses what
        // your machine runs. The digest would catch a substitution, but a
        // digest the caller got over the same channel is not independent.
        return Err("http:// sources are refused; use https:// or a digest-pinned oci:// reference".into());
    }
    Err(format!("unsupported source scheme in {source:?}"))
}

/// Pull a blob from an OCI registry by digest.
///
/// Only the digest form is accepted: `oci://registry/repo@sha256:...`. A tag
/// is a name somebody else can repoint, and this helper exists precisely so
/// that what lands on disk is what was asked for.
fn fetch_oci(reference: &str, output: &Path) -> Result<u64, String> {
    let (repository, digest) = reference
        .rsplit_once('@')
        .ok_or("an oci:// reference must be pinned by @sha256:...")?;
    if !digest.starts_with("sha256:") {
        return Err("only sha256 digests are supported".into());
    }
    let (registry, path) = repository
        .split_once('/')
        .ok_or("an oci:// reference needs a registry and a repository")?;
    let token = registry_token(registry, path).unwrap_or_default();
    let url = format!("https://{registry}/v2/{path}/blobs/{digest}");
    let mut headers = vec![
        "-H".to_string(),
        "Accept: application/octet-stream".to_string(),
    ];
    if !token.is_empty() {
        headers.push("-H".into());
        headers.push(format!("Authorization: Bearer {token}"));
    }
    let borrowed: Vec<&str> = headers.iter().map(String::as_str).collect();
    curl(&url, output, &borrowed)
}

/// Anonymous pull token, for registries that insist on one even for public
/// blobs. A failure here is not fatal: plenty of registries need no token.
fn registry_token(registry: &str, repository: &str) -> Option<String> {
    let url = format!(
        "https://{registry}/token?service={registry}&scope=repository:{repository}:pull"
    );
    let output = Command::new("curl")
        .args(["-sS", "--max-time", "30", "--fail", &url])
        .stderr(Stdio::inherit())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    body.get("token")
        .or_else(|| body.get("access_token"))
        .and_then(|t| t.as_str())
        .map(str::to_string)
}

fn curl(url: &str, output: &Path, extra: &[&str]) -> Result<u64, String> {
    let status = Command::new("curl")
        .args([
            "-sS",
            "--fail",
            "--location",
            // A redirect chain that leaves https is a downgrade; refuse it.
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-redirs",
            "5",
            "--connect-timeout",
            "30",
            "--retry",
            "3",
            "--retry-delay",
            "2",
            "-o",
        ])
        .arg(output)
        .args(extra)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| format!("running curl: {e}"))?;
    if !status.success() {
        return Err(format!("curl failed with {status} fetching {url}"));
    }
    std::fs::metadata(output)
        .map(|m| m.len())
        .map_err(|e| format!("stat of the download: {e}"))
}

fn digest_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

/// The report goes to stdout for a direct caller, and beside the job file for
/// the systemd path — where stdout is the journal and the daemon cannot read
/// it back.
fn report(json: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{json}");
    let _ = out.flush();
    if let Some(path) = report_path() {
        let tmp = path.with_extension("report.tmp");
        if std::fs::write(&tmp, json).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

fn report_path() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--job" {
            return args.next().map(|p| PathBuf::from(p).with_extension("report"));
        }
    }
    None
}

fn json_string(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_string())
}

fn fail(message: &str) -> ! {
    report(&format!("{{\"ok\":false,\"error\":{}}}", json_string(message)));
    std::process::exit(1)
}

fn print_help() {
    println!(
        "ai-daemon-fetch {} — download a model artifact into a staging directory

usage: ai-daemon-fetch --source URL --output PATH [--expect-digest sha256:...]

Sources: https://…, file:///…, oci://registry/repo@sha256:…

With --job FILE, all three are read from a JSON file instead; that is how
ai-daemon-fetch@.service is started, since the daemon has no network of its
own and must ask systemd for a process that does.

Prints a single JSON object on stdout. This helper verifies nothing: the
daemon re-hashes the file it finds, which is the whole point of running the
download somewhere that cannot reach the model store.",
        env!("CARGO_PKG_VERSION")
    );
}
