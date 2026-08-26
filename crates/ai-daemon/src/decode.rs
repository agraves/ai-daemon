//! Running the confined media decoder (§11).
//!
//! The daemon links no image or audio codecs. Accepting attacker-supplied
//! PNG, JPEG or MP4 parsing into the process that holds every grant and every
//! session would import the largest CVE surface in desktop software into the
//! one place it must not be.
//!
//! So: one child per attachment, encoded bytes in on stdin, raw frames out on
//! stdout, no filesystem, no network, killed on a deadline. A decoder crash
//! costs exactly one attachment, which the client is told about and can retry
//! by decoding it themselves.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ai_daemon_proto::frame::{self, AttachKind, Frame};
use serde::{Deserialize, Serialize};

use crate::debug;

/// Ceiling on decoded output, independent of the attachment budget: a small
/// encoded file can decode to an enormous bitmap, and that asymmetry is the
/// decompression bomb.
const MAX_DECODED: u64 = 256 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(20);

#[derive(Debug, Serialize)]
struct DecodeRequest {
    kind: String,
    hint: String,
    len: u64,
    max_output: u64,
}

#[derive(Debug, Deserialize)]
struct DecodeReply {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: String,
    #[serde(default)]
    w: Option<u32>,
    #[serde(default)]
    h: Option<u32>,
    #[serde(default)]
    fmt: Option<String>,
    #[serde(default)]
    rate: Option<u32>,
    #[serde(default)]
    len: u64,
}

pub struct Decoded {
    pub w: Option<u32>,
    pub h: Option<u32>,
    pub fmt: Option<String>,
    pub rate: Option<u32>,
    pub data: Vec<u8>,
}

pub fn decode(
    libexec_dir: &Path,
    kind: AttachKind,
    hint: &str,
    encoded: &[u8],
) -> Result<Decoded, String> {
    let helper = libexec_dir.join("ai-daemon-decode");
    if !helper.exists() {
        return Err(format!("{} is not installed", helper.display()));
    }
    let kind_str = match kind {
        AttachKind::Image => "image",
        AttachKind::Audio => "audio",
    };

    let mut child = Command::new(&helper)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .env_clear()
        .spawn()
        .map_err(|e| format!("spawning the decoder: {e}"))?;

    let mut stdin = child.stdin.take().ok_or("decoder has no stdin")?;
    let request = DecodeRequest {
        kind: kind_str.to_string(),
        hint: hint.to_string(),
        len: encoded.len() as u64,
        max_output: MAX_DECODED,
    };
    // Written on a thread: a decoder that refuses to read would otherwise
    // deadlock us on a full pipe before the deadline logic ever runs.
    let payload = encoded.to_vec();
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        frame::write_cbor(&mut stdin, &request)?;
        frame::write_blob(&mut stdin, &payload)?;
        stdin.flush()
    });

    let mut stdout = child.stdout.take().ok_or("decoder has no stdout")?;
    let started = Instant::now();
    let outcome = read_reply(&mut stdout);
    let _ = writer.join();

    if started.elapsed() > DEADLINE {
        let _ = child.kill();
        let _ = child.wait();
        return Err("the decoder exceeded its deadline".into());
    }
    let status = child.wait().map_err(|e| format!("waiting for the decoder: {e}"))?;
    let decoded = outcome?;
    if !status.success() {
        debug!("decoder exited with {status} after answering");
    }
    Ok(decoded)
}

fn read_reply(stdout: &mut impl Read) -> Result<Decoded, String> {
    let reply: DecodeReply = match frame::read_typed(stdout) {
        Ok(Some(reply)) => reply,
        Ok(None) => return Err("the decoder produced nothing".into()),
        Err(e) => return Err(format!("decoder reply: {e}")),
    };
    if !reply.ok {
        return Err(if reply.error.is_empty() { "decode failed".into() } else { reply.error });
    }
    if reply.len > MAX_DECODED {
        return Err(format!("decoded output of {} bytes is over the limit", reply.len));
    }
    let mut data = Vec::with_capacity(reply.len.min(1 << 20) as usize);
    while (data.len() as u64) < reply.len {
        match frame::read_frame(stdout) {
            Ok(Some(Frame::Blob(mut chunk))) => data.append(&mut chunk),
            Ok(Some(Frame::Cbor(_))) => return Err("decoder interleaved a structured frame".into()),
            Ok(None) => return Err("decoder stopped mid-payload".into()),
            Err(e) => return Err(format!("decoder payload: {e}")),
        }
    }
    Ok(Decoded { w: reply.w, h: reply.h, fmt: reply.fmt, rate: reply.rate, data })
}
