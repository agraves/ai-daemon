// SPDX-License-Identifier: Apache-2.0

//! Running the confined media decoder (§11).
//!
//! The daemon links no image or audio codecs. Accepting attacker-supplied
//! PNG, JPEG or MP4 parsing into the process that holds every grant and every
//! session would import the largest CVE surface in desktop software into the
//! one place it must not be.
//!
//! So: one child per attachment, encoded bytes in on stdin, raw frames out on
//! stdout, no filesystem, no network, and killed on a deadline enforced by a
//! thread that is not waiting on the child — see [`decode_within`] for why
//! that distinction is the whole of it. A decoder crash, or a decoder that
//! simply stops, costs exactly one attachment; the client is told which and
//! can decode it themselves instead.

use std::io::{Read, Write};
use std::path::Path;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ai_daemon_proto::frame::{self, AttachKind, Frame};
use serde::{Deserialize, Serialize};

/// Ceiling on decoded output, independent of the attachment budget: a small
/// encoded file can decode to an enormous bitmap, and that asymmetry is the
/// decompression bomb.
const MAX_DECODED: u64 = 256 * 1024 * 1024;
/// How long a decoder gets before it is killed. Enforced in [`decode_within`].
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

#[derive(Debug)]
pub struct Decoded {
    pub w: Option<u32>,
    pub h: Option<u32>,
    pub fmt: Option<String>,
    pub rate: Option<u32>,
    pub data: Vec<u8>,
}

/// A pipe read that cannot outlast a deadline.
///
/// The first version of this fix killed the child at the deadline and relied
/// on that closing its stdout, so the blocked read would see EOF. That works
/// for the shipped decoder — its seccomp filter allows no `clone`, `fork` or
/// `execve`, so it has no children to hold the write end open — but it makes
/// the timeout depend on a property of the *child* rather than on anything
/// this side controls, and the first test written against it hung for five
/// minutes behind a `sleep` that had outlived the shell that spawned it.
///
/// So the deadline lives on the read. `poll` with the time remaining, and only
/// read once the kernel says there is something there.
struct DeadlineReader<'a> {
    inner: &'a mut std::process::ChildStdout,
    fd: std::os::unix::io::RawFd,
    deadline: Instant,
}

impl std::io::Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "the decoder ran out of time",
                ));
            }
            let mut pollfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let milliseconds = remaining.as_millis().min(i32::MAX as u128) as i32;
            // SAFETY: one initialised pollfd, and a count that matches it.
            let ready = unsafe { libc::poll(&mut pollfd, 1, milliseconds) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "the decoder ran out of time",
                ));
            }
            return self.inner.read(buf);
        }
    }
}

pub fn decode(
    libexec_dir: &Path,
    kind: AttachKind,
    hint: &str,
    encoded: &[u8],
) -> Result<Decoded, String> {
    decode_within(libexec_dir, kind, hint, encoded, DEADLINE)
}

/// The deadline is a parameter so it can be tested. A twenty-second timeout
/// verified by a twenty-second test is a timeout nobody runs.
fn decode_within(
    libexec_dir: &Path,
    kind: AttachKind,
    hint: &str,
    encoded: &[u8],
    deadline: Duration,
) -> Result<Decoded, String> {
    let helper = libexec_dir.join("ai-daemon-decode");
    if !helper.exists() {
        return Err(format!("{} is not installed", helper.display()));
    }
    let kind_str = match kind {
        AttachKind::Image => "image",
        AttachKind::Audio => "audio",
    };

    let mut command = Command::new(&helper);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .env_clear();
    // Its own process group, so the deadline can kill everything the decoder
    // started and not just the decoder. The shipped helper starts nothing —
    // its seccomp filter allows no clone, fork or execve — but "the helper has
    // no children" is a property of the helper, and a deadline should not
    // depend on the thing it is policing behaving.
    //
    // SAFETY: setsid is async-signal-safe and is the only call between fork
    // and exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("spawning the decoder: {e}"))?;
    let group = child.id() as libc::pid_t;

    let mut stdin = child.stdin.take().ok_or("decoder has no stdin")?;
    let mut stdout = child.stdout.take().ok_or("decoder has no stdout")?;

    let request = DecodeRequest {
        kind: kind_str.to_string(),
        hint: hint.to_string(),
        len: encoded.len() as u64,
        max_output: MAX_DECODED,
    };
    // Written on a thread: a decoder that refuses to read would otherwise
    // deadlock this one on a full pipe. Killing the group below is what
    // unblocks it if that happens.
    let payload = encoded.to_vec();
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        frame::write_cbor(&mut stdin, &request)?;
        frame::write_blob(&mut stdin, &payload)?;
        stdin.flush()
    });

    // The deadline lives on the read, which is the whole of the fix.
    //
    // The obvious shape — read the reply, then check how long that took — can
    // only fire in the case where enforcing it is pointless: it needs the read
    // to *return* before it looks at the clock, so a decoder that simply never
    // answers is never killed, and the only branch that runs is the one where
    // a good result has already arrived and gets thrown away.
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&stdout);
    let outcome = {
        let mut reader = DeadlineReader {
            inner: &mut stdout,
            fd,
            deadline: Instant::now() + deadline,
        };
        read_reply(&mut reader)
    };
    let timed_out = matches!(&outcome, Err(e) if e.contains("ran out of time"));

    // SAFETY: a kill of a process group we created and have not yet reaped, so
    // the id cannot have been recycled.
    unsafe {
        libc::kill(-group, libc::SIGKILL);
    }
    let status = child.wait().map_err(|e| format!("waiting for the decoder: {e}"))?;
    let _ = writer.join();

    if timed_out {
        return Err(format!(
            "the decoder did not answer within {}s and was killed",
            deadline.as_secs_f32()
        ));
    }

    let decoded = match outcome {
        Ok(decoded) => decoded,
        // A decoder killed by SIGSYS is the confinement working, and it is
        // worth saying so by name: without this the message is "the decoder
        // produced nothing", which reads like a bug in the codec rather than a
        // syscall the cage did not allow.
        Err(e) => {
            use std::os::unix::process::ExitStatusExt;
            return Err(match status.signal() {
                Some(libc::SIGSYS) => format!(
                    "the decoder was killed by its own seccomp filter, which means it \
                     attempted a syscall the filter does not allow: {e}"
                ),
                Some(libc::SIGKILL) => e,
                Some(signal) => format!("the decoder died on signal {signal}: {e}"),
                None => e,
            });
        }
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// A stand-in decoder. The real one is a separate package binary; what is
    /// under test here is the daemon's side of the contract, and the only
    /// thing that needs to be true of the child is how it (mis)behaves.
    fn helper_dir(name: &str, script: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("ai-daemon-decode-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ai-daemon-decode");
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "#!/bin/sh\n{script}").unwrap();
        drop(file);
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        dir
    }

    /// The regression. Before the reaper, this call never returned: the read
    /// blocked forever and the elapsed-time check sat behind it, so a decoder
    /// that says nothing was never killed. It wedged the session thread that
    /// called it, permanently.
    #[test]
    fn a_decoder_that_never_answers_is_killed_at_the_deadline() {
        let dir = helper_dir("silent", "sleep 300");
        let started = Instant::now();
        let error = decode_within(
            &dir,
            AttachKind::Image,
            "image/png",
            b"whatever",
            Duration::from_millis(700),
        )
        .unwrap_err();

        assert!(error.contains("did not answer"), "{error}");
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "took {:?}; the deadline did not fire",
            started.elapsed()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The other half of the hang: a decoder that never *reads*. The writer
    /// thread fills the pipe and blocks; killing the child is what unblocks it.
    #[test]
    fn a_decoder_that_never_reads_its_input_is_also_killed() {
        let dir = helper_dir("deaf", "exec sleep 300 </dev/null");
        let big = vec![0u8; 4 * 1024 * 1024];
        let error = decode_within(
            &dir,
            AttachKind::Image,
            "image/png",
            &big,
            Duration::from_millis(700),
        )
        .unwrap_err();
        assert!(error.contains("did not answer"), "{error}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A decoder that exits without saying anything must be an error promptly,
    /// not a wait for the full deadline.
    #[test]
    fn a_decoder_that_exits_silently_fails_without_waiting_out_the_clock() {
        let dir = helper_dir("mute", "exit 3");
        let started = Instant::now();
        let error = decode_within(
            &dir,
            AttachKind::Image,
            "image/png",
            b"whatever",
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(error.contains("produced nothing"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_missing_helper_is_reported_rather_than_spawned() {
        let error = decode_within(
            std::path::Path::new("/nonexistent"),
            AttachKind::Image,
            "image/png",
            b"x",
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(error.contains("is not installed"), "{error}");
    }
}
