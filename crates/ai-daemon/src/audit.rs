// SPDX-License-Identifier: Apache-2.0

//! The record of what happened, and nothing about what was said.
//!
//! §5 is unambiguous: identity, model and byte counts are logged; content is
//! never logged. This module exists so that rule has exactly one place to be
//! broken, and so that reviewing whether it holds means reading one file.
//!
//! Records go to the journal — natively with structured `AI_*` fields where
//! journald's socket exists, via stderr where it does not — and to a
//! newline-delimited JSON file that survives log rotation policy the admin
//! did not choose. `journalctl -t ai-daemon AI_IDENTITY=… -o json` is the
//! query interface; the file is the evidence.
//!
//! ## The chain
//!
//! The design record asks for a hash-chained log, and the word that matters in
//! it is *tamper-evident* — not tamper-proof. Every record carries the hash of
//! the one before it, so the file is a chain rather than a pile: an edited
//! line, a deleted line or a reordered pair breaks the link at that point and
//! `aidctl audit --verify` says which line and how.
//!
//! What that is worth, stated honestly, because it is easy to oversell:
//!
//! * It detects **retrospective** edits. Somebody who alters a record after
//!   the fact cannot leave the file consistent without rewriting every record
//!   after it too.
//! * It does not stop somebody who owns the file from rewriting the whole
//!   chain from the point of the edit. Nothing local can, short of a signature
//!   over a key the daemon does not hold or an append-only store it does not
//!   have. The chain raises the cost from "edit one line" to "rewrite the
//!   remainder", and makes truncation visible as a missing tail rather than
//!   invisible as a shorter file.
//! * The daemon runs as its own uid and the file is 0600, so the people this
//!   defends against are the ones who have already got that far.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Serialize;

use crate::identity::Identity;
use crate::policy::now_secs;
use crate::{info, warn};

#[derive(Debug, Serialize)]
pub struct Record<'a> {
    pub at: u64,
    pub event: &'a str,
    pub identity: &'a str,
    pub class: &'a str,
    pub uid: u32,
    pub pid: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<&'a str>,
    /// The previous record's hash. Set by the writer, never by a caller —
    /// which is why it is last in the struct and therefore last on the line:
    /// what gets hashed is everything before it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<&'a str>,
}

pub struct Audit {
    file: Mutex<Option<std::fs::File>>,
    path: Option<PathBuf>,
    /// The hash of the last record written, which the next one carries.
    ///
    /// Recovered from the file at startup rather than restarted, or every
    /// daemon restart would be an unexplained break in the chain and the
    /// verifier would cry wolf at the one event that happens most.
    head: Mutex<Option<String>>,
    /// The journal's native socket, when this machine has one.
    ///
    /// Structured fields (`AI_IDENTITY=`, `AI_MODEL=`, …) make
    /// `journalctl -t ai-daemon AI_IDENTITY=unit:claude-code@1000 -o json`
    /// a query instead of a grep, which is what per-app accounting is for.
    /// When a record is delivered this way the stderr line is *not* also
    /// written — both land in the same journal under the same unit, and a
    /// meter that shows every turn twice is wrong in the way that spreads.
    /// Where there is no journal (a container, a dev run) or a send fails,
    /// stderr carries the same line it always has.
    journal: Option<std::os::unix::net::UnixDatagram>,
}

impl Audit {
    pub fn new(state_dir: &Path) -> Audit {
        let path = state_dir.join("audit.jsonl");
        // Read the tail before opening for append, so the chain continues
        // across a restart instead of starting a second one in the same file.
        let head = head_of(&path);
        let journal = journal_socket();
        match std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            Ok(file) => {
                if let Some(h) = &head {
                    info!("audit: continuing the chain from {}", &h[..16.min(h.len())]);
                }
                Audit {
                    file: Mutex::new(Some(file)),
                    path: Some(path),
                    head: Mutex::new(head),
                    journal,
                }
            }
            Err(e) => {
                warn!("audit: cannot open {} ({e}); journal only", path.display());
                Audit { file: Mutex::new(None), path: None, head: Mutex::new(None), journal }
            }
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn write(&self, record: Record<'_>) {
        // Structured first: on a machine with a journal, fields make the
        // record queryable and the terse line below is not also written —
        // same unit, same journal, and a meter that counts every turn twice
        // is wrong in the way that spreads.
        let delivered = self
            .journal
            .as_ref()
            .is_some_and(|socket| socket.send(&journal_payload(&record)).is_ok());
        if delivered {
            return self.append(record);
        }
        // The journal line is deliberately terse and fixed-shape: it is read by
        // humans looking for "who used what", and grep is the query language.
        info!(
            "audit {} identity={} class={} uid={} pid={}{}{}{}{}",
            record.event,
            record.identity,
            record.class,
            record.uid,
            record.pid,
            record.session.map(|s| format!(" session={s}")).unwrap_or_default(),
            record.model.map(|m| format!(" model={m}")).unwrap_or_default(),
            match (record.prompt_tokens, record.completion_tokens) {
                (Some(p), Some(c)) => format!(" prompt_tokens={p} completion_tokens={c}"),
                _ => String::new(),
            },
            record.detail.map(|d| format!(" detail={d}")).unwrap_or_default(),
        );
        self.append(record);
    }

    /// The chained file, which every record reaches however the journal half
    /// went.
    fn append(&self, record: Record<'_>) {
        let mut guard = self.file.lock().unwrap();
        if let Some(file) = guard.as_mut() {
            // The link is taken and replaced under the file lock, so two
            // threads cannot both chain onto the same predecessor and produce
            // a fork that reads as tampering.
            let mut head = self.head.lock().unwrap();
            let mut record = record;
            record.prev = head.as_deref();
            match serde_json::to_string(&record) {
                Ok(line) => {
                    *head = Some(hash_line(&line));
                    let _ = writeln!(file, "{line}");
                    let _ = file.flush();
                }
                Err(e) => warn!("audit: could not serialise record ({e})"),
            }
        }
    }

    pub fn session_start(&self, identity: &Identity, session: &str, model: &str, digest: &str, local: bool) {
        self.write(Record {
            at: now_secs(),
            event: "session-start",
            identity: &identity.key(),
            class: identity.class.as_str(),
            uid: identity.uid,
            pid: identity.pid,
            session: Some(session),
            model: Some(model),
            digest: Some(digest),
            local: Some(local),
            prompt_tokens: None,
            completion_tokens: None,
            attachment_bytes: None,
            detail: None,
            prev: None,
        });
    }

    pub fn session_end(
        &self,
        identity: &Identity,
        session: &str,
        model: &str,
        prompt_tokens: u64,
        completion_tokens: u64,
        attachment_bytes: u64,
    ) {
        self.write(Record {
            at: now_secs(),
            event: "session-end",
            identity: &identity.key(),
            class: identity.class.as_str(),
            uid: identity.uid,
            pid: identity.pid,
            session: Some(session),
            model: Some(model),
            digest: None,
            local: None,
            prompt_tokens: Some(prompt_tokens),
            completion_tokens: Some(completion_tokens),
            attachment_bytes: Some(attachment_bytes),
            detail: None,
            prev: None,
        });
    }

    pub fn denied(&self, identity: &Identity, capability: &str, reason: &str) {
        self.write(Record {
            at: now_secs(),
            event: "denied",
            identity: &identity.key(),
            class: identity.class.as_str(),
            uid: identity.uid,
            pid: identity.pid,
            session: None,
            model: Some(capability),
            digest: None,
            local: None,
            prompt_tokens: None,
            completion_tokens: None,
            attachment_bytes: None,
            detail: Some(reason),
            prev: None,
        });
    }
}

/// The hash of one record's line, which the next record carries as `prev`.
///
/// Over the line exactly as written, so verification is a re-read rather than
/// a re-serialisation: nothing depends on serde emitting fields in the same
/// order next release, and a verifier written in another language can check
/// the file with sha256sum and a text editor.
/// A datagram socket aimed at journald's native endpoint, or nothing.
///
/// Unconnected sends to a path would need `sendto` per record; connecting once
/// here means a machine without a journal costs one failed connect at startup
/// and nothing after.
fn journal_socket() -> Option<std::os::unix::net::UnixDatagram> {
    let socket = std::os::unix::net::UnixDatagram::unbound().ok()?;
    socket.connect("/run/systemd/journal/socket").ok()?;
    Some(socket)
}

/// One record in the journal's native protocol.
///
/// Every field uses the length-prefixed form (`NAME\n` + little-endian u64
/// length + bytes + `\n`) rather than `NAME=value\n`, because the simple form
/// is only legal for values without newlines and a `detail` is prose from an
/// error path — encoding by shape of content is how a log format grows a
/// parser bug. Field names are the query surface and are stable:
/// `journalctl -t ai-daemon AI_IDENTITY=... -o json` is the interface.
fn journal_payload(record: &Record<'_>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    let mut field = |name: &str, value: &str| {
        buf.extend_from_slice(name.as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(&(value.len() as u64).to_le_bytes());
        buf.extend_from_slice(value.as_bytes());
        buf.push(b'\n');
    };
    field(
        "MESSAGE",
        &format!(
            "audit {} identity={} model={} tokens={}/{}",
            record.event,
            record.identity,
            record.model.unwrap_or("-"),
            record.prompt_tokens.unwrap_or(0),
            record.completion_tokens.unwrap_or(0),
        ),
    );
    field("PRIORITY", "6");
    field("SYSLOG_IDENTIFIER", "ai-daemon");
    field("AI_EVENT", record.event);
    field("AI_IDENTITY", record.identity);
    field("AI_CLASS", record.class);
    field("AI_UID", &record.uid.to_string());
    field("AI_PID", &record.pid.to_string());
    if let Some(session) = record.session {
        field("AI_SESSION", session);
    }
    if let Some(model) = record.model {
        field("AI_MODEL", model);
    }
    if let Some(digest) = record.digest {
        field("AI_DIGEST", digest);
    }
    if let Some(local) = record.local {
        field("AI_LOCAL", if local { "true" } else { "false" });
    }
    if let Some(n) = record.prompt_tokens {
        field("AI_PROMPT_TOKENS", &n.to_string());
    }
    if let Some(n) = record.completion_tokens {
        field("AI_COMPLETION_TOKENS", &n.to_string());
    }
    if let Some(n) = record.attachment_bytes {
        field("AI_ATTACHMENT_BYTES", &n.to_string());
    }
    if let Some(detail) = record.detail {
        field("AI_DETAIL", detail);
    }
    buf
}

fn hash_line(line: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(line.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// The hash of the last usable record in an existing file.
///
/// A trailing partial line — the daemon was killed mid-write — is dropped
/// rather than chained onto, because chaining onto a truncated record would
/// bake the truncation into every later link and make the whole tail
/// unverifiable. The partial line stays in the file, where the verifier will
/// name it.
fn head_of(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines().rev().find(|l| !l.trim().is_empty()).and_then(|last| {
        serde_json::from_str::<serde_json::Value>(last).ok().map(|_| hash_line(last))
    })
}

/// Walk the chain and report the first break.
///
/// Not called by the daemon — the daemon writes the chain, `aidctl audit`
/// reads it, and a verifier the writer runs on itself proves little. It lives
/// here so the format has one definition in this crate and the tests below
/// exercise the same code a reader would.
///
/// Returns the number of records checked, or the line number and reason it
/// stopped being checkable. Deliberately a free function over a path rather
/// than a method: verifying the log is something you want to do to a *copy*,
/// on another machine, without a daemon.
#[cfg_attr(not(test), allow(dead_code))]
pub fn verify(path: &Path) -> Result<u64, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let mut expected: Option<String> = None;
    let mut checked = 0u64;
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        if line.trim().is_empty() {
            continue;
        }
        let record: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| format!("line {number} is not a record: {e}"))?;
        let carried = record.get("prev").and_then(|p| p.as_str());
        match (&expected, carried) {
            // The first record carries nothing: there is nothing before it.
            (None, None) => {}
            (None, Some(p)) => {
                return Err(format!(
                    "line {number} claims to follow {} but it is the first record in this file — \
                     everything before it is missing",
                    &p[..16.min(p.len())]
                ))
            }
            (Some(_), None) => {
                return Err(format!(
                    "line {number} carries no link, so the chain restarts here — a record \
                     written by something that did not know about the chain, or a splice"
                ))
            }
            (Some(want), Some(got)) if want != got => {
                return Err(format!(
                    "line {number} follows {} but the record before it hashes to {} — \
                     something between them was changed, removed or reordered",
                    &got[..16.min(got.len())],
                    &want[..16.min(want.len())]
                ))
            }
            (Some(_), Some(_)) => {}
        }
        expected = Some(hash_line(line));
        checked += 1;
    }
    Ok(checked)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_three(dir: &Path) -> PathBuf {
        let audit = Audit::new(dir);
        for event in ["one", "two", "three"] {
            audit.write(Record {
                at: 0,
                event,
                identity: "uid:1",
                class: "native",
                uid: 1,
                pid: 2,
                session: None,
                model: None,
                digest: None,
                local: None,
                prompt_tokens: None,
                completion_tokens: None,
                attachment_bytes: None,
                detail: None,
                prev: None,
            });
        }
        dir.join("audit.jsonl")
    }

    #[test]
    fn an_untouched_log_verifies() {
        let dir = scratch("intact");
        let path = write_three(&dir);
        assert_eq!(verify(&path).unwrap(), 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The point of the whole thing: an edit after the fact is visible.
    #[test]
    fn an_edited_record_breaks_the_chain_at_the_next_line() {
        let dir = scratch("edited");
        let path = write_three(&dir);
        let text = std::fs::read_to_string(&path).unwrap();
        let tampered = text.replacen("\"uid\":1", "\"uid\":0", 1);
        std::fs::write(&path, tampered).unwrap();

        let error = verify(&path).expect_err("an edited record must not verify");
        // Line 2, because line 1 is what changed and line 2 is what no longer
        // matches it — naming the wrong one would send somebody to the wrong
        // record.
        assert!(error.contains("line 2"), "{error}");
        assert!(error.contains("changed, removed or reordered"), "{error}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Deleting a record is the case the chain exists for: without it, a
    /// shorter file is just a shorter file.
    #[test]
    fn a_deleted_record_breaks_the_chain() {
        let dir = scratch("deleted");
        let path = write_three(&dir);
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();

        let error = verify(&path).expect_err("a deleted record must not verify");
        assert!(error.contains("line 2"), "{error}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Restarting the daemon must not look like tampering, which it would if
    /// the chain began again at every process start.
    #[test]
    fn the_chain_survives_a_restart() {
        let dir = scratch("restart");
        write_three(&dir);
        // A second Audit over the same directory is what a restart is.
        let again = Audit::new(&dir);
        again.write(Record {
            at: 0,
            event: "after-restart",
            identity: "uid:1",
            class: "native",
            uid: 1,
            pid: 2,
            session: None,
            model: None,
            digest: None,
            local: None,
            prompt_tokens: None,
            completion_tokens: None,
            attachment_bytes: None,
            detail: None,
            prev: None,
        });
        assert_eq!(verify(&dir.join("audit.jsonl")).unwrap(), 4);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
