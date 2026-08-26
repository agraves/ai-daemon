//! The record of what happened, and nothing about what was said.
//!
//! §5 is unambiguous: identity, model and byte counts are logged; content is
//! never logged. This module exists so that rule has exactly one place to be
//! broken, and so that reviewing whether it holds means reading one file.
//!
//! Records go to the journal via stderr (so `journalctl -u ai-daemon` is the
//! interface) and, when configured, to a newline-delimited JSON file that
//! survives log rotation policy the admin did not choose.

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
}

pub struct Audit {
    file: Mutex<Option<std::fs::File>>,
    path: Option<PathBuf>,
}

impl Audit {
    pub fn new(state_dir: &Path) -> Audit {
        let path = state_dir.join("audit.jsonl");
        match std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            Ok(file) => Audit { file: Mutex::new(Some(file)), path: Some(path) },
            Err(e) => {
                warn!("audit: cannot open {} ({e}); journal only", path.display());
                Audit { file: Mutex::new(None), path: None }
            }
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn write(&self, record: Record<'_>) {
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
        let mut guard = self.file.lock().unwrap();
        if let Some(file) = guard.as_mut() {
            match serde_json::to_string(&record) {
                Ok(line) => {
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
        });
    }
}
