// SPDX-License-Identifier: Apache-2.0

//! Asking the user, through the mechanism the desktop already has.
//!
//! polkit rather than a bespoke dialog because the answer to "may this app use
//! the local model" belongs in the same place as every other authorisation
//! decision on the machine: one agent, one set of rules, one audit trail, and
//! `pkaction`/`pkcheck` work on it without ai-daemon inventing a CLI for them.
//!
//! The subject is `unix-process` with a start time, not a bare pid: a pid on
//! its own is reusable, and a grant remembered against a reused pid is a grant
//! given to the wrong program.

use std::collections::HashMap;

use zbus::zvariant::Value;

use crate::identity::Identity;

const AUTHORITY_DEST: &str = "org.freedesktop.PolicyKit1";
const AUTHORITY_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const AUTHORITY_IFACE: &str = "org.freedesktop.PolicyKit1.Authority";

/// `AllowUserInteraction`: polkit may put a dialog in front of the user. The
/// caller is blocked while that happens, which is why every consent check
/// happens on a session's own thread and never on the bus thread.
const FLAG_ALLOW_INTERACTION: u32 = 1;

pub fn check_authorization(
    conn: &zbus::blocking::Connection,
    identity: &Identity,
    action_id: &str,
) -> Result<bool, String> {
    let start_time = process_start_time(identity.pid).unwrap_or(0);

    let mut subject_details: HashMap<&str, Value<'_>> = HashMap::new();
    subject_details.insert("pid", Value::U32(identity.pid.max(0) as u32));
    subject_details.insert("start-time", Value::U64(start_time));
    let subject = ("unix-process", subject_details);

    // Details reach the authentication dialog, so polkit accepts them only
    // from uid 0 or from the action's declared owner — a mechanism that could
    // set them freely could put words in front of a user about to type their
    // password. This daemon is neither root nor, on an install whose polkit
    // predates the owner annotation, an owner; so it asks with the details it
    // would like and, if refused for that reason, asks again without them.
    //
    // Losing the app's name from the dialog is a real loss and the fallback is
    // the right one anyway: the wording then comes from the .policy file the
    // package installs, where an administrator can read it.
    let display = identity.display();
    let mut details: HashMap<&str, &str> = HashMap::new();
    details.insert("application", &display);
    details.insert("identity.class", identity.class.as_str());

    match ask(conn, subject.clone(), action_id, details) {
        Ok(authorized) => Ok(authorized),
        Err(e) if e.contains("pass details") => ask(conn, subject, action_id, HashMap::new()),
        Err(e) => Err(e),
    }
}

type Subject<'a> = (&'a str, HashMap<&'a str, Value<'a>>);

fn ask(
    conn: &zbus::blocking::Connection,
    subject: Subject<'_>,
    action_id: &str,
    details: HashMap<&str, &str>,
) -> Result<bool, String> {
    let reply = conn
        .call_method(
            Some(AUTHORITY_DEST),
            AUTHORITY_PATH,
            Some(AUTHORITY_IFACE),
            "CheckAuthorization",
            &(subject, action_id, details, FLAG_ALLOW_INTERACTION, ""),
        )
        .map_err(|e| e.to_string())?;

    let ((authorized, challenge, _details),): ((bool, bool, HashMap<String, String>),) =
        reply.body().deserialize().map_err(|e| e.to_string())?;
    interpret(authorized, challenge)
}

/// polkit's answer, read the way the caller in `policy.rs` needs it.
///
/// The `is_challenge` half of the reply is the difference between a refusal
/// and a question nobody was there to answer, and dropping it is not a
/// rounding error: `auth_admin` on a machine with no authentication agent —
/// a headless box, a container, an ssh session, the state every `.policy`
/// action here defaults to — comes back `(false, true)`, and reading that as
/// a plain `false` records a permanent deny for a user who was never asked.
/// The grant table then short-circuits every later attempt, so fixing the
/// polkit configuration afterwards changes nothing, and the documented way
/// out (`aidctl revoke`) needs the capability that is now denied.
///
/// So the three cases are three cases:
///
/// - `(true, _)` — the subject may proceed.
/// - `(false, false)` — a real refusal: no rule permits this subject, and no
///   authentication would change that. Worth remembering.
/// - `(false, true)` — authentication was required and none arrived. Nobody
///   answered, so there is nothing to remember — `Err` puts this on the
///   caller's "no authority could be reached" path, which refuses without
///   writing a decision down.
///
/// A user who dismisses the dialog lands in the third case too, and that is
/// the right home for it: closing a prompt is not a decision to be held to
/// for the life of the install.
fn interpret(authorized: bool, challenge: bool) -> Result<bool, String> {
    match (authorized, challenge) {
        (true, _) => Ok(true),
        (false, false) => Ok(false),
        (false, true) => Err(
            "polkit requires authentication for this action and no authentication \
             agent answered; run an agent (pkttyagent works on a terminal) or grant \
             the action in a polkit rule"
                .into(),
        ),
    }
}

/// Field 22 of `/proc/<pid>/stat`, in clock ticks since boot.
///
/// The comm field is parenthesised and may itself contain spaces and
/// parentheses, so the only safe split is at the *last* `)`.
pub fn process_start_time(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let tail = &stat[stat.rfind(')')? + 1..];
    tail.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_authorized_subject_proceeds() {
        assert_eq!(interpret(true, false), Ok(true));
        assert_eq!(interpret(true, true), Ok(true), "authorized wins over a stale challenge bit");
    }

    #[test]
    fn a_refusal_no_authentication_could_change_is_an_answer() {
        assert_eq!(
            interpret(false, false),
            Ok(false),
            "allow_any=no with no matching rule is a decision, and remembering it is correct"
        );
    }

    /// The regression this function exists for. `auth_admin` with no agent
    /// running is the default state of every headless install, and it must
    /// not reach the grant table — `Err` is what routes it to the caller's
    /// refuse-without-recording path.
    #[test]
    fn an_unanswered_challenge_is_not_a_denial() {
        assert!(
            interpret(false, true).is_err(),
            "nobody was asked, so there is no decision to persist"
        );
    }
}
