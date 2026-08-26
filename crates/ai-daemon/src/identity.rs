//! Who is asking (§5).
//!
//! The honest summary, which the daemon repeats rather than hides: Linux has
//! no way to verify that the binary behind a socket is the binary it claims to
//! be. There is no code-signature check on a peer. What the kernel *will* tell
//! us is uid, gid and pid, and from pid we can read the cgroup and so the
//! systemd unit. That is real information and it is worth acting on — it is
//! just not proof, and anything with privilege in the same session can forge
//! it.
//!
//! So identities carry their own [`Class`], the daemon shows it in every
//! consent prompt, and policy can be written against it. A portal-introduced
//! app is strong identity. A native process is a good guess. The HTTP shim is
//! the weakest thing we accept and says so.

use std::fmt;
use std::path::Path;

/// How much the identity below is worth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    /// Asserted by xdg-desktop-portal, which the daemon trusts as an
    /// introducer. The only strong app identity on this platform.
    Portal,
    /// Peer credentials plus the caller's systemd unit. Spoofable by a
    /// sufficiently privileged process in the same session.
    Native,
    /// Peer credentials of whatever connected to the OpenAI-compat socket.
    /// Lowest trust: the whole point of the shim is that the client was
    /// written for a server with no policy at all.
    Shim,
}

impl Class {
    pub fn as_str(self) -> &'static str {
        match self {
            Class::Portal => "portal",
            Class::Native => "native",
            Class::Shim => "shim",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub class: Class,
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
    /// systemd unit or scope owning the caller, if we could read one.
    pub unit: Option<String>,
    /// Flatpak/Snap application id, only ever set on the portal path.
    pub app_id: Option<String>,
    /// `/proc/<pid>/exe` basename. Advisory; used in prompts, never as the key
    /// on its own.
    pub exe: Option<String>,
}

impl Identity {
    /// The string grants are keyed by, and the string `aidctl grants` prints.
    ///
    /// Stability matters more than beauty here: a grant is remembered against
    /// this, so it must not change when a process restarts under a new pid.
    pub fn key(&self) -> String {
        match self.class {
            Class::Portal => format!(
                "portal:{}",
                self.app_id.as_deref().unwrap_or("unknown")
            ),
            Class::Native => match (&self.unit, &self.exe) {
                (Some(unit), _) => format!("unit:{unit}@{}", self.uid),
                (None, Some(exe)) => format!("exe:{exe}@{}", self.uid),
                (None, None) => format!("uid:{}", self.uid),
            },
            Class::Shim => match &self.exe {
                Some(exe) => format!("shim:{exe}@{}", self.uid),
                None => format!("shim:uid:{}", self.uid),
            },
        }
    }

    /// What a human sees in a consent dialog.
    pub fn display(&self) -> String {
        match self.class {
            Class::Portal => self.app_id.clone().unwrap_or_else(|| "an app".into()),
            _ => self
                .exe
                .clone()
                .or_else(|| self.unit.clone())
                .unwrap_or_else(|| format!("pid {}", self.pid)),
        }
    }

    /// Build from credentials obtained some other way — over D-Bus, the bus
    /// daemon is the one holding the socket, so it answers for the peer.
    pub fn from_pid_uid(pid: i32, uid: u32, gid: u32, class: Class) -> Identity {
        Identity {
            class,
            uid,
            gid,
            pid,
            unit: unit_of_pid(pid),
            app_id: None,
            exe: exe_of_pid(pid),
        }
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}]", self.key(), self.class.as_str())
    }
}

/// The systemd unit or scope a pid belongs to, from cgroup v2.
///
/// `/proc/<pid>/cgroup` on a v2 host is one line, `0::/user.slice/...`. We take
/// the last path component that looks like a unit; a `.scope` is as much an
/// answer as a `.service`, since that is how a desktop session's apps appear.
pub fn unit_of_pid(pid: i32) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    unit_from_cgroup(&text)
}

/// The parsing half, separated so it can be tested against the shapes real
/// machines produce rather than against whatever this container happens to be.
///
/// The *innermost* unit wins. A desktop app sits under `user@1000.service`,
/// which is a unit but is the session manager rather than the app; the app's
/// own `.scope` is what a grant should be remembered against.
pub fn unit_from_cgroup(text: &str) -> Option<String> {
    for line in text.lines() {
        let path = line.rsplit_once("::").map(|(_, p)| p).unwrap_or(line);
        let path = path.rsplit_once(':').map(|(_, p)| p).unwrap_or(path);
        let unit = path
            .split('/')
            .rfind(|c| c.ends_with(".service") || c.ends_with(".scope"));
        if let Some(unit) = unit {
            return Some(unit.to_string());
        }
    }
    None
}

/// Every group a pid is in: its primary gid and its supplementary set.
///
/// Read from `/proc/<pid>/status` rather than asked of NSS, because the answer
/// must be about *that process as it exists now*, not about what the user's
/// entry currently says. A user added to a group after their session started
/// is genuinely not in it yet, and pretending otherwise would make the gate
/// disagree with the kernel.
pub fn groups_of_pid(pid: i32) -> Vec<u32> {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return Vec::new();
    };
    let mut groups = Vec::new();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Gid:") {
            if let Some(real) = rest.split_whitespace().next() {
                if let Ok(gid) = real.parse() {
                    groups.push(gid);
                }
            }
        }
        if let Some(rest) = line.strip_prefix("Groups:") {
            groups.extend(rest.split_whitespace().filter_map(|g| g.parse::<u32>().ok()));
        }
    }
    groups
}

/// A group's gid, from `/etc/group`. Same reasoning as the passwd lookup in
/// the registry: the daemon runs with a locked-down NSS surface and a number
/// out of a text file is all this needs.
pub fn gid_of_group(name: &str) -> Option<u32> {
    let text = std::fs::read_to_string("/etc/group").ok()?;
    gid_from_group_file(&text, name)
}

pub fn gid_from_group_file(text: &str, name: &str) -> Option<u32> {
    field_two(text, name)
}

/// A user's uid, from `/etc/passwd`, for the same reason.
///
/// Used to recognise the daemon's own helpers — the shim introduces its HTTP
/// callers and must be identified before that assertion is believed, and it
/// cannot be identified by executable name because the daemon cannot read
/// `/proc/<pid>/exe` for a process it does not own.
pub fn uid_of_user(name: &str) -> Option<u32> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    uid_from_passwd_file(&text, name)
}

pub fn uid_from_passwd_file(text: &str, name: &str) -> Option<u32> {
    field_two(text, name)
}

/// `name:x:ID:…` is the shape of both files, so one parser does both.
fn field_two(text: &str, name: &str) -> Option<u32> {
    for line in text.lines() {
        let mut fields = line.split(':');
        if fields.next()? == name {
            let _password = fields.next()?;
            return fields.next()?.parse().ok();
        }
    }
    None
}

/// The caller's executable, when the kernel will tell us.
///
/// It usually will not. Reading `/proc/<pid>/exe` needs ptrace-level access to
/// the target, so a daemon running as its own system user gets `None` for
/// every process belonging to a human — which is most of them. It is kept
/// because it costs nothing and is genuinely useful for same-uid callers, and
/// because `None` here is what makes an identity fall back to something
/// coarser rather than to something wrong.
///
/// `/proc/<pid>/comm` is world-readable and would fill the gap. It is
/// deliberately not used: any process can set its own `comm`, so an identity
/// built on it could be chosen by the process being identified — which is
/// worse than a coarse identity, not better. `/proc/<pid>/cgroup` is also
/// world-readable and is *not* self-selectable, which is why the unit is the
/// part that carries weight.
pub fn exe_of_pid(pid: i32) -> Option<String> {
    let target = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    Path::new(&target)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cgroup_v2_line_yields_the_unit() {
        assert_eq!(
            unit_from_cgroup("0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-foo.scope\n"),
            Some("app-foo.scope".to_string())
        );
        assert_eq!(
            unit_from_cgroup("0::/system.slice/ai-daemon.service\n"),
            Some("ai-daemon.service".to_string())
        );
    }

    #[test]
    fn the_innermost_unit_wins_not_the_outermost() {
        // user@1000.service is a real unit, but the app's own scope is the
        // thing a grant should be remembered against.
        assert_eq!(
            unit_from_cgroup("0::/user.slice/user@1000.service/app.slice/app-gnome-editor.scope"),
            Some("app-gnome-editor.scope".to_string())
        );
    }

    #[test]
    fn a_container_with_no_units_has_no_unit() {
        assert_eq!(unit_from_cgroup("0::/\n"), None);
        assert_eq!(unit_from_cgroup("0::/docker/abc123\n"), None);
    }

    #[test]
    fn cgroup_v1_lines_are_understood_too() {
        assert_eq!(
            unit_from_cgroup(
                "11:name=systemd:/user.slice/user-1000.slice/session-2.scope\n1:cpu:/\n"
            ),
            Some("session-2.scope".to_string())
        );
    }

    #[test]
    fn an_identity_key_is_stable_across_a_restart() {
        // pid changes, the key must not: a grant remembered against a pid
        // would be a grant for whatever reuses that pid.
        let first = Identity {
            class: Class::Native,
            uid: 1000,
            gid: 1000,
            pid: 4242,
            unit: Some("app-foo.scope".into()),
            app_id: None,
            exe: Some("foo".into()),
        };
        let second = Identity { pid: 9999, ..first.clone() };
        assert_eq!(first.key(), second.key());
        assert_eq!(first.key(), "unit:app-foo.scope@1000");
    }

    #[test]
    fn identity_keys_are_distinct_per_class() {
        let base = Identity {
            class: Class::Native,
            uid: 1000,
            gid: 1000,
            pid: 1,
            unit: None,
            app_id: Some("org.gnome.Newelle".into()),
            exe: Some("aidctl".into()),
        };
        assert_eq!(base.key(), "exe:aidctl@1000");
        assert_eq!(Identity { class: Class::Shim, ..base.clone() }.key(), "shim:aidctl@1000");
        assert_eq!(
            Identity { class: Class::Portal, ..base }.key(),
            "portal:org.gnome.Newelle"
        );
    }

    #[test]
    fn a_passwd_line_yields_the_uid_the_shim_check_depends_on() {
        let passwd = "root:x:0:0::/root:/bin/bash\nai-daemon-shim:x:971:971::/:/usr/bin/nologin\n";
        assert_eq!(uid_from_passwd_file(passwd, "ai-daemon-shim"), Some(971));
        assert_eq!(uid_from_passwd_file(passwd, "nobody"), None);
    }

    #[test]
    fn a_group_line_is_parsed_from_etc_group_shape() {
        assert_eq!(gid_from_group_file("ai:x:987:alice,bob\nvideo:x:44:\n", "ai"), Some(987));
        assert_eq!(gid_from_group_file("ai:x:987:\n", "video"), None);
    }

    #[test]
    fn this_process_is_in_its_own_group_list() {
        let groups = groups_of_pid(std::process::id() as i32);
        assert!(!groups.is_empty(), "/proc/self/status always has a Gid line");
    }
}
