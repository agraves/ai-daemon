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
        // Innermost outwards, taking the first component that names something
        // an app identity can be pinned to. Components that name a *launch*
        // rather than an app yield `None` here and are skipped.
        for component in path.split('/').rev() {
            if let Some(unit) = normalise_unit(component) {
                return Some(unit);
            }
        }
    }
    None
}

/// Turn one cgroup path component into a stable identity, or nothing.
///
/// This is where the grant key is decided, so it is where the per-launch noise
/// has to come off. Desktops mint a fresh transient scope for every launch and
/// put the pid or a random number in its name — GNOME's
/// `app-gnome-org.gnome.TextEditor-4242.scope` is a different string on every
/// start of the same editor. Keying a remembered grant on that string means
/// the grant dies with the process: the user is re-prompted every launch,
/// which is how a consent dialog becomes something people click through, and
/// `grants.json` grows a dead row per launch forever.
///
/// The rules, and what each is for:
///
/// * `*.service` — verbatim. A system service's unit name is already stable
///   and already means what it says.
/// * `app[-<launcher>]-<AppID>-<launch>.scope` — the XDG shape. Strip the
///   launcher and the launch token, keep the application id.
/// * `vte-spawn-*.scope`, `session-*.scope`, `user@*.service` — nothing. These
///   name a terminal tab, a login session and a session manager respectively.
///   None of them is an application, and a key built on one would either
///   change per tab or be the uid wearing a disguise, so the caller falls back
///   to executable-and-uid, which says the same thing more honestly.
/// * anything else ending `.scope` — verbatim, which may be unstable but is at
///   least never two applications sharing one key.
pub fn normalise_unit(component: &str) -> Option<String> {
    if let Some(name) = component.strip_suffix(".service") {
        // `user@1000.service` is the per-user manager, not an app.
        if name.starts_with("user@") {
            return None;
        }
        return Some(component.to_string());
    }

    let name = component.strip_suffix(".scope")?;
    if name.starts_with("vte-spawn-") || name.starts_with("session-") || name == "init" {
        return None;
    }

    // snapd mints `snap.<snap>.<app>-<uuid>.scope` with a fresh uuid per
    // launch, which is the same defect as the app scopes below wearing a
    // different prefix. It needs its own arm rather than the trailing-token
    // rule: a uuid is five dash-separated groups, so popping one token at a
    // time stops at the first four-character group and leaves most of it
    // behind. Matching the whole 8-4-4-4-12 shape is also the safer trim —
    // nothing that is genuinely part of a snap or command name looks like
    // that, so two snaps cannot collide onto one key.
    if name.starts_with("snap.") {
        return Some(strip_launch_uuid(name).unwrap_or(name).to_string());
    }

    let Some(body) = name.strip_prefix("app-") else {
        return Some(component.to_string());
    };

    let mut parts: Vec<&str> = body.split('-').collect();
    // Trailing launch token. Only a plainly generated one is dropped: an
    // application id is reverse-DNS and may itself contain digits and dashes,
    // and trimming greedily would let two applications collide onto one key —
    // which is worse than an unstable key, because it silently shares a grant.
    if parts.len() > 1 && parts.last().is_some_and(|last| is_launch_token(last)) {
        parts.pop();
    }
    // Leading launcher (`gnome`, `flatpak`, `KDE`), present only when what
    // follows is the dotted application id.
    if parts.len() > 1 && !parts[0].contains('.') && parts[1..].iter().any(|p| p.contains('.')) {
        parts.remove(0);
    }
    if parts.is_empty() {
        return Some(component.to_string());
    }
    Some(parts.join("-"))
}

/// Remove a trailing `-<uuid>`, where uuid is the RFC 4122 8-4-4-4-12 hex
/// shape. `None` when the name does not end in one, so the caller can keep it
/// verbatim rather than guess.
fn strip_launch_uuid(name: &str) -> Option<&str> {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    let parts: Vec<&str> = name.split('-').collect();
    // Strictly more, so that something remains after the uuid is taken off.
    if parts.len() <= GROUPS.len() {
        return None;
    }
    let tail = &parts[parts.len() - GROUPS.len()..];
    if !tail
        .iter()
        .zip(GROUPS)
        .all(|(part, width)| part.len() == width && part.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return None;
    }
    // 32 hex digits, the four dashes inside the uuid, and the one before it.
    let suffix = GROUPS.iter().sum::<usize>() + GROUPS.len();
    Some(&name[..name.len() - suffix])
}

/// A pid or a systemd `$RANDOM`: all digits, or a long hex string. Anything
/// else is assumed to be part of the name.
fn is_launch_token(part: &str) -> bool {
    if part.is_empty() {
        return false;
    }
    part.bytes().all(|b| b.is_ascii_digit())
        || (part.len() >= 6 && part.bytes().all(|b| b.is_ascii_hexdigit()))
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
            unit_from_cgroup("0::/system.slice/ai-daemon.service\n"),
            Some("ai-daemon.service".to_string())
        );
    }

    #[test]
    fn the_innermost_unit_wins_not_the_outermost() {
        // user@1000.service is a real unit, but it is the session manager
        // rather than the app; the app's own scope is what a grant belongs to.
        assert_eq!(
            unit_from_cgroup(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-org.gnome.Nautilus-3312.scope"
            ),
            Some("org.gnome.Nautilus".to_string())
        );
    }

    /// The finding this replaces: the old test used `app-foo.scope`, a shape
    /// no desktop produces, so it passed while every real launch minted a new
    /// key. These are the shapes GNOME, KDE and Flatpak actually write.
    #[test]
    fn a_launch_token_is_stripped_from_a_transient_app_scope() {
        for (component, expected) in [
            ("app-gnome-org.gnome.TextEditor-4242.scope", "org.gnome.TextEditor"),
            ("app-org.gnome.Nautilus-1234.scope", "org.gnome.Nautilus"),
            ("app-flatpak-org.telegram.desktop-7781.scope", "org.telegram.desktop"),
            ("app-KDE-org.kde.dolphin-9012.scope", "org.kde.dolphin"),
            ("app-flatpak-md.obsidian.Obsidian-3f9a1c.scope", "md.obsidian.Obsidian"),
        ] {
            assert_eq!(
                normalise_unit(component).as_deref(),
                Some(expected),
                "{component}"
            );
        }
    }

    /// The property the whole key exists for, against the shape that broke it.
    #[test]
    fn the_same_app_launched_twice_has_one_key() {
        let launch = |pid: i32, scope: &str| Identity {
            class: Class::Native,
            uid: 1000,
            gid: 1000,
            pid,
            unit: unit_from_cgroup(&format!(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/{scope}"
            )),
            app_id: None,
            exe: Some("gnome-text-editor".into()),
        };
        let monday = launch(4242, "app-gnome-org.gnome.TextEditor-4242.scope");
        let tuesday = launch(9137, "app-gnome-org.gnome.TextEditor-9137.scope");

        assert_eq!(monday.key(), tuesday.key());
        assert_eq!(monday.key(), "unit:org.gnome.TextEditor@1000");
    }

    /// Two applications must never land on one key. A greedier strip would
    /// take `org.gnome.Text-Editor` down to `org.gnome.Text` and quietly hand
    /// one app's grant to another.
    #[test]
    fn two_applications_never_share_a_key() {
        let editor = normalise_unit("app-gnome-org.gnome.Text-Editor-4242.scope");
        let viewer = normalise_unit("app-gnome-org.gnome.Text-Viewer-4242.scope");
        assert_eq!(editor.as_deref(), Some("org.gnome.Text-Editor"));
        assert_eq!(viewer.as_deref(), Some("org.gnome.Text-Viewer"));
        assert_ne!(editor, viewer);
    }

    /// A terminal tab, a login session and the user manager are not
    /// applications. Keying on them would be per-tab noise or the uid in
    /// disguise, so they yield nothing and the caller falls back.
    #[test]
    fn a_scope_that_names_a_launch_rather_than_an_app_yields_nothing() {
        for component in [
            "vte-spawn-1c1a2b3c4d5e6f70819a2b3c4d5e6f70.scope",
            "session-2.scope",
            "user@1000.service",
            "init.scope",
        ] {
            assert_eq!(normalise_unit(component), None, "{component}");
        }
    }

    #[test]
    fn a_command_run_in_a_terminal_falls_back_to_the_executable() {
        let identity = Identity {
            class: Class::Native,
            uid: 1000,
            gid: 1000,
            pid: 77,
            unit: unit_from_cgroup(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-org.gnome.Terminal.slice/vte-spawn-1c1a2b3c4d5e6f70819a2b3c4d5e6f70.scope"
            ),
            app_id: None,
            exe: Some("aidctl".into()),
        };
        assert_eq!(identity.unit, None, "a terminal tab is not an app identity");
        assert_eq!(identity.key(), "exe:aidctl@1000");
    }

    /// Held as a minor residual after the grant-key fix landed, and closed
    /// here: snapd puts a fresh uuid in the scope name every launch, so the
    /// key rotated for snap-packaged apps exactly the way it used to for every
    /// app. Rare on the Arch target this ships for, real anywhere with snapd.
    #[test]
    fn a_snap_launch_uuid_is_stripped() {
        assert_eq!(
            normalise_unit("snap.spotify.spotify-1f2e3d4c-5b6a-7c8d-9e0f-a1b2c3d4e5f6.scope")
                .as_deref(),
            Some("snap.spotify.spotify")
        );
        // Snap names may contain dashes; matching the whole uuid shape rather
        // than popping tokens is what keeps them.
        assert_eq!(
            normalise_unit("snap.my-editor.my-editor-00112233-4455-6677-8899-aabbccddeeff.scope")
                .as_deref(),
            Some("snap.my-editor.my-editor")
        );
    }

    #[test]
    fn the_same_snap_launched_twice_has_one_key() {
        let key = |uuid: &str| {
            normalise_unit(&format!("snap.spotify.spotify-{uuid}.scope")).unwrap()
        };
        assert_eq!(
            key("1f2e3d4c-5b6a-7c8d-9e0f-a1b2c3d4e5f6"),
            key("ffeeddcc-bbaa-9988-7766-554433221100")
        );
    }

    #[test]
    fn a_snap_scope_without_a_uuid_is_left_alone() {
        // No uuid to strip, so it stays whole rather than being guessed at.
        assert_eq!(
            normalise_unit("snap.spotify.spotify.scope").as_deref(),
            Some("snap.spotify.spotify")
        );
        // A trailing hex run that is not the uuid shape is part of the name.
        assert_eq!(
            normalise_unit("snap.foo.bar-deadbeef.scope").as_deref(),
            Some("snap.foo.bar-deadbeef")
        );
    }

    #[test]
    fn a_system_service_keeps_its_own_name() {
        assert_eq!(
            normalise_unit("ai-daemon-shim.service").as_deref(),
            Some("ai-daemon-shim.service")
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
                "11:name=systemd:/user.slice/user-1000.slice/app.slice/app-org.kde.konsole-8123.scope\n1:cpu:/\n"
            ),
            Some("org.kde.konsole".to_string())
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
            unit: Some("ai-daemon-shim.service".into()),
            app_id: None,
            exe: Some("foo".into()),
        };
        let second = Identity { pid: 9999, ..first.clone() };
        assert_eq!(first.key(), second.key());
        assert_eq!(first.key(), "unit:ai-daemon-shim.service@1000");
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
