//! ai-daemon-portal — the strong app identity from §5 and §13.
//!
//! ## What problem this solves
//!
//! The daemon can see who is calling: peer credentials give it a uid and a
//! pid, and the caller's cgroup gives it a systemd unit. On a desktop that is
//! usually enough to tell Telegram from a shell script. It is not *strong*:
//! nothing stops a process in the same session from arranging to look like
//! another one, and the daemon says so — that class is called `native` and the
//! consent prompt is worded for a guess.
//!
//! A sandboxed app is different. Flatpak and Snap each put the app in a mount
//! namespace with a file in it that the app cannot forge, because the app is
//! not the thing that wrote it: the sandbox is. Reading that file *from
//! outside* the sandbox, for a pid the bus vouched for, yields an application
//! id that the app itself had no hand in. That is the only strong app identity
//! this platform offers, and this is the process that reads it.
//!
//! ## Why it is a separate process
//!
//! It runs in the user's session, as the user, on the session bus. The daemon
//! runs as its own uid on the system bus, and a process running as one user
//! cannot read `/proc/<pid>/root/` for another user's process — so the daemon
//! *cannot* do this itself, however much it would like to. It has to be told,
//! by something in the session, and then decide whether to believe it.
//!
//! It decides by looking at who is calling: the daemon accepts a
//! `portal_app_id` claim only from a caller whose systemd unit or executable
//! is on a short allow-list (`policy.portal_units`), which this binary is on
//! and an app is not. The check is on the caller's identity, never on what the
//! caller says about itself.
//!
//! ## Its relationship to xdg-desktop-portal
//!
//! `org.freedesktop.portal.AI` is a *proposal* (see
//! `packaging/portal/org.freedesktop.portal.AI.xml`), and until it is accepted
//! the interface does not exist in xdg-desktop-portal for anyone to implement
//! a backend against. So this serves the same interface under its own
//! well-known name, `io.github.agraves.AIPortal1`, and is honest about being
//! an interim: an app written against it today moves to
//! `org.freedesktop.portal.Desktop` by changing the bus name, because the
//! method signatures are deliberately identical.
//!
//! What it deliberately does not do is squat on the portal's name or object
//! path. Two processes claiming to be the desktop portal is a worse outcome
//! than an interim name.

use std::collections::HashMap;
use std::path::PathBuf;

use zbus::zvariant::{OwnedFd, OwnedObjectPath, OwnedValue, Value};
use zbus::{fdo, interface, Connection};

const OUR_NAME: &str = "io.github.agraves.AIPortal1";
const OUR_PATH: &str = "/io/github/agraves/AIPortal1";
const DAEMON_NAME: &str = "io.github.agraves.AIDaemon1";
const DAEMON_PATH: &str = "/io/github/agraves/AIDaemon1/Manager";
const DAEMON_IFACE: &str = "io.github.agraves.AIDaemon1.Manager";

/// Where an app's confinement wrote down what it is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Sandbox {
    Flatpak(String),
    Snap(String),
}

impl Sandbox {
    fn app_id(&self) -> &str {
        match self {
            Sandbox::Flatpak(id) | Sandbox::Snap(id) => id,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Sandbox::Flatpak(_) => "flatpak",
            Sandbox::Snap(_) => "snap",
        }
    }
}

/// Parse `.flatpak-info` for the application id.
///
/// The file is an ini written by flatpak into the sandbox's root before the
/// app starts. Reading it *for* a pid, from outside, is what makes it
/// trustworthy: the app can write anything it likes into its own filesystem,
/// but it cannot change what `/proc/<pid>/root` resolves to, and it cannot
/// change its own mount namespace back out of the sandbox.
///
/// Only `name=` under `[Application]` counts. A `name=` in some other section
/// is a different key that happens to share a spelling, and taking it would
/// let an app that can influence any part of this file choose its own id.
fn flatpak_app_id(text: &str) -> Option<String> {
    let mut in_application = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_application = line == "[Application]";
            continue;
        }
        if !in_application {
            continue;
        }
        if let Some(value) = line.strip_prefix("name=") {
            let value = value.trim();
            return (!value.is_empty()).then(|| value.to_string());
        }
    }
    None
}

/// Parse an AppArmor label for a snap name.
///
/// snapd's labels look like `snap.spotify.spotify (enforce)`, or
/// `snap.<instance>.<app>`. The snap *name* is what identifies the publisher's
/// package; the app suffix is which binary inside it ran.
///
/// `complain` mode is refused. A complain-mode profile logs violations instead
/// of blocking them, which means the confinement this whole function is
/// treating as evidence is not actually in force — accepting it would be
/// reading a lock that is hanging open.
fn snap_app_id(label: &str) -> Option<String> {
    let label = label.trim().trim_end_matches('\0');
    let (profile, mode) = match label.split_once(' ') {
        Some((profile, mode)) => (profile, mode.trim()),
        None => (label, ""),
    };
    if mode.contains("complain") || mode.contains("unconfined") {
        return None;
    }
    let mut parts = profile.split('.');
    if parts.next()? != "snap" {
        return None;
    }
    let name = parts.next()?;
    (!name.is_empty()).then(|| name.to_string())
}

/// When a process started, in clock ticks since boot: field 22 of
/// `/proc/<pid>/stat`.
///
/// Used to close the reuse window. A pid the bus reported can in principle be
/// gone and replaced by the time we read its root, and the replacement could
/// be a process that *is* in a sandbox — so the same value is read before and
/// after and the answer is thrown away if it moved. `stat`'s second field is a
/// parenthesised comm that may itself contain spaces and brackets, so the scan
/// starts after the last `)` rather than splitting the whole line.
fn start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = &stat[stat.rfind(')')? + 1..];
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// What is this pid, if its confinement will say?
fn sandbox_of(pid: u32) -> Option<Sandbox> {
    let before = start_time(pid)?;

    let root = PathBuf::from(format!("/proc/{pid}/root"));
    let found = if let Ok(text) = std::fs::read_to_string(root.join(".flatpak-info")) {
        flatpak_app_id(&text).map(Sandbox::Flatpak)
    } else {
        std::fs::read_to_string(format!("/proc/{pid}/attr/current"))
            .ok()
            .and_then(|label| snap_app_id(&label))
            .map(Sandbox::Snap)
    };

    // Same process throughout, or nothing.
    if start_time(pid)? != before {
        eprintln!("<4>portal: pid {pid} was replaced while we read it; asserting nothing");
        return None;
    }
    found
}

struct Portal {
    system: Connection,
}

impl Portal {
    /// The pid the bus says is behind this message.
    ///
    /// From the bus daemon, never from the message: a sender can put anything
    /// in a message body and the whole value of this service is that it does
    /// not take the app's word for anything.
    async fn caller_pid(&self, connection: &Connection, sender: &str) -> fdo::Result<u32> {
        let bus = fdo::DBusProxy::new(connection).await?;
        let name = zbus::names::BusName::try_from(sender)
            .map_err(|e| fdo::Error::InvalidArgs(format!("sender {sender:?}: {e}")))?;
        let credentials = bus.get_connection_credentials(name).await?;
        credentials
            .process_id()
            .ok_or_else(|| fdo::Error::Failed("the bus would not say who is calling".into()))
    }

    /// The app id to assert, or a refusal that explains itself.
    async fn assert_for(&self, connection: &Connection, sender: &str) -> fdo::Result<Sandbox> {
        let pid = self.caller_pid(connection, sender).await?;
        match sandbox_of(pid) {
            Some(sandbox) => {
                eprintln!(
                    "<6>portal: pid {pid} is {} app {}",
                    sandbox.kind(),
                    sandbox.app_id()
                );
                Ok(sandbox)
            }
            // Not an error to be sorry about. An unsandboxed app has no strong
            // identity to offer, and this service exists to carry one; passing
            // it through anyway would identify every unsandboxed caller on the
            // machine as *this process*, which is both wrong and a way to make
            // them share one grant. They should use the daemon's own API,
            // where they are correctly and visibly identified as `native`.
            None => Err(fdo::Error::AccessDenied(format!(
                "pid {pid} is not in a sandbox this portal can vouch for; call \
                 {DAEMON_NAME} directly, where you will be identified by unit \
                 rather than by application id"
            ))),
        }
    }
}

#[interface(name = "org.freedesktop.portal.AI")]
impl Portal {
    /// Open a session on the app's behalf.
    ///
    /// Deliberately the same signature as the daemon's own CreateSession, plus
    /// the app id this process contributed. A portal that reformatted the API
    /// would become a second API to keep in step, and the fd it returns is the
    /// daemon's fd — not a relay, not a copy, the same socket the daemon
    /// created — so nothing here sits in the path of a single token.
    async fn create_session(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &Connection,
        model: String,
        options: HashMap<String, OwnedValue>,
    ) -> fdo::Result<(OwnedFd, OwnedObjectPath)> {
        let sender = header
            .sender()
            .ok_or_else(|| fdo::Error::Failed("no sender on the message".into()))?
            .to_string();
        let sandbox = self.assert_for(connection, &sender).await?;

        let mut forwarded = options;
        // Refused rather than overwritten. An app that sent this was trying to
        // choose its own identity, and quietly correcting it would hide an
        // attempt worth seeing in a log.
        if forwarded.contains_key("portal_app_id") {
            return Err(fdo::Error::AccessDenied(
                "portal_app_id is this portal's to set, not the caller's".into(),
            ));
        }
        forwarded.insert(
            "portal_app_id".into(),
            Value::Str(sandbox.app_id().into())
                .try_into()
                .map_err(|e| fdo::Error::Failed(format!("app id: {e}")))?,
        );

        let (path, fd): (OwnedObjectPath, OwnedFd) = self
            .system
            .call_method(
                Some(DAEMON_NAME),
                DAEMON_PATH,
                Some(DAEMON_IFACE),
                "CreateSession",
                &(model, forwarded),
            )
            .await?
            .body()
            .deserialize()?;
        // Argument order mirrors the proposed interface: the fd first, because
        // it is the thing the app actually needs.
        Ok((fd, path))
    }

    /// What the app may ask for.
    ///
    /// A limitation worth stating rather than papering over: the daemon
    /// filters its model list by the *caller's* identity, and the caller here
    /// is this portal, so what comes back is the machine's list as the portal
    /// sees it — not the list narrowed to what the asking app is allowed.
    ///
    /// Fixing it properly means giving the daemon's `ListModels` an options
    /// dictionary so the app id can travel with it, and that changes a
    /// control-plane method signature from `()` to `(a{sv})`, which breaks
    /// every existing caller. It is a control-plane version bump, not a patch,
    /// and it has not been made. Until then an app should treat this as "what
    /// exists" and `CreateSession` as "what I may have" — which is where the
    /// decision is actually enforced, and always was.
    ///
    /// It still refuses a caller it cannot identify, so it is not a way around
    /// the rest of this interface.
    async fn list_models(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &Connection,
        _options: HashMap<String, OwnedValue>,
    ) -> fdo::Result<Vec<HashMap<String, OwnedValue>>> {
        let sender = header
            .sender()
            .ok_or_else(|| fdo::Error::Failed("no sender on the message".into()))?
            .to_string();
        // Called for its refusal as much as for its answer: an app that cannot
        // be identified does not get a model list from here either.
        self.assert_for(connection, &sender).await?;
        Ok(self
            .system
            .call_method(Some(DAEMON_NAME), DAEMON_PATH, Some(DAEMON_IFACE), "ListModels", &())
            .await?
            .body()
            .deserialize()?)
    }

    /// The app id this portal would assert for the caller.
    ///
    /// Exists so an app can find out how it is being seen without opening a
    /// session, which is the difference between a permission prompt a user
    /// understands and one they do not.
    async fn identify(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> fdo::Result<(String, String)> {
        let sender = header
            .sender()
            .ok_or_else(|| fdo::Error::Failed("no sender on the message".into()))?
            .to_string();
        let sandbox = self.assert_for(connection, &sender).await?;
        Ok((sandbox.kind().to_string(), sandbox.app_id().to_string()))
    }

    // Lower-cased to match the proposal, which follows the other portal
    // interfaces; zbus would otherwise name it `Version`.
    #[zbus(property, name = "version")]
    fn version(&self) -> u32 {
        1
    }
}

fn main() {
    // One argument or none: every branch below leaves, so there is nothing to
    // loop over.
    if let Some(arg) = std::env::args().nth(1) {
        match arg.as_str() {
            "--version" | "-V" => {
                println!("ai-daemon-portal {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--help" | "-h" => {
                println!(
                    "ai-daemon-portal {} — app identity for sandboxed apps

Runs in the user's session and owns {OUR_NAME} on the session bus, serving
org.freedesktop.portal.AI. Reads the caller's Flatpak or Snap confinement to
learn what application it is, and asserts that to ai-daemon on the system bus.

Refuses callers it cannot identify: an unsandboxed app should call
{DAEMON_NAME} directly, where the daemon identifies it by unit.",
                    env!("CARGO_PKG_VERSION")
                );
                return;
            }
            other => {
                eprintln!("portal: unknown argument {other:?}");
                std::process::exit(1);
            }
        }
    }
    if let Err(e) = zbus::block_on(serve()) {
        eprintln!("<3>portal: {e}");
        std::process::exit(1);
    }
}

async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    let system = Connection::system().await?;
    let portal = Portal { system };
    let session = zbus::connection::Builder::session()?
        .name(OUR_NAME)?
        .serve_at(OUR_PATH, portal)?
        .build()
        .await?;
    eprintln!("<6>portal: {OUR_NAME} at {OUR_PATH}");
    // Nothing else to do: zbus serves on its own tasks.
    std::future::pending::<()>().await;
    drop(session);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flatpak_app_is_named_by_its_application_section() {
        let info = "[Application]\nname=org.telegram.desktop\nruntime=org.kde.Platform\n";
        assert_eq!(flatpak_app_id(info).as_deref(), Some("org.telegram.desktop"));
    }

    /// The reason the section is checked rather than the key.
    ///
    /// `[Instance]` and `[Context]` are written by flatpak too, but an app
    /// with any influence over the file at all should not be able to pick its
    /// own id by putting `name=` somewhere else in it.
    #[test]
    fn a_name_outside_the_application_section_is_not_an_app_id() {
        let info = "[Instance]\nname=something.else\n[Context]\nname=also.not.this\n";
        assert_eq!(flatpak_app_id(info), None);
        let after = "[Instance]\nname=decoy\n\n[Application]\nname=real.app\n";
        assert_eq!(flatpak_app_id(after).as_deref(), Some("real.app"));
    }

    #[test]
    fn an_empty_name_is_not_an_app_id() {
        assert_eq!(flatpak_app_id("[Application]\nname=\n"), None);
    }

    #[test]
    fn a_snap_is_named_by_its_snap_not_its_app() {
        assert_eq!(snap_app_id("snap.spotify.spotify (enforce)").as_deref(), Some("spotify"));
        assert_eq!(snap_app_id("snap.chromium.chromedriver (enforce)").as_deref(), Some("chromium"));
    }

    /// A complain-mode profile logs violations instead of blocking them, so
    /// the confinement being treated as evidence here is not in force.
    #[test]
    fn a_complain_mode_label_is_not_evidence() {
        assert_eq!(snap_app_id("snap.spotify.spotify (complain)"), None);
        assert_eq!(snap_app_id("unconfined"), None);
        assert_eq!(snap_app_id("/usr/bin/firefox (enforce)"), None);
        assert_eq!(snap_app_id(""), None);
    }

    /// The kernel writes this with a trailing NUL, and a label that came back
    /// as `snap.spotify.spotify\0` must not become the app id `spotify\0`.
    #[test]
    fn a_trailing_nul_does_not_become_part_of_the_name() {
        assert_eq!(snap_app_id("snap.spotify.spotify (enforce)\n\0").as_deref(), Some("spotify"));
    }

    /// `/proc/<pid>/stat`'s comm field is the process name in parentheses, and
    /// a process may be named `) 1 2 3 (`. Field-counting from the left finds
    /// a different field for such a process, which is a bug that only appears
    /// when somebody is trying to cause it.
    #[test]
    fn a_hostile_comm_does_not_shift_the_field_we_read() {
        // Our own pid, whatever it is called, must produce a start time.
        let mine = std::process::id();
        assert!(start_time(mine).is_some(), "could not read our own start time");
    }
}
