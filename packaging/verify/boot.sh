#!/bin/bash
# Bring up the pieces a real machine would have systemd bring up, then verify.
#
# There is no systemd in a container, so this stands in for it — and only for
# it. Nothing here substitutes for the daemon, the package or the policy: the
# daemon runs as the ai-daemon user the package created, under the bus policy
# the package installed, consulting the polkit actions the package installed.
# What is faked is the init system, and the script says so where that changes
# what a test can claim.
set -uo pipefail

log() { printf '\033[36m[boot]\033[0m %s\n' "$*"; }

# With arguments, run them and exit: the box doubles as a shell to poke at
# while working out why something in the verification is unhappy.
if [ "$#" -gt 0 ]; then
  exec "$@"
fi

log "starting the system bus"
mkdir -p /run/dbus
dbus-daemon --system --fork
sleep 0.5

log "installing the machine's local policy decisions"
# Written before polkit starts, because polkitd reads the rules directory at
# startup and this is the machine owner's answer standing in for a dialog
# nobody is here to click.
mkdir -p /etc/polkit-1/rules.d
cat > /etc/polkit-1/rules.d/49-verification.rules <<'RULES'
polkit.addRule(function (action, subject) {
    if (action.id.indexOf("io.github.agraves.aidaemon.") !== 0) {
        return undefined;
    }
    if (action.id === "io.github.agraves.aidaemon.model-admin") {
        return subject.user === "root" ? polkit.Result.YES : polkit.Result.NO;
    }
    return subject.isInGroup("ai") ? polkit.Result.YES : polkit.Result.NO;
});
RULES

log "starting polkit (consent is a real code path here, not a stub)"
mkdir -p /run/polkit-1
POLKITD=$(command -v polkitd || echo /usr/lib/polkit-1/polkitd)
"$POLKITD" --no-debug >/tmp/polkitd.log 2>&1 &
for _ in $(seq 1 40); do
  busctl --system status org.freedesktop.PolicyKit1 >/dev/null 2>&1 && break
  sleep 0.25
done
if busctl --system status org.freedesktop.PolicyKit1 >/dev/null 2>&1; then
  log "polkit is on the bus"
else
  log "polkitd did not take its name; its output follows, and the run continues"
  log "so that the transcript shows what a machine with no authority does."
  sed 's/^/       /' /tmp/polkitd.log
  ls -l "$POLKITD" 2>&1 | sed 's/^/       /'
fi

log "creating the people the verification acts as"
# Fixed uids so the identity strings in the config drop-in are stable.
useradd --uid 4001 --create-home --groups ai alice
useradd --uid 4002 --create-home --groups ai bob
useradd --uid 4003 --create-home mallory      # deliberately outside the gate
usermod --append --groups ai root
# systemd would do this from SupplementaryGroups= in the units. Without an init
# system, setpriv --init-groups reads /etc/group, so the membership has to be
# there. The shim needs it for the same reason a person does: it is a caller.
usermod --append --groups ai ai-daemon-shim

# The rule above stands in for a person clicking "Allow": on a desktop polkit
# asks, here the machine's owner has written the answer down. Either way the
# daemon's consent path is the one being exercised, not a bypass.

mkdir -p /etc/ai-daemon/config.toml.d
cat > /etc/ai-daemon/config.toml.d/60-rate-limit.conf <<'CONF'
# bob gets a deliberately tiny allowance so the verification can watch a rate
# limit actually bite. uid:4002 is how the daemon names him here: there are no
# systemd units in a container, and a daemon running as its own user cannot
# read /proc/<pid>/exe for somebody else's process, so the uid is all the
# kernel will say. On a desktop this would be unit:app-….scope@4002.
[[identity]]
identity = "uid:4002"
tokens_per_minute = 50
CONF

cat > /etc/ai-daemon/config.toml.d/75-attachments.conf <<'CONF'
[attachments]
# Raised from the shipped 16 MiB so that the *pixel* budget is what refuses the
# oversized screenshot below rather than the byte budget getting there first.
# Both are tested; they are different limits protecting different things, and a
# test that cannot tell which one fired is not testing either.
max_bytes = 33554432
max_pixels = 4194304
max_samples = 960000
max_per_session = 16
allow_encoded = true
CONF

cat > /etc/ai-daemon/config.toml.d/70-container.conf <<'CONF'
[daemon]
state_dir = "/var/lib/ai-daemon"
runtime_dir = "/run/ai-daemon"
libexec_dir = "/usr/lib/ai-daemon"
# No idle exit: without systemd there is no bus activation to bring the daemon
# back, so exiting would end the verification rather than demonstrate anything.
idle_exit_seconds = 0
model_idle_unload_seconds = 0
CONF

log "creating the state the tmpfiles.d snippet creates on a real install"
systemd-tmpfiles --create /usr/lib/tmpfiles.d/ai-daemon.conf 2>&1 | sed 's/^/       /'

log "starting ai-daemon as the ai-daemon user, the way its unit would"
setpriv --reuid ai-daemon --regid ai-daemon --init-groups --inh-caps=-all \
  -- /usr/bin/ai-daemon --debug >/tmp/daemon.log 2>&1 &
for _ in $(seq 1 40); do
  busctl --system status io.github.agraves.AIDaemon1 >/dev/null 2>&1 && break
  sleep 0.25
done
if ! busctl --system status io.github.agraves.AIDaemon1 >/dev/null 2>&1; then
  log "the daemon never took its bus name; log follows"
  cat /tmp/daemon.log
  exit 1
fi
log "the daemon is on the bus"

log "starting the shim (off by default on a real install; on here to test it)"
setpriv --reuid ai-daemon-shim --regid ai-daemon-shim --init-groups --inh-caps=-all \
  -- /usr/bin/ai-daemon-shim >/tmp/shim.log 2>&1 &
sleep 1

exec /usr/local/bin/verify
