# ai-daemon: what got built, and where it departs from the design record

**Date:** 2026-08-26 · Status: **implemented; package builds and verifies on
Arch.** Companion to `2026-08-25-dev-ai-design.md`, which it partly supersedes.

## The two designs

The founding record proposes `/dev/ai`: a CUSE-served device tree where a node
is a provider, `open()` yields a session fd, and the trust boundary is which
node you can see. Draft 0.3 of the spec — the one this implements — proposes
something different: a D-Bus control plane with a per-session Unix socket, and
a trust boundary drawn around *the calling application* rather than around the
provider.

They are not variations on a theme, so it is worth being explicit about what
was kept and what was dropped.

**Kept, because it was the right idea in both:**

- A broker holding what callers must not hold, with callers getting a
  vocabulary instead. Here that is credentials and weights.
- Identity asserted by the substrate rather than taken from the payload. The
  bus names the peer; the caller cannot choose who it is.
- A session as a held file descriptor, closed when the process dies, with
  process-lifetime cleanup for free.
- Framed CBOR on that descriptor, boring on purpose.
- Per-cgroup-ish accounting, an audit record of every session, mandatory
  digest pinning for local weights.

**Dropped, and why:**

- **The device tree.** `/dev/ai/anthropic` is a beautiful answer to "which
  company may see this conversation", and this spec has no remote providers in
  v1 — the default install never sends bytes off-machine. A tree of one node
  is a directory. The provider-as-trust-boundary idea is not wrong, it is
  *early*: it becomes load-bearing the moment §7's remote providers exist, and
  the `local: false` flag threaded through consent prompts, session info and
  the audit record is the seam it would attach to.
- **CUSE.** Serving a device node buys mount-namespace scoping, `chmod`, and
  LSM labels per provider. What it costs is the thing this spec is actually
  for: xdg-desktop-portal cannot mediate a device node, and portal mediation
  is the only strong app identity Linux has. D-Bus gets activation,
  introspection and peer credentials for free and is where GNOME and KDE
  already converge.
- **`aid` as a name.** The spec's name note rules it out; the binary is
  `ai-daemon`, in the `dbus-daemon`/`avahi-daemon` tradition.

The lineage paragraph in the founding record still holds, one layer up: the
broker is the vault, the session fd is the per-session token made unforgeable
by the kernel, the audit chain is the audit chain.

## Departures from Draft 0.3, and additions

Everything below is a place where the spec was silent, ambiguous, or where
implementing it turned up something the prose did not anticipate.

**The `ai` group has no socket to be a mode on.** §4 specifies the native data
socket as `ai-daemon:ai 0660`. There is no listening socket: sessions arrive as
descriptors passed over D-Bus, which is strictly better — the bus has already
named the peer. So the gate lives in the daemon instead, as a group-membership
check read from `/proc/<pid>/status`, configurable as `policy.gate_group` and
disableable by clearing it. Same question, same answer, different enforcement
point. There is deliberately no root exception.

**Model administration cannot be reached through consent mode.** §5 has
`model-admin` requiring polkit admin auth. The daemon routes it to polkit
regardless of `policy.consent`, so an install that has chosen `consent =
"allow"` for convenience has not thereby made "install any weights you like"
free. This is stricter than the spec's wording and is the reading that makes
the capability mean anything.

**`ai-daemon-fetch` had to become a real unit, not a child process.** §9's
split only works if the downloader is in a different network namespace, and a
process forked from a daemon with `PrivateNetwork=yes` inherits the daemon's.
So the daemon asks systemd to start `ai-daemon-fetch@<job>.service` over D-Bus,
which needs a narrow polkit rule for `manage-units` scoped to that unit
pattern — shipped as `50-ai-daemon-fetch.rules`. Where there is no systemd to
ask (a container, a development run) the daemon falls back to spawning the
helper directly and says in the journal that the split is weaker than the
design describes. The job travels in a file rather than in the unit's instance
name: a URL in a unit name is an injection surface.

**Backends are three processes deep, not two.** §7 puts backends out of
process for crash isolation. The llama.cpp backend then drives `llama-server`
as a *further* child and speaks HTTP to it on loopback. A backend that linked
libllama and got faulted by CUDA would only have moved the problem one process
along; this way a segfault costs the model runtime and the daemon sees a clean
error. It also decouples us from llama.cpp's ABI churn.

**The decoder needed a decoder.** §11 says the daemon links no media codecs and
that encoded input is decoded in a confined helper. It does not say what
decodes it. Linking an image crate into the helper would move the CVE surface
rather than remove it, so `ai-daemon-decode` contains hand-written readers for
8-bit non-interlaced PNG (with its own DEFLATE) and PCM WAVE — small enough to
read in full — and refuses everything else, at which point the client decodes
it themselves, which is §11's first accepted form and always available. The
helper installs a seccomp allow-list before touching a byte of input and
refuses to decode at all if it could not, because a helper that silently ran
unconfined would be worse than none.

**A mock backend ships.** §7 names llama.cpp as the reference backend, and it
is. But every property this project exists for — identity, consent, rate
limits, preemption, KV eviction, tool round-trips, attachment budgets, the
audit trail — is a property of the daemon rather than of a language model, and
testing them against an 8B model would make the tests slow, non-deterministic,
and dependent on a GPU no CI has. `ai-daemon-backend-mock` emits exactly
`max_tokens` deterministic tokens and is also the reference implementation of
the provider protocol. It is installed and declares itself; a backend that
pretended to be a model would be a worse lie than one that says what it is.

**`InstallModel` grew an options dictionary.** §12 sketches
`InstallModel(source, digest)`. That cannot express which backend should own a
model or what licence the user agreed to, so there is a fourth `a{sv}`
argument. The declared format is checked against the file's four-byte magic —
a magic check, not a header parse; reading weight headers stays a backend's
job.

## Three things the container found that reading could not

**A D-Bus handler must never block on D-Bus.** zbus dispatches every incoming
method call on one internal executor thread, so `InstallModel` — which asked
polkit whether the caller may install anything — was waiting for a reply that
only the thread it was blocking could deliver. Not a slow daemon: a dead one,
from the first administrative call. Anything that can take longer than a
message round trip now goes through `unblock()` and awaits a thread.

**polkit will not take details from a daemon that is not root.** Details reach
the authentication dialog, so polkit accepts them only from uid 0 or from an
action's declared owner — a mechanism that could set them freely could put
words in front of somebody about to type their password. The actions now
declare `unix-user:ai-daemon` as their owner, which is the mechanism polkit
provides for exactly this, and the daemon retries without details if an older
polkit refuses them anyway.

**Native identity is coarser than §5 implies.** Reading `/proc/<pid>/exe` needs
ptrace-level access to the target, so a daemon running as its own system user
gets nothing for any process belonging to a human. What is readable across uids
is `/proc/<pid>/cgroup`, which on a systemd machine names the app's scope and
is the identity grants are keyed on — and in a container, where there are no
units, the honest answer is the bare uid, which is what the verification shows.
`/proc/<pid>/comm` would fill the gap and is deliberately not used: a process
can set its own `comm`, so an identity built on it would be chosen by the
thing being identified.

## A correction to the git history

Which commit contains what, since neither message says so correctly:

| commit | what is actually in it |
|---|---|
| `f1fe738` | `crates/ai-daemon/src/decode.rs` — the decoder deadline moved onto the read; and `crates/ai-daemon/src/identity.rs` — `normalise_unit`, so the Native grant key survives a relaunch. |
| `b35f10e` | `crates/ai-daemon/src/sched.rs` only — the KV eviction fix. Its message describes `f1fe738`'s two files and is stale. |
| `2713f5a` | `identity.rs` again (snapd's per-launch uuid) and this note. |

`b35f10e` — "Make the decoder deadline real, and the grant key survive a
relaunch" — **describes the wrong diff.** Its title, body and test-name
paragraph all narrate the decoder deadline and the grant key, which are
`f1fe738`'s contents. Its own diff is one file: `crates/ai-daemon/src/sched.rs`,
the KV **eviction** fix — `reserve_kv` rebuilt to plan victims before touching
any of them, so a reservation that cannot succeed no longer destroys a
session's backend cache on its way to returning `Err` and then discards the
list of who it cost.

It happened because two workers were running the same job at once after a
lease expiry; one committed the other's newer tree under its own older
message. History is landed and is not being rewritten for a wrong comment, so
this paragraph is the record instead.

The practical consequence, and the reason this is written down rather than
shrugged at: `git log --grep=evict` returns nothing on master, so the eviction
fix is not findable from the log at all. Anyone bisecting to `b35f10e` will
read about decoders while looking at a scheduler diff. Search for
`reserve_kv` or for this file instead.

## The four that were deferred, and now are not

The list below this one used to open with four items. They were built in two
passes after the first landing; what follows is what each one turned out to
cost, because in three of the four the interesting part was not the feature.

**Media output, parallel tool calls, and logit control** needed somewhere on
the wire to live, so the data plane and the provider protocol went to v2 —
both still serving v1. A version is negotiated in the hello and the newer side
sends nothing the older one cannot read: a v1 client offered two tool calls
gets one, because it has no frame in which to answer two and dropping the rest
silently is worse than not offering them.

Building them found two bugs in code that was already landed, both mine:

- `reader_loop` routed backend events by `req_id` with a `_ => None`
  catch-all, so the two new event kinds compiled cleanly and went to the
  *control* channel — neither delivered to the request that asked nor
  recognised by the load waiting there. The match is exhaustive now, with the
  reason written at it, so the next variant does not build until somebody has
  decided which channel it is on. Same shape as the control-plane correlation
  bug the monitor found earlier; the lesson did not generalise the first time
  because the fix was to the *sending* side.
- Three `events.recv()` calls had no timeout. A backend request thread that
  dies without sending `done` leaves the process alive, so nothing closes the
  channel and the session hangs for good holding a decode slot. All three are
  bounded now and say which of silence or disconnection happened.

The bound was then wrong in a way the monitor caught and I had not: it ran
while the request was *paused*, and pausing is the daemon's own doing. §8
pauses every background request whenever any interactive one is running and
resumes only when none is left, so on a busy desktop a batch job sits silent
past the whole window without a gap — and the net for a dead backend would
kill the exact workload preemption exists to protect, throwing away the tokens
already generated and making the retry re-spend the prompt. The window is
accumulated in slices now and a paused slice does not count. It does not
*reset* the count either: a backend that died while being paused and resumed
around it would otherwise evade the net for ever, and the question being asked
is how long it has been silent while free to speak. The slicing also means the
cancel flag is re-read every few seconds instead of at the far end of a
quarter-hour wait. The window is `daemon.backend_silence_seconds` because a
test cannot wait out fifteen minutes.

**The remote provider** is the one that changed an architectural assumption.
Every other backend is a child of the daemon over a socketpair, and a remote
one cannot be: `PrivateNetwork=yes` means anything the daemon forks has no
route anywhere, and that is the setting the whole of §9 rests on. So backends
gained a second transport — `connect` instead of `exec` — and the remote
provider is its own unit with its own uid, its own runtime directory and a
network the daemon does not have.

Worth being exact about what that does to §9's claim. "The process that holds
every prompt has no network" is still true of `ai-daemon`. It is not true of
the machine once a remote provider is configured, because that process has
both — which is what a remote provider *is*, and why turning one on is a
deliberate act, why it sees only what is routed to it, and why every session
it serves reports `local: false` in the consent prompt, the session and the
audit record. Nothing the package installs turns it on.

Two smaller things fell out of it. A model with no weights has nothing to
hash, so `aidctl install --source remote:<id>` asks for no digest and
manufactures none; its manifest identifier reads `remote:<id>` rather than
wearing a `sha256:` prefix it could not honour, and offering `--digest`
anyway is refused rather than ignored. And `shutdown()` no longer sends
`Shutdown` to a backend the daemon merely dialled: that is a service it does
not own and the daemon idling out is not a reason for it to die.

**The portal** runs as the user, on the session bus, because
`/proc/<pid>/root/.flatpak-info` is readable by the owner of that process and
the daemon is a different uid — the daemon *cannot* do this itself, which is
the whole reason a separate process exists. It reads the confinement for a pid
the bus vouched for, never one a message body claimed, and re-reads the
process start time afterwards so a recycled pid cannot substitute itself
mid-read. A caller it cannot identify is refused rather than passed through:
lending it the portal's own identity would label every unsandboxed app on the
machine as the portal and make them share one grant.

It also found a real hole in the daemon's side, which had been there since the
first commit. The check on who may assert an app identity was
`unit.starts_with("xdg-desktop-portal")`, chosen because desktops ship
`-gtk`, `-gnome` and `-kde` variants. An unprivileged user can write
`~/.config/systemd/user/xdg-desktop-portal-anything.service`, and everything
they started under it would have been believed when it claimed to be any
application on the machine. It is exact names now, the variants listed one by
one, in a config key an administrator can extend or empty.

Two things the container cannot show, both named where they happen:

- **The portal-to-daemon assertion end to end.** The daemon identifies a
  portal by the caller's systemd unit, read from `/proc/<pid>/cgroup` because
  that is world-readable and not self-chosen. This box has no systemd and a
  read-only cgroupfs, so nothing can be placed in a cgroup named after a unit
  and the daemon sees a caller with no unit at all — and refuses, correctly.
  The other two routes are closed for good reasons: `/proc/<pid>/exe` is
  unreadable across uids and the portal must run as the user. So the
  verification proves the portal's own half in full, proves the daemon's
  refusal, and covers the daemon's acceptance with unit tests over the same
  function the D-Bus path calls.
- **A real sandbox.** `.flatpak-info` is placed at the container root rather
  than in a mount namespace, which exercises the read and the parse and not
  the isolation — that part is flatpak's to provide. Which section of the file
  counts, and which AppArmor labels are refused, are unit tests.

And one thing that is implemented but weaker than the headline: tool calling
through a remote provider is not grammar-constrained, because constrained
decoding needs the logits and those are on somebody else's machine. The
endpoint does its own function calling instead. Refusing tools outright on
that basis would rule out every hosted provider over a mechanism they replace
rather than lack — so the daemon allows it, advertises `grammar` in the
session's capabilities exactly when it is what happened, and checks every call
that comes back against the tools the client actually offered. That check runs
on the grammar path too, where it is free.

## What is not implemented

Stated plainly rather than left to be discovered:

- **The freedesktop names.** `org.freedesktop.AI1` and
  `org.freedesktop.portal.AI` are what this wants to be called and are not
  what it is called. Both are proposals; the portal interface is implemented
  and served under `io.github.agraves.AIPortal1`, which is the part review
  would change. Squatting the name it wants to standardise would poison the
  review it needs.
- **`ListModels` through the portal is not narrowed to the asking app.** The
  daemon filters by caller identity and the caller is the portal, so what
  comes back is the machine's list. Fixing it means giving that method an
  options dictionary, which changes its D-Bus signature from `()` to
  `(a{sv})` and breaks every existing caller — a control-plane version bump,
  not a patch. `CreateSession` is where a per-app decision is enforced, and
  always was.
- **A vendor NPU backend.** The provider protocol was written to be sufficient
  for one — device claims, capability declarations, memory reporting — but
  nobody has written one, so that sufficiency is a claim rather than a
  demonstration.
- **VRAM cgroups.** §14 says it; still true. The scheduler's accounting is only
  as good as each backend's `kv_bytes_per_token`.

## Verifying it

`packaging/verify/` builds the package with `makepkg`, installs it with
`pacman`, and exercises the result over the system bus with polkit running: the
gate, consent, digest verification, content-addressed sharing, streaming, tool
round-trips, PNG decoding through the confined helper, attachment budgets, rate
limits, revocation, preemption, the audit log's silence about content, and the
OpenAI shim. It is deliberately adversarial — a wrong digest, an oversized
image, a truncated PNG, a user outside the gate, a remote `image_url` — because
"it generated some text" is the easy half and the refusals are the project.

A hundred and eighty-odd checks, all passing. Four of them are honest about
their limits rather than quietly weaker — the two below, plus the portal's
cgroup and its sandbox, described in the section above:

- **systemd is absent**, so the run stands in for the init system and only for
  that: the daemon still runs as the packaged user, under the packaged bus
  policy, consulting the packaged polkit actions. What a container cannot show
  is the sandboxing systemd applies — `PrivateNetwork=yes` most of all — so
  those claims are checked by asserting on the shipped unit files instead of by
  observing them hold.
- **seccomp is unavailable**, because the box is a translated x86-64 container
  on an arm64 host and the emulator cannot pass a filter to the kernel. So
  `ai-daemon-decode` refuses to decode, which is the designed behaviour — a
  helper that could not build its cage must not parse hostile bytes — and the
  verification asserts that refusal rather than skipping the case. The encoded
  path is therefore *not* demonstrated end to end here; the codecs are covered
  by unit tests that `makepkg`'s `check()` runs, and the raw attachment form,
  which needs no decoder anywhere, is demonstrated in full.
