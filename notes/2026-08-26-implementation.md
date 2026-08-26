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

## What is not implemented

Stated plainly rather than left to be discovered:

- **The portal itself.** §13's `org.freedesktop.portal.AI` is published as a
  proposal in `packaging/portal/` and is not installed anywhere. What exists is
  the daemon's side of the contract: it accepts an app identity asserted over
  its own API, but only from a caller that is actually xdg-desktop-portal, and
  marks the session as the only strong app identity available. Writing the
  portal backend is a separate piece of work in a separate repository.
- **Remote providers.** The `local` flag is threaded through the backend
  protocol, session info, consent metadata and the audit record, and the
  daemon never substitutes remote for local. No remote backend exists.
- **Media output.** Deferred by §11. Frames are typed, so nothing precludes it.
- **Parallel tool calls, fine-grained logit control.** Deferred by §12.
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

There is no systemd in a container, so the run stands in for the init system
and only for that: the daemon still runs as the packaged user under the
packaged bus policy consulting the packaged polkit actions. What a container
cannot demonstrate is the sandboxing systemd applies — `PrivateNetwork=yes`
most of all — so those claims are checked by asserting on the shipped unit
files rather than by observing them hold.
