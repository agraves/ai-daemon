# ai-daemon

A system inference service for desktop and workstation Linux: the role Apple's
Foundation Models framework fills on macOS and AICore fills on Android.

Every AI integration on a Linux desktop today — KDE's client, GNOME's Newelle,
Omarchy's agent tooling, editor plugins — independently spawns or connects to
an inference server on `localhost:11434` speaking the OpenAI HTTP API. It
works, and it has no access control, no resource arbitration, no shared model
store, nothing to offer a sandboxed app but a hole in its sandbox, and no
stable contract. The kernel layer is already right: NPUs and GPUs are devices,
and gigabytes of floating-point state do not belong in the kernel. The missing
piece is a privileged userspace service with a stable IPC API.

That is this.

```
┌─────────────┐  ┌─────────────┐  ┌──────────────────┐
│ native app  │  │ flatpak app │  │ legacy client    │
│ (D-Bus+UDS) │  │ (portal)    │  │ (OpenAI HTTP)    │
└──────┬──────┘  └──────┬──────┘  └────────┬─────────┘
       │                │ portal           │ 127.0.0.1 shim
       ▼                ▼                  ▼
┌─────────────────────────────────────────────────────┐
│ ai-daemon — systemd service, D-Bus activated        │
│  control plane: D-Bus · data plane: per-session UDS │
│  policy engine · scheduler · model registry         │
└──────┬──────────────────────┬───────────────────────┘
       ▼                      ▼
  llama.cpp backend      vendor NPU backend      (out-of-process plugins)
       ▼                      ▼
   /dev/dri/*             /dev/accel/*
```

## What it actually does

**Tells its callers apart.** Peer credentials plus the caller's systemd unit
for native processes, an application id for sandboxed ones — read out of their
Flatpak or Snap confinement by `ai-daemon-portal`, which runs in the user's
session because the daemon cannot read another user's `/proc` — and the
lowest trust class for anything arriving through the HTTP shim. The daemon
takes an asserted app id only from a caller on `policy.portal_units`, never
because a message said so.
The first request from a new app asks the user through polkit; the answer is
remembered per (identity, capability) and is revocable. Linux has no
code-signature check on a peer, so native identity is a good guess rather than
proof — the daemon says so rather than pretending otherwise.

**Arbitrates.** One scheduler, two priority classes. An interactive request
preempts a background batch at a token boundary; within a class, the session
that has had the least gets the next slot. KV cache is budgeted globally and
the least recently used background caches are dropped under pressure, with the
client told `context-evicted` so it can replay.

**Shares one copy of the weights.** The store is content-addressed: two apps
asking for `llama-3.1-8b-q4` get one file and one mmap. Apps should ask for
`default`, `fast` or `embed` and let the machine's owner decide what fills
them.

**Has no network.** `ai-daemon` runs with `PrivateNetwork=yes`. Downloads
happen in `ai-daemon-fetch@.service`, which has a network, writes to one
staging directory, and never sees a prompt; the daemon verifies the digest
itself and moves the artifact in. The process that touches prompts cannot
reach a network and the process that touches the network never sees a prompt.
This is not configurable off.

**Can still use a provider that is not on this machine, and says so.** A
remote backend runs as its own unit with its own uid and its own network, and
the daemon connects to it rather than forking it — because a child of the
daemon would inherit a namespace with no route anywhere. Everything it serves
is marked `local: false` in the consent prompt, in the session, and in every
audit record, and a model it serves carries `remote:<id>` where a local model
carries a content hash, because there is nothing here to hash. It is off
unless an administrator writes `/etc/ai-daemon/remote.toml`; the package ships
an example and no configuration.

**Links no media codecs.** Attachments arrive as raw pixels or PCM, or as
encoded bytes handed to `ai-daemon-decode`: one child per attachment, seccomp
confined to read, write, memory and exit. A decoder crash costs one
attachment.

**Never executes anything.** Tool schemas are compiled into a decoding grammar
so tool calls are well-formed by construction, and the daemon emits a
`tool_call` frame — inert data. The client executes it. Prompt-injection
consequences land in the client's sandbox under the client's permissions,
where the user granted them. A model may ask for several tools at once; the
turn resumes when the last one has been answered.

**Generates media as well as text**, behind its own capability. A user can let
an app write text and refuse to let it synthesise a voice, which a permission
that cannot be withheld on its own does not allow. Results are raw pixels or
raw PCM: there is no encoder in the daemon, for the same reason there is no
decoder.

**Logs who, never what.** Identity, model, digest and token counts go to the
journal and an audit file. Content does not, and there is exactly one module
where that rule could be broken.

## Trying it

```
aidctl status                    # what the daemon is doing
aidctl models                    # what is installed, and where it came from
aidctl generate "hello"          # open a session and stream an answer
aidctl sessions                  # who else is using it right now
aidctl grants                    # every consent decision, and when
```

Building the package on Arch (and so on Omarchy):

```
./packaging/arch/make-package.sh
sudo pacman -U packaging/arch/ai-daemon-*.pkg.tar.zst
sudo usermod -aG ai "$USER"      # the outer gate; log back in afterwards
```

Building and verifying it in a container, end to end — the package built by
`makepkg`, installed by `pacman`, then exercised over the system bus with
polkit running:

```
dev build -t ai-daemon-box .
```

The verification runs *during* the build, so a green build is a green run and a
failing check fails the build. (It has to: containers started by `dev run` have
every capability dropped, and the run needs to act as three different users.)
The transcript is kept at `/verification.txt` in the resulting image, which is
what the image prints if you run it.

It checks ninety-one things, and is deliberately adversarial about most of
them — a wrong digest, an oversized screenshot, a truncated PNG, a user outside
the gate, a revoked identity, a remote `image_url` — because "it generated some
text" is the easy half and the refusals are the point.

## Layout

| | |
|---|---|
| `crates/ai-daemon` | the service: D-Bus control plane, sessions, policy, registry, scheduler |
| `crates/ai-daemon-proto` | the three wire contracts; data and provider planes at v2, v1 still served |
| `crates/ai-daemon-backend-llamacpp` | reference provider backend (GGUF via llama.cpp) |
| `crates/ai-daemon-backend-mock` | conformance backend: deterministic, no weights, no devices |
| `crates/ai-daemon-backend-remote` | an OpenAI-compatible endpoint elsewhere; its own unit, its own network |
| `crates/ai-daemon-portal` | session-bus portal: turns a sandbox into an app identity |
| `crates/ai-daemon-fetch` | the download helper, and the only thing here with a network |
| `crates/ai-daemon-decode` | the confined media decoder |
| `crates/ai-daemon-shim` | OpenAI-compatible localhost endpoint, off by default |
| `crates/aidctl` | administration and inspection |
| `packaging/` | PKGBUILD, systemd units, D-Bus and polkit policy, the verification run |
| `docs/protocol.md` | the wire protocols in full |

## On the name

The target D-Bus name is `org.freedesktop.AI1` and this does not use it. That
namespace is earned by taking the specification through freedesktop review, not
claimed by shipping under it; a daemon squatting the name it wants to
standardise would poison the review it needs. Until then the daemon owns
`io.github.agraves.AIDaemon1`, and will keep answering to it as a
compatibility alias afterwards. The portal interface in
`packaging/portal/org.freedesktop.portal.AI.xml` is a proposal on the same
terms.

## Prior art

[inferd](https://github.com/3rg0n/inferd) independently implements much of the
same daemon architecture: a host-wide service holding warm models behind a
small frozen Unix-socket protocol, with a separate unprivileged OpenAI-compat
bridge and an explicit "no network listener ever" rule. What it deliberately
excludes is what this exists for — per-app identity, consent and policy;
portal mediation; freedesktop standardisation. inferd validates the
architecture. Wire-format convergence is worth evaluating before either
project's protocol has users.

## Status

Draft. The data plane and provider protocol are at v2 and both still serve v1;
"frozen" means the daemon refuses a peer speaking anything outside that range,
not that anyone has agreed to them yet. The design record this implements is
in `notes/`.

Not built: the freedesktop review that would make `org.freedesktop.AI1` and
`org.freedesktop.portal.AI` real names rather than a proposal and an interim,
and structured output beyond tool-call grammars. The portal interface is
implemented and served — under our own bus name, which is the part review
would change.
