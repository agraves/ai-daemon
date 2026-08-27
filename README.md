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
for native processes; an application id for sandboxed ones, read out of their
Flatpak or Snap confinement by `ai-daemon-portal`, which runs in the user's
session because the daemon cannot read another user's `/proc`. Callers on the
shim's Unix socket are named by the kernel too (`SO_PEERCRED`); on its TCP
port the kernel will not say, so a configured token names the caller
(`shim:cx`) and an anonymous one is honestly just a uid — six agents on one
machine are six policies either way, and everything through the shim stays
the lowest trust class. The daemon takes an asserted app id only from a
caller on `policy.portal_units`, never because a message said so. The first
request from a new app asks the user through polkit; the answer is remembered
per (identity, capability) and is revocable. Linux has no code-signature
check on a peer, so native identity is a good guess rather than proof — the
daemon says so rather than pretending otherwise.

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

**Can be handed over, narrowed.** A session is a file descriptor, and it can
be opened with less than the caller holds — no tools, a lower rate, a subset of
models, a prelude the far end cannot remove. So a supervisor can open one, pass
it to a sandboxed child, and know the child has strictly less than it does.
`ai-run` is that in one command: the program runs in a network namespace with
no route off the machine and reaches the daemon through a Unix socket, which is
why the shim has one — a port does not survive a namespace, a filesystem object
does. What that removes is the credential and the egress; it does not stop a
program acting badly on what a model says, and it is not a container.

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
aidctl meter                     # tokens and spend per identity, rolling 24h
```

An agent gets a standing identity in one flag, and a standing policy in one
rule: `ai-run --as claude-code -- claude …` makes every launch arrive as
`unit:claude-code@1000`, and an `[[identity]]` rule in
`/etc/ai-daemon/config.toml` — models, rate, spend ceiling — then holds for
good. `aidctl meter --waybar` is the same accounting as a status-bar module
(`waybar.jsonc.example` ships with the docs), and on a machine with a journal
every audit record carries structured fields, so
`journalctl -t ai-daemon AI_IDENTITY=unit:claude-code@1000 -o json` is a
query rather than a grep.

Building an application on it is the same session opened from your own code:
one D-Bus call returns a socket, and frames on the socket are length-prefixed
CBOR. `examples/think.py` is the whole client in forty lines — no API key, no
SDK, and it keeps working under `ai-run` with the network gone:

```
python examples/think.py "why is the sky blue?"
ai-run -- python examples/think.py "and again with no network at all"
```

`docs/provisioning.md` is the other half of the no-credential claim: how to
ship a machine so no application ever holds a provider key, which is what
makes going around the daemon not just forbidden but useless.

Building the package on Arch (and so on Omarchy):

```
./packaging/arch/make-package.sh
sudo pacman -U packaging/arch/ai-daemon-1.0.0-1-*.pkg.tar.zst
sudo usermod -aG ai "$USER"      # the outer gate; log back in afterwards
```

`makepkg` emits an `ai-daemon-debug` package beside that one, which a bare
`ai-daemon-*` glob would sweep up as well; the version in the name is what
keeps it out.

To actually run a model you need llama.cpp and, separately, kernels for it —
Arch splits those out of `ggml`, which ships no compute backend of its own, so
`llama-cpp` alone gets a `llama-server` that exits at load with "no backends
are loaded":

```
sudo pacman -S llama-cpp ggml-cuda    # or ggml-cpu / ggml-hip / ggml-vulkan
```

Then put the model on the GPU, which is off until you say so — `/etc/ai-daemon/config.toml`
carries the line commented out under the `llamacpp` backend:

```toml
env = { AI_DAEMON_LLAMACPP_GPU_LAYERS = "99" }
```

**Under WSL2** there is no `/dev/dri` and no NVIDIA PCI device; the GPU arrives
as `/dev/dxg` with the driver bind-mounted from Windows, so the unit needs a
drop-in and *no* NVIDIA packages installed inside the distro. See
`/usr/share/doc/ai-daemon/wsl.conf.example`.

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

It checks over three hundred things, and is deliberately adversarial about most of
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
| `crates/ai-daemon-shim` | OpenAI- and Anthropic-compatible endpoint on loopback and a Unix socket, off by default |
| `crates/ai-run` | run a program with inference and nothing else: no network, no credential |
| `crates/aidctl` | administration and inspection |
| `packaging/` | PKGBUILD, systemd units, D-Bus and polkit policy, the verification run |
| `examples/think.py` | the native protocol as a working client, forty lines |
| `docs/protocol.md` | the wire protocols in full |
| `docs/provisioning.md` | shipping a machine so no application ever holds a provider key |

## On the name

The target D-Bus name is `org.freedesktop.AI1` and this does not use it. That
namespace is earned by taking the specification through freedesktop review, not
claimed by shipping under it; a daemon squatting the name it wants to
standardise would poison the review it needs. Until then the daemon owns
`io.github.agraves.AIDaemon1`, and will keep answering to it as a
compatibility alias afterwards. The portal interface in
`packaging/portal/org.freedesktop.portal.AI.xml` is a proposal on the same
terms.

## Licensing

Apache-2.0, everywhere, on purpose. The point of this project is to be
substrate — applications route through it, SDKs land on it, distributions
ship it — and the licence choice follows from that the way the D-Bus names
do. Permissive, because copyleft would tax exactly the adoption the project
exists for while buying nothing: the daemon talks to applications across an
IPC boundary, so the GPL would not reach them anyway. Apache over MIT for
one reason, the explicit patent grant — this is infrastructure in the most
patent-litigious corner of the industry, and both adopters and contributors
get the protection MIT is silent about. Every source file carries an SPDX
header, and the build fails if one is missing, because a per-file promise
that depends on memory is not one. Every dependency in the tree is
permissively licensed (verified, not assumed — `cargo metadata` says so and
nothing in it is copyleft-only).

Two forward commitments, written down now so they are not decided by
accident later. If an eBPF enforcement layer is ever built — the
default-deny egress gate the design conversations keep circling — its
`.bpf.c` programs go in their own directory as
`GPL-2.0-only OR BSD-2-Clause`: the kernel's verifier refuses GPL-only
helpers to programs without a GPL-compatible licence string, so that half is
forced, and the dual with BSD-2-Clause is the shape Cilium's `bpf/` tree
settled on under Linux Foundation review for the same problem. And the wire
protocols in `docs/protocol.md` are meant to be implemented by anyone,
including competing daemons, without asking; the document says so itself.

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

1.0.0. The wire contracts are versioned and held — data plane and provider
protocol at v2, both still serving v1, and the daemon refuses a peer speaking
anything outside that range. The number means the contracts are ready to be
relied on, not that the ecosystem has agreed to them: nothing has shipped
beyond development machines yet. The design record this implements is in
`notes/`.

Not built: the freedesktop review that would make `org.freedesktop.AI1` and
`org.freedesktop.portal.AI` real names rather than a proposal and an interim,
and structured output beyond tool-call grammars. The portal interface is
implemented and served — under our own bus name, which is the part review
would change.
