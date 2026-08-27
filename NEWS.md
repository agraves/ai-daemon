# ai-daemon — release notes

Written for whoever picks this up next, and specifically for the WSL2 side of
the Omarchy image. It assumes you have not read the commit log and do not
intend to.

`0.1.0`, master at the commit that added this file. Nothing has been deployed
anywhere, which is worth knowing before you read the compatibility notes: they
describe what *would* break, not what did.

---

## Getting it running on WSL2

Build and install the package the way a user would:

```
./packaging/arch/make-package.sh
sudo pacman -U packaging/arch/ai-daemon-0.1.0-1-*.pkg.tar.zst
```

The version in that glob matters. `makepkg` emits an `ai-daemon-debug` package
beside the real one and a bare `ai-daemon-*` would sweep it up.

**Inference needs two packages, not one.** Arch splits the compute kernels out
of `ggml`, so `llama-cpp` on its own gets you a `llama-server` that exits at
load with "no backends are loaded" — which reads like a daemon problem and is
not one:

```
sudo pacman -S llama-cpp ggml-cuda    # or ggml-cpu / ggml-hip / ggml-vulkan
```

**The GPU is off until you say so.** `/etc/ai-daemon/config.toml` has the line
commented out under the `llamacpp` backend:

```toml
env = { AI_DAEMON_LLAMACPP_GPU_LAYERS = "99" }
```

### The WSL2 part

The unit wants a drop-in on WSL2 and only on WSL2. The package ships it as
documentation rather than installing it, because on real hardware it loosens
the unit for nothing:

```
sudo mkdir -p /etc/systemd/system/ai-daemon.service.d
sudo cp /usr/share/doc/ai-daemon/wsl.conf.example \
        /etc/systemd/system/ai-daemon.service.d/10-wsl.conf
sudo systemctl daemon-reload
```

Two lines, and the second is the one that costs an afternoon if you find it
yourself. WSL2 does not pass the GPU through as a PCI device: there is no
NVIDIA device on the bus, no `/dev/dri`, and no driver to install. The guest
talks to a paravirtualised `/dev/dxg` and links against the Windows driver's
libraries, which WSL bind-mounts at `/usr/lib/wsl/lib`. **Installing
`nvidia-utils` or an NVIDIA DKMS package there is worse than unnecessary** — it
shadows the working `libcuda` with one that does not match the host driver.

So `DeviceAllow=/dev/dxg rw`, and `PrivateDevices=no`. The second is not
obvious: `DeviceAllow` is a cgroup rule and does its job — the device is
present in the sandbox with the right mode — but `PrivateDevices=yes` mounts a
fresh minimal `/dev` and NVML still refuses on the far side of it with
`Failed to initialize NVML: GPU access blocked by the operating system`.
Verified as a matrix on WSL 2.7.12 / kernel 6.18.33: every combination with
`PrivateDevices=yes` fails regardless of `DeviceAllow`. Nothing else in the
unit is implicated — `ProtectSystem=strict`, `SystemCallFilter=@system-service`,
`MemoryDenyWriteExecute` and an empty `CapabilityBoundingSet` all load CUDA
without complaint. The unit still reaches exactly one device.

---

## What is new since the first working daemon

### Claude Code can be pointed at it

The shim served OpenAI's API only, so the most-used agent on a developer's
machine could not talk to the daemon at all. It now serves both:

| | |
|---|---|
| OpenAI | `GET /v1/models`, `POST /v1/chat/completions`, `POST /v1/embeddings` |
| Anthropic | `POST /v1/messages`, `POST /v1/messages/count_tokens` |

Same port (`127.0.0.1:11434`), same sessions underneath, same policy engine,
same audit log. Streaming and non-streaming, tools, images, `system`, and
Anthropic's own error envelope and stop reasons.

Both routes refuse to fetch a URL a prompt named. OpenAI `image_url` takes
`data:` only; Anthropic image blocks take `source.type = "base64"` only. This
process is the last one that should hold a server-side request forgery
primitive.

### Several agents are now several policies

This is the one that matters if you are running six of them.

The shim listens on loopback TCP, and a TCP socket carries no `SO_PEERCRED` —
the kernel will not say which process is at the other end. So **every HTTP
client reached the daemon as one identity**, sharing one grant, one rate limit
and one revocation. The audit log had been saying so for weeks: a `curl`
running as root recorded as `shim:uid:967`, the shim's own uid.

`/etc/ai-daemon/shim.toml` (example at `/usr/share/doc/ai-daemon/`) maps tokens
to names, read from `Authorization: Bearer` or `x-api-key`:

```toml
require_token = false

[[client]]
name = "cx"
token = "..."
```

A caller presenting one is `shim:cx`, so `aidctl deny shim:cx generate`
refuses that agent and leaves the others working. A caller without one is
anonymous and says so.

**Read this before relying on it.** A token is a shared secret in a file:
anything that can read `/etc/ai-daemon/shim.toml` can present the token. It
tells *cooperating* clients apart, which is what per-agent budgets need. It is
not peer credentials, and the trust class deliberately does not move —
everything through the shim is still the daemon's lowest class. The structural
fix is a Unix-socket listener, where the kernel does answer. **It is not
built.**

### Spend caps in money

Tokens per minute bounds a burst and says nothing about a bill. A runaway
agent on a local model costs nothing; the same agent on a hosted endpoint costs
real money at a rate no token count reveals.

```toml
[[price]]
model = "gpt-4o-mini"
input_per_mtok = 0.15
output_per_mtok = 0.60

[[identity]]
identity = "shim:ci-runner"
daily_spend = 2.00
```

`aidctl spend` shows the running total. A rolling 24 hours, not a calendar day.
Prices are yours to write: no endpoint publishes a rate the daemon could read,
and a guessed one gives a ceiling nobody can reconcile with an invoice. A model
with no entry is free, so this is inert until you configure a remote provider.

Charged after the fact, because the cost is not known until the tokens exist —
so one request can carry the total past the ceiling and the next is refused.

### A remote provider, and what it does to the privacy claim

`ai-daemon-backend-remote` talks to an OpenAI-compatible endpoint. It cannot be
a child of the daemon: `PrivateNetwork=yes` means anything the daemon forks has
no route anywhere. So it is its own unit, with its own uid and its own network,
and the daemon connects to it over a socket.

Be exact about what that changes. "The process that holds every prompt has no
network" is **still true of `ai-daemon`**. It is **not true of the machine**
once a remote provider is configured, because that process has both — which is
what a remote provider *is*. Turning one on is a deliberate act: the unit will
not start without `/etc/ai-daemon/remote.toml`, which the package does not
install. Every session it serves reports `local: false` in the consent prompt,
in the session, and in every audit record.

### Preludes and provenance marking

Text every turn carries that the client cannot remove, and markers saying where
the rest of the prompt came from — `<policy>` for the machine owner's text,
`<from-app>` for the client's, `<tool-output>` for whatever came back from a
tool call, which is to say whatever was in a file or a web page.

Each marker carries a nonce minted per session from `/dev/urandom`. The nonce
*and the tag names* are stripped from everything a client or tool supplied, so
a prompt cannot spell a second `<policy>` block at all.

Both off by default and both per-identity, which is usually what you want: the
agent that reads issue trackers needs this, the plugin summarising a paragraph
does not. A prelude shipping with the daemon would be a sentence somebody else
wrote appearing in every prompt on the machine, which is the thing the feature
exists to prevent.

**What it is:** the part an OS can guarantee — the distinction is available to
the model and is not forgeable from inside the content. **What it is not:** a
promise the model honours it. Nothing at this layer can make it.

### An audit log that notices being edited

Every record carries the hash of the line before it. `aidctl audit --verify`
walks the chain and names the line it broke at, and whether something was
changed, removed or reordered. The verifier reads the file rather than asking
the daemon — a log you can only check by asking the process that wrote it is
not evidence — so point it at a copy on another machine.

Tamper-evident, not tamper-proof. Somebody who owns the file can rewrite the
chain from the point of an edit; what this costs them is the whole remainder
rather than one line, and it makes a truncated tail visible instead of merely
shorter.

### A portal, for apps that have a real identity

`ai-daemon-portal` runs as the user on the session bus and reads a caller's
Flatpak or Snap confinement from outside the sandbox — the only application
identity on Linux the app itself cannot choose. It serves the interface
proposed in §13 under an interim bus name, because `org.freedesktop.portal.AI`
is a proposal and squatting it would poison the review it needs.

It refuses callers it cannot identify rather than lending them its own name:
passing an unsandboxed app through would label every one of them as the portal
and make them share a grant.

### Protocol v2

Media generation, parallel tool calls, and fine-grained sampling control
(`top_k`, `min_p`, `repeat_penalty`, `logit_bias`, `logprobs`). Both the data
plane and the provider protocol are at v2 and both still serve v1: a v1 client
is never sent anything v2 added.

---

## Compatibility

**Model capabilities are now enforced.** `manifest.capabilities` was documented
as intersected with the backend's claims and was consulted nowhere — the mock
backend embeds, so every model installed against it embedded, whatever its
manifest said. Both halves are enforced now, at install and at request.

`aidctl install` has always defaulted to `["generate"]`, so **a model installed
before this and used for embeddings will be refused.** The error names the
model, says what it does offer, and carries the fix:

```
aidctl install --capability embed ...
```

There is no grandfathering, and the reasoning is worth repeating because it
will look like an oversight: every manifest has a non-empty list, so a legacy
default and a deliberately generate-only model are indistinguishable. Exempting
them makes the field permanently unenforceable, which is worse than the break.

The blast radius was measured rather than estimated. Turning enforcement on
broke six checks in this repository's own verification — media output, raw
pixels, embeddings on the remote model — in sections with nothing to do with
capabilities. They broke because the fixtures declared `generate` and `embed`
and were then handed screenshots and asked for pictures. That is the shape of
the break for a real install too: it lands wherever the field was decoration.

The operator approved it on the grounds that nothing is deployed yet.

---

## Known limitations

Stated here rather than left to be discovered:

- **The shim's identity is a shared secret**, not peer credentials. See above.
  The Unix-socket listener that would fix it properly is not built.
- **The freedesktop names are not ours yet.** `org.freedesktop.AI1` and
  `org.freedesktop.portal.AI` are proposals; the daemon owns
  `io.github.agraves.AIDaemon1` and the portal `io.github.agraves.AIPortal1`.
- **`ListModels` through the portal is not narrowed to the asking app.** The
  daemon filters by caller identity and the caller is the portal, so you get
  the machine's list. Fixing it changes that method's D-Bus signature and
  breaks every existing caller, so it waits for a control-plane version bump.
  `CreateSession` is where a per-app decision is enforced, and always was.
- **Media output is not budgeted against the KV ceiling.** An image model holds
  no per-token cache and every media backend reports zero, so reserving what
  they report and reserving nothing are the same number today. The daemon warns
  loudly if one ever reports non-zero.
- **Two things the verification cannot show**, both named where they happen
  rather than skipped: the portal-to-daemon assertion end to end, because the
  daemon identifies a portal by the caller's cgroup and the test container has
  a read-only cgroupfs; and a real mount-namespace sandbox, so `.flatpak-info`
  sits at the container root and what is proven is the read and the parse, not
  the isolation. The daemon's *refusal* is tested end to end; its acceptance is
  unit-tested over the same function the D-Bus path calls.
- **seccomp is unavailable in the test box**, which is a translated x86-64
  container on an arm64 host, so `ai-daemon-decode` refuses to decode — the
  designed behaviour for a helper that cannot build its cage. The verification
  asserts that refusal rather than skipping the case, and the codecs are
  covered by unit tests.

---

## Verifying it yourself

`dev build` runs the whole thing: `makepkg` from a source tarball, `pacman -U`
into a clean box, then 253 checks against the installed package over the system
bus with polkit running, plus the workspace’s 154 unit tests. The verification
runs *during* the build, so a failure fails the build.

It is deliberately adversarial — a wrong digest, an oversized attachment, a
truncated PNG, a user outside the gate, a revoked identity, a prompt trying to
forge a provenance marker, an edited audit record — because "it generated some
text" is the easy half and the refusals are the point.
