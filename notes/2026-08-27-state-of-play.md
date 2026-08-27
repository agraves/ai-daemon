# Where this is, what it is for, and what comes next

**Date:** 2026-08-27 · master `7e6df21`, plus one branch of work built and not
yet landed. Written after a day in which the goal was restated more sharply
than the design record had it, so the first section is the important one.

## What this is actually for

The design record describes the mechanism. The purpose, as the operator put it
after the first agents were pointed at it, is narrower and easier to argue:

> Applications should reach a model the way they reach a disk. You do not build
> network frames to write a file; there are layers for that, and the operating
> system knows who is asking and can say no. This is that layer for inference.

The problem it answers is concrete. Once a desktop has a dozen widgets talking
to model providers, each one holds a credential, each one has egress, each one
runs as the user, and each one's behaviour is influenced by text it did not
write. That is a dozen remote-code-execution surfaces with no common place to
watch, throttle or refuse them.

So the goal is a **chokepoint**: applications get inference and nothing else.
No provider key, no network, no way to widen what they were handed. The daemon
holds the credential; the daemon does the talking; the daemon has the record.

Two things follow from that framing and are worth writing down because they
change what is worth building.

**Enforcement is credential custody first, network policy second.** If the only
provider key on the machine lives in `/etc/ai-daemon/remote.key`, an
application that goes direct has nothing to authenticate with. It does not need
to be blocked; it cannot succeed. Network confinement (`ai-run`) is
defence-in-depth for the case you cannot rule out — a widget that ships its own
key, or a user who pastes one in. Provisioning is the load-bearing half and it
is a policy about how the distribution ships, not code in this repository.

**Model interop is a side effect, not the point.** Claude Code talking to a
local llama through the shim is real, verified, and demonstrably impressive.
It is not the goal, and chasing it would turn a compatibility layer into the
product. Parked deliberately.

## The two demos this is being built toward

1. **"Build applications this way."** An app that does inference with no
   credential and no network, in one command, with `aidctl` attributing it
   afterwards. The pitch is that LLM access is a first-class thing a Linux
   installation should care about.
2. **Paperclipper's own problem.** Transparent HTTP calls flying around with no
   way to see usage, throttle, or detect a loop — and some components that
   should have no network at all.

Demo 2's visibility half works today with no new code: point the calls at the
shim with a token per component and `aidctl spend`, `aidctl sessions`,
`aidctl grants` and `aidctl audit --verify` answer all of it. The confinement
half is what the current branch adds.

## State of play

### Landed

The daemon does the things §5 promised and, until this week, largely did not:

- **Identity per caller** — systemd unit for native callers, Flatpak/Snap
  application id through `ai-daemon-portal`, and for HTTP callers a token
  table, now backed by real peer credentials on the socket. The portal-identity
  prefix check was a genuine hole (any user unit named `xdg-desktop-portal-*`
  could speak for any app) and is an exact-match allowlist now.
- **Policy per identity** — capabilities, context, sessions, tokens per minute,
  and a spend ceiling in money against an administrator's price table.
  `manifest.capabilities` is enforced at install and at request, both halves,
  no grandfathering.
- **Provenance marking and mandatory preludes**, per identity, off by default,
  with a per-session nonce and the marker names stripped from anything a client
  or tool supplied — so a prompt cannot spell a second `<policy>` block.
- **A hash-chained audit log**, verified by `aidctl audit --verify` reading the
  file rather than asking the daemon. Tamper-evident, not tamper-proof, and it
  says so.
- **Two client APIs** — OpenAI (chat completions, responses) and Anthropic
  (messages, count_tokens) — because the agents on the target box speak one
  each and neither speaks the other.
- **A remote provider** in its own unit with its own uid and network, marked
  `local: false` everywhere it shows.

### Built, not yet landed, and not yet green

The verification for these is in flight at the time of writing: the last
full run was 288 passed and 6 failed, five of them the `ai-run` namespace
limitation below and one a real bug in the rate narrowing — a session-local
limit written into `Limits` changed nothing, because the token bucket belongs
to the identity and already existed. Both are addressed; none of it has passed
a clean run yet, and it should not be described as done until it has.

- **A Unix socket on the shim.** The reason is confinement: loopback *is*
  network, so an application in a namespace with no interfaces cannot reach
  `127.0.0.1` either. A socket survives a namespace where a port does not. It
  is also where `SO_PEERCRED` answers, which retires the shared-secret wart —
  a caller there is named by the kernel.
- **Attenuation on `CreateSession`.** Seven options that can only narrow:
  `no_tools`, rate, sessions, spend, models, prelude (appended, never
  replaced), provenance (only ever on). This is the primitive the whole
  supervisor/child model needs — a descriptor you can hand over knowing the
  holder has strictly less than you do. A narrowed rate gets a session-private
  bucket *in addition to* the identity's, because otherwise a supervisor could
  mint unlimited children each under the limit.
- **`ai-run`** — network namespace with a downed loopback, socket left
  reachable, execs and gets out of the way. Refuses rather than running
  unconfined if it cannot unshare.

## What is not done

In the order I would do it.

1. **A client story that is not "here is the CBOR framing".** `aidctl` is the
   only worked example of the native protocol. If the pitch is "build
   applications this way", the thing a viewer copies has to exist and be about
   forty lines. This is the largest gap between the claim and the artifact.
2. **Provisioning guidance.** The credential-custody argument only holds if the
   distribution ships so that no application ever gets a provider key. That is
   a paragraph in an installation guide and a default, not code — but without
   it the strongest claim in the pitch is aspirational.
3. **Pinned-agent smoke tests in the verification box.** The shim reimplements
   vendors' APIs and they move: codex dropped chat completions between releases
   while this was being written. The defence is a failing build, not a support
   matrix. It needs network access during the build, which the box deliberately
   does not have — a real decision, not a task.
4. **Content inspection**, if wanted. The audit log records who and never what,
   by design. Under "protect the user from the app" rather than "protect the
   user from the daemon" that is a coherent thing to change, and the design
   record already anticipates it as a per-identity toggle. It should stay
   off by default and be visible in the audit when on. Not started, and it
   changes what this project is, so it wants a decision rather than a commit.
5. **`ListModels` through the portal is not narrowed to the asking app.**
   Fixing it changes a D-Bus method's signature and breaks every caller, so it
   waits for a control-plane version bump.

## What the box cannot show

Four now, all named where they happen rather than skipped, because a
verification that quietly proves less than it claims is worse than one that
admits the gap:

- **seccomp** — the box is a translated x86-64 container on an arm64 host and
  the emulator cannot pass a filter to the kernel, so `ai-daemon-decode`
  refuses to decode. The verification asserts the refusal.
- **cgroups** — read-only cgroupfs, so nothing can be placed in a cgroup named
  after a unit, so the daemon cannot recognise the portal. Its *refusal* is
  tested; its acceptance is unit-tested over the same function.
- **A real sandbox** — `.flatpak-info` sits at the container root, which
  exercises the read and the parse but not the isolation.
- **`ai-run`'s namespace** — a docker build step has neither `CAP_SYS_ADMIN`
  nor a seccomp profile permitting `unshare(CLONE_NEWUSER)`. What is proven is
  that it fails closed, and the rest of the wiring under `--keep-network`.

The first three have been true for days. The fourth is new and is the one that
matters for the demo, because the demo *is* the thing the box cannot do — which
is an argument for recording it on a real machine, not for weakening the claim.

## The thing I would flag to whoever picks this up

The shim is 2,507 lines of 19,402 and it is the only part speaking a protocol
we do not control. That asymmetry is permanent: the native protocol is one we
freeze and version and refuse peers outside, and the shim speaks protocols
vendors change without asking. The right response is not to make it better but
to make it *bounded* — serve what the named agents use, pin their versions in
the box, and let breakage be a failing build. If the freedesktop portal
interface ever lands, applications target that and the shim stops growing. It
is a bridge in the literal sense: built to be crossed and eventually abandoned.
The failure mode to avoid is letting it become the product.
