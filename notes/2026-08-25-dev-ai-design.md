# Plan: /dev/ai — LLM inference as an OS-mediated resource

**Date:** 2026-08-25 · Status: **proposed; project `ai-daemon` created, source
stub at `daemon/Sources/ai-daemon/`.** This is the founding design record.

## The problem

Every process that wants intelligence today does three broken things: holds an
API key as ambient authority (any dependency in the process can read it),
needs open egress to a provider (sandboxing an AI-using program means punching
exactly the hole exfiltration wants), and is invisible to the OS (no identity
on requests, no quotas, no audit, no policy). The fix is the one Unix applied
to every other shared, dangerous, expensive resource: put a device in front of
it and make the kernel the source of truth about *who is asking*.

## The pattern: mediation surface in the kernel, machinery in userspace

Inference no more belongs in the kernel than a VM's instruction emulation —
`/dev/kvm` is the precedent: a small, sharp kernel surface (identity, fds,
accounting) with heavy userspace machinery behind it.

- **`aid`** — the broker. Holds provider credentials, talks to backends
  (local llama.cpp/vLLM, remote APIs), enforces policy, meters usage, writes
  the audit chain.
- **The device tree** — served CUSE/FUSE-style, no kernel patches required;
  the kernel contributes what it already contributes: requester identity and
  file descriptors.
- **`/sys/class/ai/`** (eventually) — enumeration and attributes.

## The device tree: a node is a trust boundary

```
/dev/ai/
  auto            ← opaque: "the admin's routing decides"
  anthropic       ← explicit consent to Anthropic seeing the conversation
  openai
  local           ← weights on this box; nothing leaves
```

One node per **provider** — the trust boundary, the answer to "who is allowed
to see this process's prompts" — plus the opaque `auto` node. Model choice
*within* a provider is a preference among endpoints that all see the same
data, so it lives in the request payload, governed quantitatively by `aid`.
Providers change rarely; models weekly; the tree stays small and stable.

What the tree buys, each from existing machinery:

- **DAC/MAC per target.** `chmod` answers "who may use Claude"; an LSM label
  per node lets SELinux/AppArmor policy speak in (domain, provider) natively.
- **Per-sandbox views via mount namespaces.** Bind-mount only `local` into a
  container and remote egress *does not exist* for it — not denied, absent.
  The namespace is the approval, legible and revocable by unmount.
- **Enumeration**: `ls /dev/ai` answers "what can this box think with", per
  observer. `/dev/disk/by-*`-style alias views (`by-capability/`, `by-cost/`)
  are symlinks, no new mechanism.
- **Literal mounts**: binding a provider can be a mount —
  `mount -t ai -o provider=anthropic,credential=@vault none /run/ai/anthropic`
  — options carry config, namespaces scope visibility, `umount` is
  revocation. Providers are to `aid` what filesystem types are to the VFS.

### The `auto` node's rules

- **Routes only within the caller's namespace**: `auto` may pick among the
  provider nodes the caller can see. Without this rule `auto` is a bypass
  hole that re-centralizes everything the tree decentralized.
- **Pins its provider per session** (chosen at open or first request) and
  **discloses the choice** in stream metadata and the audit record. A
  conversation must never move companies silently.
- **The default grant for sandboxes is `auto` alone** — the admin controls
  routing entirely; handing a process a provider node is the deliberate act
  of consenting to that egress.

## Sessions are capabilities

`open()` on any node yields a session fd — an **unforgeable, delegable
capability** and the design's center of gravity. A supervisor opens a session
under narrow policy (model X, 4k context, 10k tokens, no tools, mandatory
prelude) and passes the fd into a sandboxed child over `SCM_RIGHTS`. The
child can think and can do nothing else: no key to steal, no network to need,
no way to widen the grant. Cross-provider escalation is the supervisor's job
— open the second fd, hand over the context — never the session's.

## Identity and policy

Requests arrive with kernel-attested identity: pid, uid/gid, cgroup path, LSM
context. `aid` evaluates `/etc/ai/policy.d/` against the tuple:

- models by name and, for local weights, **by digest** (a tag someone can
  repoint is not a security boundary),
- limits: context, max output, tokens per window, sessions, spend caps,
- **mandatory preludes** the client cannot remove, with **provenance
  marking** — the broker knows which bytes came from the process versus from
  policy and tags them for the model (the operator-message wrapper, applied
  at the OS boundary),
- capability toggles: tool use, content vs metadata-only logging, redaction.

## Accounting: tokens get the cgroup treatment

Per-cgroup `ai.max` (tokens/window), `ai.current`, `ai.stat`, pressure
signals. `aid` schedules with priority classes and token buckets; a runaway
generation ends with `TRUNCATED_BY_LIMIT`, the `SIGXCPU` of inference. For
remote providers the same machinery meters **money**: "this CI runner may use
$2/day" is a line of policy.

## Wire protocol on the fd

Framed CBOR, boring on purpose:

```
write:  REQUEST  {model?, params?, messages | delta, tools?}
read:   EVENT    {token-delta | tool-call | usage | status}
ioctl:  AI_SET_MODEL, AI_GET_LIMITS, AI_SET_PARAMS, AI_ABORT
```

Streaming is `read()`; `poll`/`epoll` work; close aborts. A conversation is a
held fd, inheriting process-lifetime cleanup for free.

## Audit

Every request/response appended to a hash-chained log with the identity
tuple, applied policy, model digest, and usage — content or metadata-only per
policy. The property no HTTPS-and-key setup has: a tamper-evident,
machine-level answer to "what did any process on this box ever say to a
model, and who asked".

## Kernel endgame (optional, honest)

A real `ai` subsystem — native clone device, a cgroup v2 `ai` controller,
`security_ai_request()` LSM hooks, uevents for model hotplug — if the pattern
earns it. The honest counterpoint is FUSE's history: userspace-broker plus
conventions may be the permanent right shape. Bet: CUSE gets 95% of the value
at 5% of the politics.

## Ecosystem

`libai` (open/generate/stream), `ai(1)` for shells
(`git diff | ai -m local/qwen "review this"`), and an OpenAI/Anthropic-
compatible HTTP shim on localhost only, so unmodified SDKs work day one while
the fd stays the native, policy-rich path.

## Lineage

This is the paperclipper philosophy ported down a layer: `aid` is the vault
(credentials in the broker, callers get a vocabulary), the session fd is the
per-session token made unforgeable by the kernel, mandatory preludes are the
context brief, provenance marking is the operator wrapper, the audit chain is
`Audit.swift`. Identity asserted by the substrate, never taken from the
payload — the sentence this repo keeps writing.
