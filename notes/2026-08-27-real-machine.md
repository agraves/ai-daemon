# The demo on a real machine, and what the real machine found

**Date:** 2026-08-27 · Companion to `2026-08-27-state-of-play.md`, whose last
section argued the confinement demo "needs a machine, not this box". This is
that machine: the same WSL2 rig as `2026-08-27-omarchy-integration.md` — Arch
under WSL2, systemd running, an RTX 5090, `unshare -Un` permitted. The
verification container proves `ai-run` fails closed; none of what follows can
happen there at all.

## The demo, verbatim

The package built by `make-package.sh` on the box itself, installed with
`pacman -U`, services restarted. Then:

```
$ ai-run -- curl -sS --max-time 5 https://api.anthropic.com/v1/messages
(exit 7 — no route to anywhere; the namespace has one interface and it is down)

$ ai-run -- curl -sS --max-time 5 http://127.0.0.1:11434/v1/models
(exit 7 — loopback is network too, which is the whole reason the socket exists)

$ ai-run -- curl -sS --unix-socket /run/ai-daemon-shim/shim.sock \
    http://localhost/v1/chat/completions -d '{"model":"default","max_tokens":32,
    "messages":[{"role":"user","content":"Reply with exactly: CONFINED OK"}]}'
{"choices":[{"finish_reason":"stop","index":0,"message":{"content":"CONFINED OK",...
```

Same process, same user, no key anywhere in it, and the model on the other
side is running on the GPU. The audit record for that turn:

```
{"event":"session-start","identity":"shim:uid:1000","class":"shim","uid":1000,"pid":13713,...}
```

`pid` and `uid` are the *caller's*, named by the kernel over `SO_PEERCRED` —
the wart the socket was built to retire, observed retired. The key is
`shim:uid:1000` rather than an exe or unit name because a terminal-launched
process deliberately has no app identity, and the daemon cannot read
`/proc/<pid>/exe` across uids; both honest, both already written down.

And the native protocol, confined, through `examples/think.py`:

```
$ ai-run -- python think.py "Reply with exactly: CONFINED NATIVE OK"
[qwen-0.5b, you are uid:1000]
CONFINED NATIVE OK
```

That one works because the system bus is *also* a Unix socket. `ai-run` takes
the network and leaves the filesystem, so the control plane, the session
descriptor and the shim socket all survive. Nothing about that was designed
on purpose and it is the best property the design turns out to have: the
entire client story — D-Bus call, fd, CBOR frames — lives on objects a
network namespace cannot touch.

## Two things only a real machine could find

Both were found the same afternoon the demo first ran, which is the argument
for demos.

**`ai-run` never wrote uid maps.** `unshare(CLONE_NEWUSER)` leaves the
process with no identity mapping, so `getuid()` inside answered the overflow
uid (65534). curl never noticed — it sends no credentials. GDBus did:
D-Bus's EXTERNAL auth sends `SCM_CREDENTIALS`, the kernel refused to send an
unmapped uid, and `think.py` under `ai-run` died with "Error sending
credentials" — an auth failure surfacing nowhere near its cause. The fix is
the standard trio (`setgroups deny`, then uid_map and gid_map, each id mapped
to itself), and a failure to write them is fatal rather than shrugged at.
The docker box could not have found this: it cannot unshare at all, so every
path past the unshare was untested until a real kernel ran it.

**With `SO_PEERCRED` working, root got refused.** The verification's
confined-inference check ran as root, which had always worked — on TCP every
caller arrived as the shim's own uid, which is in the `ai` group. The moment
the socket named the real caller, the gate saw uid 0, which is deliberately
outside it ("there is deliberately no root exception"), and refused. The
check now runs as a gated user, and the refusal it tripped over is the gate
doing precisely what the design record promised — enforcement that used to be
impossible for want of an identity, arriving the moment the identity did.

## What this rig still is not

A supported target, a performance claim, or a substitute for the container
run — the box has secrets and state the verification would trample, so the
adversarial checks stay in the disposable box and the namespace demo lives
here. Between the two, every section of `run.sh` now has somewhere it runs
for real.

## Addendum, same day: standing identities and the meter

The second session on this rig, after `ai-run --as`, `Usage()` and the
journald fields landed. All four claims exercised for real:

```
$ ai-run --as demo-agent -- python /usr/share/doc/ai-daemon/examples/think.py "..."
[qwen-0.5b, you are unit:demo-agent@1000]        ← the standing name, confined

audit.jsonl, same minute:
  2 × "identity":"unit:demo-agent@1000"          ← native, through the scope
  2 × "identity":"shim:unit:demo-agent@1000"     ← same name over the socket

$ journalctl -t ai-daemon -o json | …            ← AI_EVENT/AI_IDENTITY/AI_*_TOKENS
session-end shim:unit:demo-agent@1000 qwen-0.5b 5 8

$ aidctl meter
shim:unit:demo-agent@1000     13    -    -
unit:demo-agent@1000          12    -    -
```

And the half that makes it policy rather than labelling: a drop-in rule
`tokens_per_minute = 5` against `unit:demo-agent@1000`, daemon restarted, and
the named launch is refused — `over its 5 tokens/minute allowance` — while an
anonymous `ai-run` of the same program is untouched. One rule, one name,
every launch.

What this session's mistake taught: the rule was first written as
`50-demo.toml`, which `config.toml.d/` silently ignores — drop-ins are
`*.conf`, systemd's convention under a directory whose name says `.toml`.
The daemon now says so at startup instead of letting a rule that does not
apply read as policy being ignored.
