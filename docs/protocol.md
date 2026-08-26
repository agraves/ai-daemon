# ai-daemon protocols

Three wire surfaces, all frozen at v1 and all versioned by an explicit integer
in the first frame. A peer that does not recognise the version says so and
closes; there is no negotiation ladder, because there is only one rung.

- **Control plane** — D-Bus on the system bus. Enumeration, sessions, policy,
  model administration.
- **Data plane** — a Unix socket per session, handed to the client as a file
  descriptor when the session is created. Token streaming, attachments,
  embeddings.
- **Provider protocol** — the same framing over a socketpair, between the
  daemon and each backend plugin.

The split between the first two is deliberate and is described in §3 of the
design: D-Bus gives activation, introspection and peer identity for free, and
its per-message cost is irrelevant for control traffic and unacceptable for a
token stream.

## Names

The target D-Bus name is `org.freedesktop.AI1`. This implementation does not
use it. That namespace is earned by taking the specification through
freedesktop review, not claimed by shipping under it, and a daemon squatting
the name it wants to standardise would poison the review it needs. Until then:

| | |
|---|---|
| Bus name | `io.github.agraves.AIDaemon1` |
| Manager object | `/io/github/agraves/AIDaemon1/Manager` |
| Manager interface | `io.github.agraves.AIDaemon1.Manager` |
| Session objects | `/io/github/agraves/AIDaemon1/session/<id>` |
| Session interface | `io.github.agraves.AIDaemon1.Session` |

When and if standardisation happens, the daemon takes the freedesktop name and
keeps answering to this one as a compatibility alias.

## Control plane

### Manager

```
ListModels()                     → aa{sv}
Resolve(alias: s)                → s
ListAliases()                    → a{ss}
CreateSession(model: s, options: a{sv})
                                 → (session: o, data: h)
ListSessions()                   → aa{sv}
ListGrants()                     → a(sssts)      identity, capability,
                                                 decision, when, via
SetGrant(identity: s, capability: s, allow: b)          [model-admin]
Revoke(identity: s)              → u                    [model-admin]
InstallModel(source: s, digest: s, name: s, options: a{sv})
                                 → s                    [model-admin]
RemoveModel(name: s)                                    [model-admin]
SetAlias(alias: s, target: s)                           [model-admin]
PinModel(model: s, pinned: b)                           [model-admin]
Status()                         → a{sv}

properties: Version (s), DataProtocol (u), Backends (as)
```

`CreateSession` options:

| key | type | meaning |
|---|---|---|
| `priority` | `s` | `interactive` (default) or `background` |
| `max_context` | `u` | clamped down by policy and by the model |
| `portal_app_id` | `s` | accepted only from xdg-desktop-portal (§13) |
| `shim_peer_pid` | `u` | accepted only from `ai-daemon-shim` (§5) |
| `shim_peer_uid` | `u` | as above |

`CreateSession` is cheap on purpose. It does not prompt for consent and does
not load weights: both can take a long time, and the bus thread is shared with
every other caller on the machine. The first `generate` on the session is
where consent is asked and the model is loaded.

`InstallModel` options are `format` (default `gguf`, checked against the file's
magic), `backend`, `license`, and `capabilities` (`as`).

### Session

```
Cancel()          stop the current generation; the session and its context live
Close()           end the session

properties: Identity, Model, Digest, Backend, Priority, State (all s),
            Local (b), PromptTokens, CompletionTokens, AttachmentBytes (t)
```

## Data plane

Framing:

```
u32 be length | u8 kind | payload[length]
kind 0x01 = CBOR value
kind 0x02 = BLOB, belonging to the most recent `attach`
```

One tag byte rather than two sockets: attachments are large and must not pay
CBOR's byte-string copy, but they still need ordering relative to the request
that references them.

Client → daemon:

```
{op: "hello", proto: 1}
{op: "attach", id, kind: "image"|"audio",
   meta: {w, h, fmt} | {rate} | {encoded: "image/png"}, len}   + BLOB frame(s)
{op: "generate", messages: [...], stream, params?, grammar?, tools?}
{op: "tool_result", id, content}
{op: "embed", inputs: [...]}
{op: "tokenize", text}
{op: "cancel"}
```

Daemon → client:

```
{ok, proto, session: {session, model, identity, local, capabilities, max_context}}
{tok: "..."}
{tool_call: {id, name, arguments}}
{event: "context-evicted", detail}
{vectors: [[...]]}
{tokens: [...]}
{done: true, usage: {prompt_tokens, completion_tokens, attachment_tokens},
   finish_reason}
{error: {code, message}}
```

Error codes are stable strings: `policy-denied`, `rate-limited`,
`no-such-model`, `attachment-unsupported`, `backend-failed`, `protocol`.

### Attachments

Two accepted forms, and the reason there are only two is that the daemon links
no media codecs (§11):

1. **Raw.** RGB8 or RGBA8 pixels with `w`/`h`/`fmt`, or mono float32 PCM with
   `rate`. The client decoded it; the privileged process parses nothing.
2. **Encoded**, with `meta.encoded` set. The daemon hands it to
   `ai-daemon-decode`: one child per attachment, seccomp-confined to read,
   write, memory and exit, no filesystem, no network, killed on a deadline. A
   decoder crash costs one attachment.

`ai-daemon-decode` accepts 8-bit non-interlaced truecolour PNG and PCM WAVE.
Everything else is refused with `attachment-unsupported`, and the client
decodes it themselves — which is always available and is form 1.

### Tool calling

The client registers schemas; the daemon compiles them into a GBNF grammar and
hands it to the backend's constrained decoder, so a tool call is well-formed by
construction rather than parsed hopefully out of free text. The daemon then
emits a `tool_call` frame — **inert data**. It has no idea what the tool does
and will not find out. The client executes it and answers with `tool_result`,
and generation resumes in the same session with its KV cache warm, which is the
latency win over a stateless HTTP loop.

Tool-enabled sessions need the `generate-tools` capability, separately from
`generate`, so a user can allow an app plain generation and deny it agentic
use.

## Provider protocol

Backends are separate processes. The daemon passes one end of a socketpair as
fd 3 and sets `AI_DAEMON_BACKEND_FD=3`. Same framing as the data plane;
requests carry `req_id` and replies echo it, so one socket multiplexes every
session assigned to that backend.

```
→ {op: "hello", proto: 1}
← {ev: "hello", proto: 1, info: {name, version, formats, quantizations,
                                 devices, device_memory, capabilities, local}}
→ {op: "load", model_id, path, digest, n_ctx}
← {ev: "loaded", model_id, kv_bytes_per_token, n_ctx}
→ {op: "generate", req_id, model_id, session_id, messages, params,
     grammar?, tools?, attachments?}
← {ev: "token", req_id, tok} …
← {ev: "tool_call", req_id, tool_call}
← {ev: "done", req_id, usage, finish_reason}
→ {op: "pause"|"resume", req_id}       honoured at a token boundary
→ {op: "cancel", req_id}
→ {op: "drop_cache", session_id}
→ {op: "embed"|"tokenize", req_id, …}
→ {op: "shutdown"}
```

Three obligations a backend must meet, because the daemon's guarantees rest on
them:

- **`kv_bytes_per_token` must be honest.** The scheduler's whole global budget
  is that number times context length, and VRAM is not cgroup-controllable
  (§14), so this accounting is the only thing between two apps and an OOM.
  Erring high costs throughput; erring low costs the machine.
- **`pause` is honoured at a token boundary** — not mid-decode, and not later
  than the next token. That is what makes interactive work actually preempt a
  batch job.
- **Declared devices are the devices opened.** The daemon checks them against
  the unit's `DeviceAllow` at hello time and refuses a backend that claims
  more, rather than discovering it at load time.

`ai-daemon-backend-mock` is the reference implementation of all of this and is
installed. It loads no weights, opens no devices, and emits exactly
`max_tokens` deterministic tokens, which is what makes it useful as a fixture.
