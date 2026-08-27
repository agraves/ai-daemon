# ai-daemon protocols

Three wire surfaces, each versioned by an explicit integer in the first frame.

The data plane and the provider protocol are at **v2**, and both still serve
**v1**. A peer says what it speaks in its hello, the other side answers with
the version it will actually use, and everything a version added is simply not
sent to a peer that predates it — a v1 client offered two tool calls receives
one, because it has no frame in which to answer two and dropping the rest
silently would be worse than not offering them. A peer asking for a version
outside the served range is told the range and the connection closes.

The floor moves only when a version is genuinely withdrawn, which has not
happened. `MIN_DATA_PROTO` and `MIN_BACKEND_PROTO` are where that is written
down.

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
| `shim_client` | `s` | as above; the name a token mapped to. Refused, not ignored, from anything that is not the shim |

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
{op: "generate_media", kind: "image"|"audio", prompt, params?, count}   v2
{op: "tool_result", id, content}
{op: "tool_results", results: [{id, content}, …]}                      v2
{op: "embed", inputs: [...]}
{op: "tokenize", text}
{op: "cancel"}
```

Daemon → client:

```
{ok, proto, session: {session, model, identity, local, capabilities, max_context}}
{tok: "...", logprobs?: [{tok, logprob}, …]}          logprobs are v2
{tool_call: {id, name, arguments}}
{tool_calls: [{id, name, arguments}, …]}              v2
{media: [{kind, mime, w, h, rate, samples, len}, …]}  v2, + BLOB frame each
{event: "context-evicted", detail}
{vectors: [[...]]}
{tokens: [...]}
{done: true, usage: {prompt_tokens, completion_tokens, attachment_tokens,
   media_bytes}, finish_reason}
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

**Parallel calls (v2).** A model that wants two tools at once sends
`tool_calls` and the turn resumes when the last one has been answered, via
`tool_results`. Answering some of several and resuming would put the model in
front of a half-answered question. The daemon asks a backend for parallel
calls only when the backend declares `parallel-tools` *and* the client
negotiated v2; otherwise it asks for one at a time and the old frames are what
appear on the wire.

### Sampling control

v2 adds `top_k`, `min_p`, `repeat_penalty`, `logit_bias` (a map of token id
to bias) and `logprobs` (how many alternatives to return per token) to
`params`. A backend applies what it can and ignores the rest; `logprobs` is a
declared capability, so a client can find out before asking.

## The HTTP shim

Two APIs on one loopback port, off by default:

| | |
|---|---|
| OpenAI | `GET /v1/models`, `POST /v1/chat/completions`, `POST /v1/embeddings` |
| Anthropic | `POST /v1/messages`, `POST /v1/messages/count_tokens` |

Both become ordinary daemon sessions: same policy engine, same rate limit,
same audit record, same `aidctl sessions`. Only the wire shapes differ, and
they differ in ways worth naming — `system` is a field rather than a message,
`max_tokens` is required and is *not* defaulted, tool results arrive inside a
user turn, tool arguments are an object rather than a JSON string, and the
streaming protocol is a state machine of named events rather than one repeated
chunk shape. Errors go out in the envelope of whichever API was called, because
a client that cannot parse the other one's error body gets nothing useful.

Neither route ever fetches a URL a prompt named. OpenAI `image_url` takes
`data:` only; Anthropic image blocks take `source.type = "base64"` only. A
`url` source is refused rather than followed: this process is the last place
that should hold a server-side request forgery primitive.

### Naming the callers

A loopback TCP socket has no `SO_PEERCRED` — the kernel will not say which
process is at the other end — so every HTTP client reached the daemon as one
identity, sharing one grant, one rate limit and one revocation. On a machine
running several agents that is the difference between per-agent policy and
none.

`/etc/ai-daemon/shim.toml` maps tokens to names. A caller presenting one in
`Authorization: Bearer` or `x-api-key` is `shim:<name>`; one without a token
stays anonymous and says so. `require_token = true` refuses anonymous callers
outright, which is the right setting once a machine has named its agents.

The trust class does not move: everything here is still `Class::Shim`. A
shared secret in a file is weaker than peer credentials and this does not
pretend otherwise — any local process that can read the token file can present
the token, so what it buys is that *cooperating* clients are told apart. The
structural fix is a Unix-socket listener where `SO_PEERCRED` answers, and it
is not built yet.

The name is the shim's to assert and nobody else's: the daemon takes
`shim_client` only from the shim, and refuses it — rather than ignoring it —
from anything else.

The OpenAI-compatible shim maps only `logit_bias` and `top_logprobs`, which
are the two OpenAI itself defines. It deliberately invents no spelling for the
others: a request that meant something different through the bridge than
through the native protocol is the one thing a compatibility bridge must not
produce.

### Media output

`generate_media` asks for pixels or samples rather than tokens, and needs the
`generate-media` capability — separately from `generate`, because a user may
reasonably let an app write text and not let it synthesise a voice, and a
permission that cannot be withheld on its own is not one.

Results arrive as a `media` header frame describing each result, then the
bytes: the same shape an attachment uses arriving, bounded by the same
per-request ceiling, because they cross the same single CBOR frame from the
backend. There is no encoder in the daemon any more than there is a decoder —
raw RGBA8 and raw float32 PCM, and the client writes a file if it wants one.

## Provider protocol

Backends are separate processes. The daemon passes one end of a socketpair as
fd 3 and sets `AI_DAEMON_BACKEND_FD=3`. Same framing as the data plane;
requests carry `req_id` and replies echo it, so one socket multiplexes every
session assigned to that backend.

```
→ {op: "hello", proto: 2}
← {ev: "hello", proto: 2, info: {name, version, formats, quantizations,
                                 devices, device_memory, capabilities, local}}
→ {op: "load", model_id, path, digest, n_ctx}
← {ev: "loaded", model_id, kv_bytes_per_token, n_ctx}
→ {op: "generate", req_id, model_id, session_id, messages, params,
     grammar?, tools?, attachments?, parallel_tools}
→ {op: "generate_media", req_id, model_id, kind, prompt, params, count}
← {ev: "token", req_id, tok, logprobs?} …
← {ev: "tool_call", req_id, tool_call}
← {ev: "tool_calls", req_id, tool_calls}
← {ev: "media", req_id, media}                 + BLOB frame per result
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
  batch job. A paused request may then say nothing for as long as the daemon
  keeps it paused, and that is not held against it: the daemon gives up on a
  backend that is silent for `daemon.backend_silence_seconds`, but only counts
  time the request was free to speak.
- **Declared devices are the devices opened.** The daemon checks them against
  the unit's `DeviceAllow` at hello time and refuses a backend that claims
  more, rather than discovering it at load time.

`ai-daemon-backend-mock` is the reference implementation of all of this and is
installed. It loads no weights, opens no devices, and emits exactly
`max_tokens` deterministic tokens, which is what makes it useful as a fixture.

### Backends the daemon connects to

The daemon normally spawns a backend and owns it. One case cannot work that
way: a provider that needs a network. The daemon runs with
`PrivateNetwork=yes`, and anything it forks lands in that namespace with no
route anywhere — there is no flag that lets a child opt back out, which is the
point of a namespace.

So a backend may say `connect = "/path/to.sock"` instead of `exec`, and the
daemon dials it. Exactly one of the two, checked at configuration load;
`args` and `env` alongside `connect` are refused rather than ignored, because
neither can reach a process this daemon did not start. Everything after the
connection is identical: same framing, same hello, same multiplexing.

`ai-daemon-backend-remote` is the implementation: an OpenAI-compatible client
in its own systemd unit, with its own uid, its own runtime directory and a
network. It declares `local: false`, which the daemon threads into the consent
prompt, into every session's `local` property and into every audit record. It
is off unless `/etc/ai-daemon/remote.toml` exists, and nothing the package
installs creates that file.

A model it serves is registered with `aidctl install --source remote:<id>`,
has format `remote`, and carries no weights — so no digest is asked for and
none is manufactured. Its manifest identifier reads `remote:<id>` rather than
`sha256:…`, because the integrity of a remote model is the endpoint's promise
rather than this machine's measurement, and a hash-shaped string would be a
claim this daemon cannot honour.

## Portal

`org.freedesktop.portal.AI` is proposed in §13 and specified in
`org.freedesktop.portal.AI.xml`, which ships with the package. Until it is
accepted into xdg-desktop-portal there is no frontend to write a backend
against, so `ai-daemon-portal` serves the same interface under its own name:

| | |
|---|---|
| Bus name | `io.github.agraves.AIPortal1` (**session** bus) |
| Object | `/io/github/agraves/AIPortal1` |
| Interface | `org.freedesktop.portal.AI` |

Methods are `CreateSession` (returns the daemon's own descriptor and object
path — the portal is not in the token path), `ListModels`, and `Identify`,
which answers "what would you assert for me" without opening anything.

`ListModels` through the portal returns the machine's list as *the portal*
sees it, not the list narrowed to the asking app: the daemon filters by caller
identity and the caller is the portal. Narrowing it needs an options argument
on the daemon's `ListModels`, which would change that method's signature from
`()` to `(a{sv})` and break every existing caller — a control-plane version
bump, not a patch, and not yet made. `CreateSession` is where a per-app
decision is enforced, and always was.

It runs as the user, because `/proc/<pid>/root/.flatpak-info` and
`/proc/<pid>/attr/current` are readable by the owner of those processes and
the daemon is not that. It reads them for a pid the *bus* vouched for, never
one a message body claimed, and re-reads the process start time afterwards so
a recycled pid cannot substitute itself mid-read.

The daemon believes it because of who is calling, never because of what the
call says: `policy.portal_units` is a list of exact unit names, matched
against the caller's systemd unit (from its cgroup, which is world-readable and
not self-chosen) and against its executable name. Only the `.service` suffix
is optional, so an administrator may write either spelling of the same unit;
everything else must match to the character. Not a prefix, deliberately: a
prefix would cover the `-gtk`/`-gnome`/`-kde` variants in one line and would
also let any user write
`~/.config/systemd/user/xdg-desktop-portal-anything.service` and be believed
about every application on the machine, so the variants are listed one by one.
Emptying that list turns portal identity off.
An app that sets `portal_app_id` itself is refused twice — by the portal,
which will not forward a caller-chosen id, and by the daemon, which will not
take the claim from anything not on the list.

A caller the portal cannot identify is refused rather than passed through.
Lending it the portal's own identity would label every unsandboxed app on the
machine as the portal and make them share one grant; such an app should call
the daemon directly, where it is honestly classed `native`.
