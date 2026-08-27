# Running Omarchy's agents through it: what broke, and what it costs to keep working

**Date:** 2026-08-27 · Status: **two of Omarchy's six agents verified running
against the daemon**; three fixes landed (`bae6482`, `ed9204d`, `aec93e2`).
Companion to `2026-08-26-implementation.md`.

The README names "Omarchy's agent tooling" in its first paragraph. This is the
first time any of it was actually pointed at the daemon rather than reasoned
about, and the exercise was worth more than the reasoning: nothing below was
predicted from reading the source.

## The rig, and what it is not

Arch on WSL2, Omarchy 3.8.5, an RTX 5090, Qwen2.5-7B-Instruct Q4_K_M served by
llama.cpp at 32k context. Claude Code 2.1.245 over `/v1/messages`, codex-cli
0.150.1 over `/v1/responses`, each with its own token in `shim.toml` so they
arrive as `shim:claude-code` and `shim:codex`.

It is a test box and its results carry that caveat. WSL2 is not a supported
target, the model is far smaller than anything these agents were built for, and
the "vendor" model name is a local GGUF wearing a costume (see below). What it
does establish is which failures are in this project and which are not, because
every one of them was hit by running the real client rather than a curl.

## Five things stood between the design and the first agent turn

In the order they were met, because the order is the point: each one had to be
cleared before the next became visible, and each reported accurately in a way
that pointed somewhere else.

**A query string changed the route.** Claude Code sends every turn to
`POST /v1/messages?beta=true`. Routing matched the raw request target, so that
fell to the 404 arm, and an Anthropic client reads a 404 from `/v1/messages` as
a model that does not exist. The user is told `There's an issue with the
selected model`, naming a model that is installed, loaded and answering. Worse
for diagnosis: the session-title call carries no query and succeeded on the same
connection with the same token, so auth and the model both looked fine and only
the turns that mattered failed. Fixed in `bae6482`.

**The shim never asked for a context size.** Every HTTP session took the
backend's 4096 fallback, because the shim is the only thing in the path that
*can* ask — neither wire format has a field for context length, since a client
states `max_tokens` for its output and assumes the window is a property of the
model it named. 4096 is under the floor here: Claude Code's system prompt alone
measures ~8.8k, so it was refused before its first turn, with an accurate
message about a window that no configuration appeared to control. Raising
`max_context` in policy correctly moved a ceiling nothing was reaching up to.
Fixed in `aec93e2`.

**The model's manifest caps context at 4096 regardless.** `Requirements::default()`
is `default_ctx: 4096, max_ctx: 4096`; `aidctl install` has no flag to set
either, and `install.rs` checks the GGUF magic but never reads its metadata. So
a 32k model becomes a 4k model permanently, and the third clamp in
`dbusapi.rs` — `.min(resolved.manifest.requirements.max_ctx)` — silently wins
over both the session request and the policy ceiling. Getting past it meant
editing JSON under `/var/lib/ai-daemon/models/manifests/` by hand. **Not
fixed**; see below.

**`tokens_per_minute = 12000` is spent by the second turn.** An agent sends its
whole system prompt every request. At ~8.8k a turn the shipped default is gone
almost immediately, and the client sees a 429 it cannot act on. **Not fixed** —
and the run described next argues the mechanism is right even though the number
is wrong.

**codex could not connect at all.** It refuses to start against a provider
configured for chat completions: `wire_api = "chat" is no longer supported`.
Modern codex speaks only the Responses API, so a bridge serving
`/v1/chat/completions` cannot serve it however correct that endpoint is.
Supporting one OpenAI dialect turned out to mean supporting the one its clients
have left. Implemented in `aec93e2`.

There was a sixth, and it is still a hack: **nothing maps a client's model id
to a daemon model.** The shim passes `body["model"]` through, agents send vendor
ids, and Claude Code validates the name client-side against a list it ships. The
only way in was to install a Qwen GGUF under the name
`claude-sonnet-4-5-20250929`. That works and should not. A mapping table belongs
beside the client table in `shim.toml`.

## What the first successful run cost

With every limit raised, one `claude -p "Reply with exactly: OMARCHY OK"`:

```
sessions opened:           715
prompt tokens billed:  2,660,643
completion tokens:        20,611
```

Claude Code printed nothing and exited 0. The 7B answered each turn in ~72
tokens, never in the shape the agent wanted, so it retried — resending ~28k of
accumulated context each time until it approached the window. codex did the same
thing in its own idiom: 120 sessions, 456,834 tokens, and a `create_goal` call
whose `token_budget` argument was a four-hundred-digit integer, which its own
router then rejected.

Two things follow, and the second matters more than the first.

The obvious one is that a 7B cannot drive these agents. That is not a defect
here, and no amount of work in this repository fixes it.

The one worth writing down is that **the accounting caught it, and the rate
limit would have stopped it.** Nothing else on a Linux desktop would have
recorded that a trivial prompt cost two and a half million tokens; the audit log
did, per identity, without seeing a word of content. And `tokens_per_minute`,
dismissed an hour earlier in this same session as too low to be usable, is
precisely the mechanism standing between a looping agent and an unbounded
invoice — against a remote backend holding a real key, that run is a bill.

So the finding is not "the defaults are too low". It is that the defaults are
load-bearing and are currently sized so that they also forbid the first
legitimate turn. What is missing is an allowance shaped like a task rather than
a minute: an agent's *turn* is the natural unit, and a per-minute bucket cannot
tell a large first request from a runaway fourth one.

## Where the maintenance actually lives

Three layers, and they do not carry the same risk.

**Configuration is stable.** Claude Code takes `ANTHROPIC_BASE_URL` plus a
token; codex takes a `[model_providers.x]` block with `base_url` and `env_key`.
These are documented features that exist because organisations put gateways in
front of these tools, and vendors have reason to keep them. Nothing here is
under the covers.

**The wire protocol is not, and this is where the cost is.** The shim does not
pass anything through — it reimplements each vendor's API. One afternoon
produced three instances of that churn: codex dropped chat completions entirely
between releases, Claude Code sends `?beta=true` and an `anthropic-beta` header
naming four extensions, and Responses events need a `sequence_number` or
order-tracking clients reject the stream. This is the "no stable contract"
complaint the README opens with, inherited rather than solved, and the cost
scales as *(agents supported) × (how fast their APIs move)*.

The asymmetry is worth stating plainly: the native D-Bus protocol is one *we*
freeze and version, and the daemon refuses a peer outside the range. The shim
speaks protocols *they* change. No other crate here has that property.

**Model identity is the fragile part**, and the fix is small: a name map, so
nobody has to install weights under a vendor SKU.

The defence against the middle layer is not documentation. A hand-maintained
support matrix is an unverified claim that goes stale, and a stale one is worse
than none. The defence is the verification box: it already runs during the build
and already writes its transcript into the image as evidence rather than as a
promise. Pin the agent versions, add a smoke test per agent asserting one turn
completes, and silent breakage becomes a failing build. If a support matrix ever
exists it should be that run's output, not a file someone edits.

## Still open

- **`aidctl install` cannot set a model's context**, and does not read it from
  the GGUF. This is the hard blocker; everything else has a workaround that
  does not involve editing the model store by hand.
- **Rate limiting is per-minute**, which cannot distinguish a legitimate large
  first request from a loop. A per-turn or per-task allowance would.
- **No client-model to daemon-model mapping** in the shim.
- **`/v1/responses` is a subset**: text and function-call output, streaming and
  non-streaming, `instructions` / `input` / `max_output_tokens` / flat tools
  inbound. Not reasoning items, not `store` / `previous_response_id`
  continuation, not inbound images. codex needed none of them.

## Reproducing it

```
# name the agents
sudo cp /usr/share/doc/ai-daemon/shim.toml.example /etc/ai-daemon/shim.toml
sudo systemctl enable --now ai-daemon-shim

# claude-code
ANTHROPIC_BASE_URL=http://127.0.0.1:11434 \
ANTHROPIC_AUTH_TOKEN=<token> ANTHROPIC_MODEL=<installed model name> \
  claude -p "hello"

# codex — wire_api must be "responses"
AIDAEMON_KEY=<token> codex exec "hello" </dev/null

aidctl grants     # one row per agent
aidctl spend      # per identity, per day
sudo aidctl audit --verify
```

An install upgraded from before the chained audit will report one break at the
first post-upgrade record. That is the boundary, not a splice.
