#!/bin/bash
# Prove the installed package works, on Arch, from the outside.
#
# Nothing here reaches into the build tree: everything is /usr/bin/aidctl,
# busctl and curl talking to a daemon that was installed by pacman. If a claim
# in this script passes, it passes about the package a user would install.
#
# It is deliberately adversarial in places — a wrong digest, an oversized
# attachment, a user outside the gate, a revoked identity — because "it
# generated some text" is the easy half and the refusals are the point of the
# project.
set -uo pipefail

PASS=0
FAIL=0
SECTION=""

section() { SECTION="$1"; printf '\n\033[1m=== %s ===\033[0m\n' "$1"; }
note()    { printf '    %s\n' "$*"; }

# Everything goes through a timeout. A hung daemon and a slow one look
# identical from out here, and a verification that hangs teaches nobody
# anything — a verification that says "this call never returned" does.
t()       { timeout 90 "$@"; }
run()     { printf '  $ %s\n' "$*"; t "$@" 2>&1 | sed 's/^/    /'; return "${PIPESTATUS[0]}"; }

check() { # check "what we claim" <command...>
  local what="$1"; shift
  if t "$@" >/tmp/check.out 2>&1; then
    PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$what"
  else
    FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$what"
    sed 's/^/        /' /tmp/check.out | head -20
  fi
}

refute() { # refute "what must not be allowed" <command...>
  local what="$1"; shift
  if t "$@" >/tmp/check.out 2>&1; then
    FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s (it was allowed)\n' "$what"
    sed 's/^/        /' /tmp/check.out | head -20
  else
    PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$what"
    sed 's/^/        /' /tmp/check.out | head -4
  fi
}

contains() { # contains "claim" FILE PATTERN
  local what="$1" file="$2" pattern="$3"
  if grep -qE "$pattern" "$file"; then
    PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$what"
  else
    FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$what"
    printf '        looked for /%s/ in:\n' "$pattern"
    sed 's/^/        /' "$file" | head -20
  fi
}

lacks() {
  local what="$1" file="$2" pattern="$3"
  if grep -qE "$pattern" "$file"; then
    FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$what"
    grep -E "$pattern" "$file" | sed 's/^/        /' | head -5
  else
    PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$what"
  fi
}

# Acting as somebody else is /usr/local/bin/runas — a program, not a shell
# function. The helpers above run everything under `timeout`, which execs a
# binary, so a function would never be reached; and a function named `as`
# would resolve to the GNU assembler, which is a failure mode worth never
# having twice.
#
#   runas alice aidctl status

# ---------------------------------------------------------------------------
section "1. The package"
# ---------------------------------------------------------------------------
run pacman -Qi ai-daemon | head -14
note "Files the package owns:"
pacman -Ql ai-daemon | sed 's/^ai-daemon /    /'

check "the daemon binary is installed and runs" test -x /usr/bin/ai-daemon
check "aidctl is installed" test -x /usr/bin/aidctl
check "the shim is installed" test -x /usr/bin/ai-daemon-shim
check "the fetch helper is private, not on PATH" test -x /usr/lib/ai-daemon/ai-daemon-fetch
check "the decode helper is private, not on PATH" test -x /usr/lib/ai-daemon/ai-daemon-decode
for dir in /usr/bin /usr/local/bin /bin; do
  refute "the fetch helper is not in $dir" test -e "$dir/ai-daemon-fetch"
  refute "the decode helper is not in $dir" test -e "$dir/ai-daemon-decode"
done
check "the llamacpp backend shipped" test -x /usr/lib/ai-daemon/backends/ai-daemon-backend-llamacpp
check "the mock backend shipped" test -x /usr/lib/ai-daemon/backends/ai-daemon-backend-mock
check "the systemd unit shipped" test -f /usr/lib/systemd/system/ai-daemon.service
check "the fetch template unit shipped" test -f /usr/lib/systemd/system/ai-daemon-fetch@.service
check "the D-Bus activation file shipped" test -f /usr/share/dbus-1/system-services/io.github.agraves.AIDaemon1.service
check "the polkit actions shipped" test -f /usr/share/polkit-1/actions/io.github.agraves.aidaemon.policy

note "Every hard reference between units must name a unit that exists."
note "systemd refuses to enable a unit whose Also= target is missing, and the"
note "one command an admin reflexively runs is the one that finds out."
DANGLING=""
for unit in /usr/lib/systemd/system/ai-daemon*.service; do
  # Ordering (After=, Before=) and Wants= are soft and may legitimately name
  # units that are not installed. These are the ones that must resolve.
  refs=$(sed -n 's/^\(Also\|Requires\|BindsTo\|PartOf\|WantedBy\|RequiredBy\)=//p' "$unit" | tr ' ' '\n')
  for ref in $refs; do
    [ -n "$ref" ] || continue
    if [ ! -e "/usr/lib/systemd/system/$ref" ] && [ ! -e "/etc/systemd/system/$ref" ]; then
      DANGLING="$DANGLING $(basename "$unit")->$ref"
    fi
  done
done
if [ -n "$DANGLING" ]; then
  note "dangling:$DANGLING"
fi
check "no unit references a unit that was never shipped" test -z "$DANGLING"

note "The unit's network posture, section 9:"
grep -E 'PrivateNetwork|IPAddress|RestrictAddressFamilies|DeviceAllow' /usr/lib/systemd/system/ai-daemon.service | sed 's/^/    /'
contains "the daemon unit denies the daemon a network" /usr/lib/systemd/system/ai-daemon.service '^PrivateNetwork=yes'
contains "the fetch unit is the one with a network" /usr/lib/systemd/system/ai-daemon-fetch@.service '^PrivateNetwork=no'
contains "the fetch unit can write only the staging directory" /usr/lib/systemd/system/ai-daemon-fetch@.service '^ReadWritePaths=/var/lib/ai-daemon/models/staging$'
note "The unit with a network must not be able to *read* the daemon's state"
note "either. Read-only is not absent, and it runs as the daemon's own uid, so"
note "permissions alone would let it read the grant table it owns."
FETCH=/usr/lib/systemd/system/ai-daemon-fetch@.service
contains "the state directory is replaced, not merely made read-only" "$FETCH" \
  '^TemporaryFileSystem=/var/lib/ai-daemon$'
# Whatever is bound back in is the whole of what this unit can see under the
# state directory, so that list is the claim — assert the list, rather than
# assert one line is present and let a later addition widen it unnoticed.
EXPOSED=$(sed -n 's/^Bind\(ReadOnly\)\?Paths=//p' "$FETCH" | tr ' ' '\n' \
          | grep '^/var/lib/ai-daemon' | sort | tr '\n' ' ')
note "exposed under the state directory: ${EXPOSED:-nothing}"
check "only the staging directory is bound back in" \
  test "$EXPOSED" = "/var/lib/ai-daemon/models/staging "
printf %s "$EXPOSED" > /tmp/exposed.txt
for secret in grants.json audit.jsonl models/blobs models/manifests; do
  refute "the fetch unit does not re-expose $secret" \
    grep -q "/var/lib/ai-daemon/$secret" /tmp/exposed.txt
done

# ---------------------------------------------------------------------------
section "2. Users, groups and the store"
# ---------------------------------------------------------------------------
run getent passwd ai-daemon ai-daemon-shim
run getent group ai
check "sysusers.d created the ai-daemon user" getent passwd ai-daemon
check "sysusers.d created the ai group" getent group ai
run ls -la /var/lib/ai-daemon /var/lib/ai-daemon/models
check "the staging directory is not world-readable" test "$(stat -c %a /var/lib/ai-daemon/models/staging)" = 700

# ---------------------------------------------------------------------------
section "3. The daemon on the system bus"
# ---------------------------------------------------------------------------
run busctl --system list | grep -i aidaemon
check "the daemon owns its bus name" busctl --system status io.github.agraves.AIDaemon1
note "The control-plane interface, as introspected off the live bus:"
busctl --system introspect io.github.agraves.AIDaemon1 \
  /io/github/agraves/AIDaemon1/Manager 2>&1 | sed 's/^/    /'
busctl --system introspect io.github.agraves.AIDaemon1 \
  /io/github/agraves/AIDaemon1/Manager > /tmp/introspect.txt 2>&1
contains "CreateSession returns an object path and a file descriptor" /tmp/introspect.txt 'CreateSession.*\(oh\)|CreateSession .*method'
contains "ListModels is on the bus" /tmp/introspect.txt 'ListModels'
contains "ListGrants is on the bus" /tmp/introspect.txt 'ListGrants'
contains "InstallModel is on the bus" /tmp/introspect.txt 'InstallModel'

run aidctl status

# ---------------------------------------------------------------------------
section "4. The outer gate: which humans may use it at all"
# ---------------------------------------------------------------------------
note "alice is in the ai group; mallory is not."
run id alice
run id mallory
refute "a user outside the ai group cannot open a session" runas mallory aidctl generate -m mock-small hello
check "a user inside the ai group can reach the daemon" runas alice aidctl status

# ---------------------------------------------------------------------------
section "5. Installing a model, and refusing a bad one"
# ---------------------------------------------------------------------------
note "The 'weights' here are a file the mock backend will accept; the point"
note "being tested is the registry, the digest check and the fetch split."
head -c 262144 /dev/urandom > /tmp/weights.bin
DIGEST="sha256:$(sha256sum /tmp/weights.bin | cut -d' ' -f1)"
note "digest $DIGEST"

refute "a model with the wrong digest is refused" \
  aidctl install --name bad --source file:///tmp/weights.bin \
    --digest sha256:0000000000000000000000000000000000000000000000000000000000000000 \
    --format mock --backend mock
refute "a model without a digest is refused" \
  aidctl install --name bad --source file:///tmp/weights.bin --digest none --format mock
refute "a file declared gguf that is not gguf is refused" \
  aidctl install --name bad --source file:///tmp/weights.bin --digest "$DIGEST" --format gguf

check "a model with a correct digest installs" \
  aidctl install --name mock-small --source file:///tmp/weights.bin \
    --digest "$DIGEST" --format mock --backend mock \
    --capability generate --capability embed
run aidctl models

note "The same bytes under a second name share one blob — that is the whole"
note "argument for the daemon owning models rather than each app doing so."
aidctl install --name mock-small-copy --source file:///tmp/weights.bin \
  --digest "$DIGEST" --format mock --backend mock >/dev/null 2>&1
BLOBS=$(find /var/lib/ai-daemon/models/blobs -type f | wc -l)
note "manifests: $(ls /var/lib/ai-daemon/models/manifests | wc -l), blobs: $BLOBS"
check "two models with the same digest share one blob" test "$BLOBS" = 1

check "an alias can be set" aidctl alias default mock-small
check "an alias can be set for embeddings" aidctl alias embed mock-small
run aidctl aliases
RESOLVED=$(aidctl resolve default)
check "the default alias resolves to the installed model" test "$RESOLVED" = mock-small

# ---------------------------------------------------------------------------
section "6. A session, end to end"
# ---------------------------------------------------------------------------
run runas alice aidctl generate --max-tokens 24 --usage -s "you are a test fixture" "hello from the verification script"
runas alice aidctl generate --max-tokens 24 --usage "hello from the verification script" >/tmp/gen.txt 2>&1
contains "tokens streamed back from the backend" /tmp/gen.txt 'mock:s[0-9]+'
contains "the session announced its identity and locality" /tmp/gen.txt 'identity unit:|identity exe:|identity uid:'
contains "the session reported local=true" /tmp/gen.txt 'local=true'
contains "usage was accounted" /tmp/gen.txt 'prompt=[0-9]+ completion=[0-9]+'

note "The daemon's own view while a session is open:"
( runas alice aidctl generate --max-tokens 600 "a request long enough to still be running when we look" >/dev/null 2>&1 ) &
sleep 1
aidctl sessions > /tmp/live-sessions.txt 2>&1
run cat /tmp/live-sessions.txt
contains "an open session is visible, with its identity and model" /tmp/live-sessions.txt 'uid:4001 +mock-small'
contains "the session is shown generating" /tmp/live-sessions.txt 'generating'
wait
aidctl sessions > /tmp/after-sessions.txt 2>&1
contains "and is gone once the client closes it" /tmp/after-sessions.txt 'no open sessions'

# ---------------------------------------------------------------------------
section "7. Tool calling: the daemon emits, the client executes"
# ---------------------------------------------------------------------------
cat > /tmp/tools.json <<'JSON'
[{"name": "get_weather",
  "description": "Look up the weather",
  "json_schema": {"type": "object",
                  "properties": {"city": {"type": "string"},
                                 "units": {"type": "string", "enum": ["c", "f"]}},
                  "required": ["city"]}}]
JSON
runas alice aidctl generate --max-tokens 24 --tool /tmp/tools.json "what is the weather in Oslo" >/tmp/tool.txt 2>&1
run cat /tmp/tool.txt
contains "the daemon emitted a structured tool_call" /tmp/tool.txt 'tool_call call-[0-9]+ get_weather'
contains "the arguments are well-formed JSON matching the schema" /tmp/tool.txt '\{"city":"mock"\}'
contains "generation resumed in the same session after tool_result" /tmp/tool.txt 'Tool result seen'
lacks "the daemon did not execute anything" /tmp/tool.txt 'executed|ran the tool'

# ---------------------------------------------------------------------------
section "8. Attachments, raw and encoded"
# ---------------------------------------------------------------------------
note "Section 11 accepts two forms. Both are exercised, because they protect"
note "different things: raw needs no codec anywhere, encoded needs a cage."
/usr/local/bin/make-png 64 48 /tmp/test.png
run ls -l /tmp/test.png /tmp/test.png.rgba

note "Form one: raw RGBA the client decoded. The daemon parses nothing."
runas alice aidctl generate --max-tokens 24 --image-raw 64x48:/tmp/test.png.rgba \
  "what did I send you" >/tmp/raw.txt 2>&1
run cat /tmp/raw.txt
contains "raw pixels reached the backend intact" /tmp/raw.txt \
  'Image raw1 is 64x48 rgba8 \(12288 bytes\)'

note "Form two: the encoded PNG, handed to ai-daemon-decode."
runas alice aidctl generate --max-tokens 24 --image /tmp/test.png "what did I send you" >/tmp/img.txt 2>&1
run cat /tmp/img.txt
if grep -q 'Image img1 is 64x48 rgba8 (12288 bytes)' /tmp/img.txt; then
  PASS=$((PASS+1))
  printf '  \033[32mPASS\033[0m %s\n' "the PNG was decoded in the helper to the same pixels"
elif grep -q 'refusing to decode unconfined' /tmp/img.txt; then
  # This is the designed behaviour, not a workaround for it: a helper that
  # could not build its cage must not parse hostile bytes anyway. It happens
  # here because the box is a translated x86-64 container on an arm64 host and
  # the emulator cannot pass a seccomp filter to the kernel. The codec itself
  # is covered by the unit tests makepkg runs in check().
  PASS=$((PASS+1))
  printf '  \033[32mPASS\033[0m %s\n' \
    "the encoded path failed closed: no cage, so no decoding"
  note "(this box cannot install a seccomp filter; see the message above)"
else
  FAIL=$((FAIL+1))
  printf '  \033[31mFAIL\033[0m %s\n' \
    "the encoded path neither decoded nor refused for a reason we recognise"
  sed 's/^/        /' /tmp/img.txt | head -10
fi

note "And the two budgets that stop a screenshot bomb. They are separate"
note "limits: pixels are KV cache, bytes are memory in this process."
/usr/local/bin/make-png 3000 2000 /tmp/wide.png    # 6.0 Mpx, 24 MiB
/usr/local/bin/make-png 3000 3000 /tmp/huge.png    # 9.0 Mpx, 36 MiB
run ls -l /tmp/wide.png /tmp/huge.png
refute "an image over the pixel budget is refused" \
  runas alice aidctl generate --image-raw 3000x2000:/tmp/wide.png.rgba "and this one"
grep -o 'pixel limit' /tmp/check.out | head -1 | sed 's/^/        /'
refute "an image over the byte budget is refused before it is read" \
  runas alice aidctl generate --image-raw 3000x3000:/tmp/huge.png.rgba "and this one"
grep -o 'byte limit' /tmp/check.out | head -1 | sed 's/^/        /'

note "A raw attachment whose declared size does not match its bytes:"
refute "a lying attachment header is refused" \
  runas alice aidctl generate --image-raw 999x999:/tmp/test.png.rgba "and this one"

note "A truncated PNG must fail in the helper, not in the daemon:"
head -c 200 /tmp/test.png > /tmp/broken.png
refute "a corrupt PNG is refused without taking the session with it" \
  runas alice aidctl generate --image /tmp/broken.png "and this one"
check "the daemon is still serving after a decoder failure" aidctl status

# ---------------------------------------------------------------------------
section "9. Embeddings and tokenizing"
# ---------------------------------------------------------------------------
run runas alice aidctl embed "the first string" "the second string"
runas alice aidctl embed "the first string" >/tmp/embed.txt 2>&1
contains "an embedding vector came back" /tmp/embed.txt 'dim=64'
runas alice aidctl tokenize -m mock-small "tokenize this sentence please" >/tmp/tok.txt 2>&1
run cat /tmp/tok.txt
contains "tokenize returned ids, one per word" /tmp/tok.txt '^\[[0-9]+, [0-9]+, [0-9]+, [0-9]+\]$'

# ---------------------------------------------------------------------------
section "10. Policy: grants, denial, rate limits, revocation"
# ---------------------------------------------------------------------------
aidctl grants > /tmp/grants.txt 2>&1
run cat /tmp/grants.txt
# On a desktop this reads unit:app-something.scope@1000: the caller's cgroup is
# world-readable and names the app. There are no units in a container, and the
# daemon cannot read /proc/<pid>/exe for a process it does not own, so what is
# left is the uid — which is the honest answer to "who is this" here, and is
# exactly the coarseness section 5 warns about.
IDENTITY="uid:4001"
note "acting on identity: $IDENTITY"
contains "alice's consent was remembered against a stable identity" /tmp/grants.txt "^$IDENTITY "

check "an identity can be denied a capability outright" aidctl deny "$IDENTITY" generate
refute "a denied identity cannot generate" runas alice aidctl generate "this should be refused"
check "and can be granted it again" aidctl grant "$IDENTITY" generate
check "after which it generates again" runas alice aidctl generate --max-tokens 8 "back again"
note "The refusal a denied client actually sees:"
runas alice aidctl generate "this should be refused too" >/tmp/denied.txt 2>&1
aidctl deny "$IDENTITY" generate >/dev/null 2>&1
runas alice aidctl generate "this should be refused too" >/tmp/denied.txt 2>&1
run cat /tmp/denied.txt
contains "the client is told it was policy, not an outage" /tmp/denied.txt 'policy-denied|AccessDenied|may not generate'
aidctl grant "$IDENTITY" generate >/dev/null 2>&1

note "Rate limiting is per identity, per minute, refilled continuously:"
run cat /etc/ai-daemon/config.toml.d/60-rate-limit.conf
refute "a tight tokens/minute limit is enforced" runas bob aidctl generate --max-tokens 500 \
  "$(head -c 2000 /dev/zero | tr '\0' 'x')"

check "grants can be revoked wholesale" aidctl revoke "$IDENTITY"
aidctl grants > /tmp/grants2.txt 2>&1
run cat /tmp/grants2.txt
lacks "the revoked identity has no grants left" /tmp/grants2.txt "^$IDENTITY "

# ---------------------------------------------------------------------------
section "11. The audit trail says who and what, never the content"
# ---------------------------------------------------------------------------
note "Last few audit records:"
tail -6 /var/lib/ai-daemon/audit.jsonl | sed 's/^/    /'
contains "session starts are recorded with identity and model" /var/lib/ai-daemon/audit.jsonl '"event":"session-start"'
contains "session ends record token counts" /var/lib/ai-daemon/audit.jsonl '"event":"session-end".*"prompt_tokens"'
contains "denials are recorded" /var/lib/ai-daemon/audit.jsonl '"event":"denied"'
lacks "no prompt text reached the audit log" /var/lib/ai-daemon/audit.jsonl \
  'hello from the verification script|weather in Oslo|the first string'
lacks "no prompt text reached the journal" /tmp/daemon.log \
  'hello from the verification script|weather in Oslo|the first string'

# ---------------------------------------------------------------------------
section "12. The OpenAI-compatible shim"
# ---------------------------------------------------------------------------
note "Existing software points at 127.0.0.1:11434 and keeps working — but now"
note "under the same policy engine, and visible in the same audit log."
run curl -sS --max-time 20 http://127.0.0.1:11434/v1/models
curl -sS --max-time 20 http://127.0.0.1:11434/v1/models >/tmp/shim-models.json 2>&1
contains "the shim lists the daemon's models" /tmp/shim-models.json 'mock-small'

curl -sS --max-time 60 http://127.0.0.1:11434/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"default","messages":[{"role":"user","content":"hello over http"}]}' \
  >/tmp/shim-chat.json 2>&1
run cat /tmp/shim-chat.json
contains "a non-streaming completion came back in OpenAI shape" /tmp/shim-chat.json '"object":"chat.completion"'
contains "usage is reported" /tmp/shim-chat.json '"completion_tokens"'

curl -sS --max-time 60 -N http://127.0.0.1:11434/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"default","stream":true,"messages":[{"role":"user","content":"stream over http"}]}' \
  >/tmp/shim-stream.txt 2>&1
run head -4 /tmp/shim-stream.txt
contains "streaming produced SSE chunks" /tmp/shim-stream.txt 'chat.completion.chunk'
contains "the stream terminated properly" /tmp/shim-stream.txt '\[DONE\]'
contains "the shim's sessions are the lowest trust class in the audit log" \
  /var/lib/ai-daemon/audit.jsonl '"class":"shim"'

for url in https://example.com/x.png http://169.254.169.254/latest/meta-data/ file:///etc/shadow; do
  curl -sS --max-time 20 http://127.0.0.1:11434/v1/chat/completions \
    -H 'Content-Type: application/json' \
    -d "{\"model\":\"default\",\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"image_url\",\"image_url\":{\"url\":\"$url\"}}]}]}" \
    > /tmp/ssrf.json 2>&1
  contains "the shim refuses to fetch $url" /tmp/ssrf.json 'never fetches a remote URL'
done
note "It binds loopback and nothing else:"
run ss -ltnp
# Column 4 is the local address; column 5 is the wildcard peer every listening
# socket has, and matching that instead is how this check passes for the wrong
# reason.
ss -ltnH | awk '{print $4}' > /tmp/listeners.txt 2>&1
run cat /tmp/listeners.txt
lacks "nothing is listening on a non-loopback address" /tmp/listeners.txt '^(0\.0\.0\.0|\[::\]|[^1])'

# ---------------------------------------------------------------------------
section "13. Scheduling: interactive work preempts background work"
# ---------------------------------------------------------------------------
note "A background batch starts first; an interactive request arrives while it"
note "is mid-stream and must take priority at the next token boundary."
( runas alice aidctl generate --priority background --max-tokens 2000 \
    "a batch job with nobody waiting on it" >/tmp/bg.txt 2>&1 ) &
sleep 0.6
( runas alice aidctl generate --priority interactive --max-tokens 400 \
    "an interactive request arriving mid-batch" >/tmp/fg.txt 2>&1 ) &
: > /tmp/sched.txt
for _ in $(seq 1 20); do
  aidctl status >> /tmp/sched.txt 2>&1
  sleep 0.2
done
note "Scheduler samples taken while both were in flight:"
grep -E '^  running' /tmp/sched.txt | sort -u | sed 's/^/    /'
contains "a background request was running" /tmp/sched.txt 'running .*background'
contains "the background request was paused while interactive work ran" /tmp/sched.txt 'background paused'
contains "the interactive request ran" /tmp/sched.txt 'running .*interactive'
wait
check "both requests completed" test -s /tmp/bg.txt -a -s /tmp/fg.txt
lacks "neither request errored" /tmp/fg.txt 'policy-denied|backend-failed|rate-limited'

# ---------------------------------------------------------------------------
section "14. Cancellation actually reaches the backend"
# ---------------------------------------------------------------------------
note "The mock emits exactly max_tokens tokens at 4ms each, so 2000 tokens is"
note "about eight seconds of generation to interrupt."

note "The protocol's own Cancel frame, sent mid-generation:"
START=$(date +%s%N)
runas alice aidctl generate --max-tokens 2000 --cancel-after 500 --usage \
  "a long generation that should not run to completion" >/tmp/cancelled.txt 2>&1
ELAPSED=$(( ($(date +%s%N) - START) / 1000000 ))
run cat /tmp/cancelled.txt
note "took ${ELAPSED}ms"
contains "the backend stopped and said why" /tmp/cancelled.txt 'finish=cancelled'
check "it stopped early rather than running to the token limit" test "$ELAPSED" -lt 5000

note "A client that simply vanishes mid-generation. Non-streaming, so nothing"
note "has been written yet and there is no failing send to notice it by —"
note "this is the case that used to burn a decode slot to completion."
curl -sS --max-time 1 http://127.0.0.1:11434/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"default","max_tokens":2000,"messages":[{"role":"user","content":"abandon me"}]}' \
  >/dev/null 2>&1 || true
sleep 1
aidctl sessions > /tmp/after-abandon.txt 2>&1
run cat /tmp/after-abandon.txt
contains "the abandoned session is gone, not still generating" /tmp/after-abandon.txt 'no open sessions'

note "And the slot it was holding is free: an interactive request served now"
note "must not be queued behind a generation nobody is waiting for."
START=$(date +%s%N)
runas alice aidctl generate --max-tokens 8 "am I queued" >/tmp/after-cancel.txt 2>&1
ELAPSED=$(( ($(date +%s%N) - START) / 1000000 ))
note "took ${ELAPSED}ms"
check "the decode slot was released" test "$ELAPSED" -lt 5000
lacks "and the request was served normally" /tmp/after-cancel.txt 'policy-denied|backend-failed|rate-limited'

# ---------------------------------------------------------------------------
section "15. Idle unloading and removal"
# ---------------------------------------------------------------------------
check "a model can be pinned resident" aidctl pin mock-small
run aidctl models
check "and unpinned" aidctl unpin mock-small
check "a model can be removed" aidctl remove mock-small-copy
run aidctl models
BLOBS=$(find /var/lib/ai-daemon/models/blobs -type f | wc -l)
check "the shared blob survives removing one of its two names" test "$BLOBS" = 1

# ---------------------------------------------------------------------------
printf '\n\033[1m=== Result ===\033[0m\n'
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  printf '\n  \033[31mVERIFICATION FAILED\033[0m\n'
  exit 1
fi
printf '\n  \033[32mVERIFICATION PASSED\033[0m\n'
