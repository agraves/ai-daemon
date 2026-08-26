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
# User units too, against the *user* search path: a user unit referring to a
# system target resolves no better than a reference to nothing, and the portal
# is a user unit.
for unit in /usr/lib/systemd/system/ai-daemon*.service /usr/lib/systemd/user/ai-daemon*.service; do
  [ -e "$unit" ] || continue
  case "$unit" in
    */user/*) SEARCH="/usr/lib/systemd/user /etc/systemd/user" ;;
    *)        SEARCH="/usr/lib/systemd/system /etc/systemd/system" ;;
  esac
  # Ordering (After=, Before=) and Wants= are soft and may legitimately name
  # units that are not installed. These are the ones that must resolve.
  refs=$(sed -n 's/^\(Also\|Requires\|BindsTo\|PartOf\|WantedBy\|RequiredBy\)=//p' "$unit" | tr ' ' '\n')
  for ref in $refs; do
    [ -n "$ref" ] || continue
    FOUND=""
    for dir in $SEARCH; do
      [ -e "$dir/$ref" ] && FOUND=yes
    done
    if [ -z "$FOUND" ]; then
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
contains "the fetch unit is one of the two with a network" /usr/lib/systemd/system/ai-daemon-fetch@.service '^PrivateNetwork=no'
note "The other is the remote provider, and it is the only other one. A count"
note "rather than a spot check: the claim is about the whole set of units."
NETWORKED=$(grep -l '^PrivateNetwork=no' /usr/lib/systemd/system/ai-daemon*.service /usr/lib/systemd/user/ai-daemon*.service 2>/dev/null | xargs -r -n1 basename | sort | tr '\n' ' ')
note "units with a network: ${NETWORKED:-none}"
check "exactly the fetch helper and the remote provider have a network" \
  test "$NETWORKED" = "ai-daemon-backend-remote.service ai-daemon-fetch@.service "
contains "and the remote provider cannot read the daemon's state either" \
  /usr/lib/systemd/system/ai-daemon-backend-remote.service '^TemporaryFileSystem=/var/lib/ai-daemon$'
refute "with nothing bound back in for it" \
  grep -qE '^Bind(ReadOnly)?Paths=.*/var/lib/ai-daemon' /usr/lib/systemd/system/ai-daemon-backend-remote.service
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

# Everything this fixture is asked for below, named. It used to say only
# generate and embed and was nonetheless handed screenshots and asked for
# pictures, because the manifest was decoration — six checks in this file
# broke the moment section 19's enforcement went in, which is the blast
# radius of that change measured rather than estimated.
check "a model with a correct digest installs" \
  aidctl install --name mock-small --source file:///tmp/weights.bin \
    --digest "$DIGEST" --format mock --backend mock \
    --capability generate --capability embed \
    --capability vision --capability audio-in \
    --capability image-out --capability audio-out
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
contains "the daemon emitted a structured tool_call" /tmp/tool.txt 'tool_call call-[0-9-]+ get_weather'
contains "the arguments are well-formed JSON matching the schema" /tmp/tool.txt '\{"city":"mock"\}'
contains "generation resumed in the same session after tool_result" /tmp/tool.txt 'Tool result seen'
lacks "the daemon did not execute anything" /tmp/tool.txt 'executed|ran the tool'
note "Parallel tool calls (protocol v2): two tools offered, both called at"
note "once, both answered in one batch, and the turn resumes only after the"
note "last of them comes back."
cat > /tmp/tools2.json <<'JSON'
[{"name": "get_weather",
  "description": "Look up the weather",
  "json_schema": {"type": "object",
                  "properties": {"city": {"type": "string"}},
                  "required": ["city"]}},
 {"name": "get_time",
  "description": "Look up the time",
  "json_schema": {"type": "object",
                  "properties": {"zone": {"type": "string"}},
                  "required": ["zone"]}}]
JSON
runas alice aidctl generate --max-tokens 24 --tool /tmp/tools2.json \
  "weather and time please" >/tmp/partool.txt 2>&1
run cat /tmp/partool.txt
contains "both calls arrived in one batch" /tmp/partool.txt '^\[tool_calls 2\]'
contains "the first is there" /tmp/partool.txt 'get_weather\(\{"city":"mock"\}\)'
contains "the second is too" /tmp/partool.txt 'get_time\(\{"zone":"mock"\}\)'
contains "and the turn resumed after both were answered" /tmp/partool.txt 'Tool result seen'

note "Fine-grained logit control: alternatives per token, on request."
runas alice aidctl generate --max-tokens 6 --logprobs 3 "alternatives please" \
  >/tmp/logprobs.txt 2>&1
run cat /tmp/logprobs.txt
contains "alternatives came back with the tokens" /tmp/logprobs.txt '\[[^]]*alt1=-1\.10[^]]*\]'
runas alice aidctl generate --max-tokens 6 "no alternatives please" >/tmp/nologprobs.txt 2>&1
lacks "and not when they were not asked for" /tmp/nologprobs.txt 'alt1='

note "Media output (§11's deferred half). Its own capability, so it can be"
note "withheld separately from text."
cd /tmp
runas alice aidctl generate-media --image --count 2 "a test pattern" >/tmp/media.txt 2>&1
run cat /tmp/media.txt
contains "an image came back with its dimensions" /tmp/media.txt 'image 32x24 rgba8'
contains "and the second one too" /tmp/media.txt '\-2\.rgba'
contains "the bytes were accounted" /tmp/media.txt 'media_bytes=[1-9][0-9]+'
runas alice aidctl generate-media --audio "a test tone" >/tmp/audio.txt 2>&1
run cat /tmp/audio.txt
contains "audio came back at its sample rate" /tmp/audio.txt 'audio 4000 samples at 16000 Hz'
cd - >/dev/null

note "The capability is separate, so denying it leaves text working:"
check "media can be denied on its own" aidctl deny uid:4001 generate-media
refute "and then media is refused" runas alice aidctl generate-media --image "denied"
check "while plain generation still works" runas alice aidctl generate --max-tokens 8 "still here"
check "and it can be granted back" aidctl grant uid:4001 generate-media

note "A v1 client is served, and is sent nothing v2 added: the same two tools"
note "produce one call, not a batch it could not answer."
runas alice aidctl generate --proto 1 --max-tokens 24 --tool /tmp/tools2.json \
  "weather and time please" >/tmp/v1tool.txt 2>&1
run cat /tmp/v1tool.txt
contains "a v1 client still gets a single tool_call" /tmp/v1tool.txt '^\[tool_call '
lacks "and never the batch form" /tmp/v1tool.txt 'tool_calls'
refute "media output is refused to a v1 client" \
  runas alice aidctl generate-media --proto 1 --image "too old"

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
section "16. A provider that is not on this machine"
# ---------------------------------------------------------------------------
note "The daemon has PrivateNetwork=yes, so a backend it forks has no route"
note "anywhere. A remote provider therefore runs as its own unit with its own"
note "network, and the daemon connects to it. That is the thing being tested:"
note "the transport, the labelling, and that nothing about it is on by default."

check "the remote backend shipped" test -x /usr/lib/ai-daemon/backends/ai-daemon-backend-remote
check "its unit shipped" test -f /usr/lib/systemd/system/ai-daemon-backend-remote.service
check "sysusers.d created its own separate user" getent passwd ai-daemon-remote
note "Separate uid because it is the one process here with a network: the"
note "daemon's files must not be readable by it."
check "it is not the daemon's user" \
  test "$(id -u ai-daemon-remote)" != "$(id -u ai-daemon)"

note "Nothing the package installs turns it on. Its unit will not even start:"
run grep -n 'ConditionPathExists' /usr/lib/systemd/system/ai-daemon-backend-remote.service
lacks "the shipped config names no endpoint" /etc/ai-daemon/config.toml 'connect *='
check "and the file its unit is conditional on is not packaged" \
  test -z "$(pacman -Qlq ai-daemon | grep -x '/etc/ai-daemon/remote.toml')"
# Asked of the package rather than of the filesystem, deliberately: the
# archlinux container image sets NoExtract for usr/share/doc, so a file that
# ships correctly is absent here. What is being claimed is that the package
# carries it, and the package's own file list is where that is true or false.
check "the example ships as documentation, not as configuration" \
  bash -c "pacman -Qlq ai-daemon | grep -qx /usr/share/doc/ai-daemon/remote.toml.example"

note "The socket the daemon dials. Its ownership is the whole access control:"
note "an API key anyone could spend is an API key anyone will."
run ls -ld /run/ai-daemon-remote /run/ai-daemon-remote/remote.sock
check "the socket is group-readable and not world-readable" \
  test "$(stat -c %a /run/ai-daemon-remote/remote.sock)" = 660
check "and shared with the daemon's group, not with everyone" \
  test "$(stat -c %G /run/ai-daemon-remote/remote.sock)" = ai-daemon
check "it is not in the daemon's own runtime directory" \
  test ! -e /run/ai-daemon/remote.sock
note "Because that one holds the live session sockets, and a uid that can"
note "create files there can unlink them."
refute "a user outside the group cannot reach the remote backend" \
  runas mallory test -r /run/ai-daemon-remote/remote.sock

note "Registering a model that has no weights on this machine. Nothing is"
note "downloaded, so there is nothing to hash and no digest is asked for."
check "a remote model registers" \
  aidctl install --name cloud-small --source remote:stub-model-1 --backend remote \
  --capability generate --capability embed
refute "and offering a digest for it is refused, not ignored" \
  aidctl install --name cloud-2 --source remote:stub-model-1 --digest "sha256:$(printf 0%.0s $(seq 64))"
note "A digest on a remote install would look like verification that is not"
note "happening."
refute "a remote model naming a backend that is not a remote provider is refused" \
  aidctl install --name cloud-3 --source remote:stub-model-1 --backend mock

aidctl models > /tmp/models-remote.txt 2>&1
run cat /tmp/models-remote.txt
contains "it is listed with format remote" /tmp/models-remote.txt 'cloud-small +remote'
contains "and marked as not local where a person will see it" /tmp/models-remote.txt 'not local'
contains "its identifier says what it is instead of pretending to be a hash" \
  /tmp/models-remote.txt 'remote:stub-model-1'
note "Section 15 left exactly one blob in the store. A model with no weights"
note "must not have added another."
check "no blob was created for a model that has none" \
  test "$(find /var/lib/ai-daemon/models/blobs -type f | wc -l)" = 1

note "Generating through it. The bytes leave this process, cross a socket to a"
note "unit with a network, and come back."
runas alice aidctl generate --model cloud-small --max-tokens 8 --usage \
  "hello from the other side" > /tmp/remote-gen.txt 2>&1
run cat /tmp/remote-gen.txt
contains "a remote model generates" /tmp/remote-gen.txt 'remote-0'
contains "and the prompt reached the far end, which counted it" \
  /tmp/remote-gen.txt 'prompt=11'

note "The label. This is the part that matters: a user must be able to find"
note "out that a prompt left the machine, and not by reading a config file."
runas alice aidctl generate --model cloud-small --max-tokens 4 \
  "am I local" > /tmp/remote-info.txt 2>&1
run cat /tmp/remote-info.txt
contains "the session itself says it is not local" /tmp/remote-info.txt 'local=false'
runas alice aidctl generate --max-tokens 4 "and now" > /tmp/local-info.txt 2>&1
contains "while a session on a local model says it is" /tmp/local-info.txt 'local=true'
note "Negative side included deliberately: a property that reads false for"
note "everything is not evidence of anything."

note "And so does the audit log, which is where somebody looks afterwards."
tail -12 /var/lib/ai-daemon/audit.jsonl | sed 's/^/    /'
contains "the audit record for a remote session says it was not local" \
  /var/lib/ai-daemon/audit.jsonl '"model":"cloud-small"[^}]*"local":false|"local":false[^}]*"model":"cloud-small"'

note "Tools over the remote transport, and the parallel batch from §12 with"
note "them: two calls in one turn, from a service, through the daemon."
# /tmp/tools2.json is the two-tool schema section 7 built.
runas alice aidctl generate --model cloud-small --max-tokens 32 \
  --tool /tmp/tools2.json "call the tools" > /tmp/remote-tools.txt 2>&1
run cat /tmp/remote-tools.txt
contains "both calls arrived from the remote endpoint" /tmp/remote-tools.txt 'tool_calls 2'
contains "the first one" /tmp/remote-tools.txt 'get_weather'
contains "the second one" /tmp/remote-tools.txt 'get_time'

note "Logprobs, from an endpoint rather than from a local model."
runas alice aidctl generate --model cloud-small --max-tokens 4 --logprobs 2 \
  "alternatives please" > /tmp/remote-logprobs.txt 2>&1
run cat /tmp/remote-logprobs.txt
contains "alternatives came back over HTTP" /tmp/remote-logprobs.txt '=-0\.25'

note "Embeddings."
runas alice aidctl embed --model cloud-small "some text" > /tmp/remote-embed.txt 2>&1
run cat /tmp/remote-embed.txt
contains "a vector came back from the endpoint" /tmp/remote-embed.txt '0\.25'

note "Cancellation. A remote endpoint can be silent for a long time and the"
note "meter usually keeps running while it is, so a cancel has to reach the"
note "transport rather than wait for the next token. The stand-in sends for a"
note "minute if nobody stops it."
START=$(date +%s%N)
runas alice aidctl generate --model cloud-small --max-tokens 2000 --cancel-after 500 --usage \
  "keep going" > /tmp/remote-cancel.txt 2>&1
ELAPSED=$(( ($(date +%s%N) - START) / 1000000 ))
run cat /tmp/remote-cancel.txt
note "took ${ELAPSED}ms of a possible 60000"
# Ordered so a request that was refused outright cannot pass as a fast
# cancellation: it has to have generated, and then stopped because we said so.
contains "the request really ran and then stopped on the cancel" \
  /tmp/remote-cancel.txt 'finish=cancelled'
contains "with tokens already received from the endpoint" /tmp/remote-cancel.txt 'remote-0'
check "the transfer was torn down rather than run out" test "$ELAPSED" -lt 5000
# The far end is mid-sleep between tokens when the transfer dies, so it learns
# about it on its next write rather than immediately.
sleep 1
contains "and the far end noticed, so it was the transfer that ended" \
  /tmp/stub-endpoint.log 'peer went away'

note "What it refuses. It has no weights, no tokeniser and no image model, and"
note "says so by name rather than failing somewhere confusing."
refute "it cannot tokenize, because the model is not here" \
  runas alice aidctl tokenize --model cloud-small "count these"
refute "and it does not generate images" \
  runas alice aidctl generate-media --model cloud-small --image "a cat"

note "Plaintext. The backend refuses http:// unless it is told to allow it, so"
note "a typo in base_url cannot quietly put prompts on the wire in clear. A"
note "second provider is running against the same http endpoint with the"
note "setting left at its default, and its whole job is to be refused."
check "a model on the strict provider registers fine" \
  aidctl install --name cloud-strict --source remote:stub-model-1 --backend remote-strict
refute "but generating through it will not send a prompt over http" \
  runas alice aidctl generate --model cloud-strict --max-tokens 4 "should not leave"
contains "and it announced the allowance on the one that has it" \
  /tmp/remote-backend.log 'may travel to http://127.0.0.1:8099/v1 unencrypted'
lacks "while the strict one announced nothing of the kind" /tmp/remote-strict.log 'may travel'
note "Same binary, same endpoint, same prompt: the only difference is one line"
note "of configuration, which is what makes this a test of that line."

note "And the config the daemon itself refuses: a backend that is both, or"
note "neither, or one that sets an environment for a process it does not start."
for BAD in 'name = "x"' 'name = "x"
exec = "/bin/true"
connect = "/tmp/s"' 'name = "x"
connect = "/tmp/s"
env = { CUDA_VISIBLE_DEVICES = "1" }'; do
  printf '[[backend]]\n%s\n' "$BAD" > /etc/ai-daemon/config.toml.d/82-bad.conf
  refute "a contradictory backend spec is refused: $(printf '%s' "$BAD" | tr '\n' ' ')" \
    /usr/bin/ai-daemon --check-config
  rm -f /etc/ai-daemon/config.toml.d/82-bad.conf
done

# ---------------------------------------------------------------------------
section "17. The portal: the one app identity an app cannot choose"
# ---------------------------------------------------------------------------
note "Peer credentials give the daemon a uid and a cgroup. That tells it which"
note "*person* is calling and usually which unit, and the daemon calls that"
note "class 'native' because a process in the same session can arrange to look"
note "like another one. A sandboxed app is different: its confinement wrote"
note "down what it is, in a file the app did not write and cannot reach out of."
note "Reading that from outside, for a pid the bus vouched for, is the only"
note "strong application identity Linux offers — and it can only be read by"
note "something running as the user, which the daemon is not."

check "the portal shipped" test -x /usr/lib/ai-daemon/ai-daemon-portal
check "as a user unit, not a system one" test -f /usr/lib/systemd/user/ai-daemon-portal.service
check "with session-bus activation" \
  test -f /usr/share/dbus-1/services/io.github.agraves.AIPortal1.service
check "it is not on PATH: apps reach it over the bus, people do not run it" \
  test ! -e /usr/bin/ai-daemon-portal
note "It serves the interface proposed in §13, under its own name until"
note "org.freedesktop.portal.AI is accepted upstream. Squatting on the desktop"
note "portal's name would be worse than an interim one:"
run grep -h '^Name=' /usr/share/dbus-1/services/io.github.agraves.AIPortal1.service
check "the proposal it implements ships alongside it" \
  bash -c "pacman -Qlq ai-daemon | grep -qx /usr/share/doc/ai-daemon/org.freedesktop.portal.AI.xml"

run cat /tmp/portal.log
contains "the portal took its name on alice's session bus" /tmp/portal.log \
  'io\.github\.agraves\.AIPortal1 at /io/github/agraves/AIPortal1'

note "First, the refusal. alice's shell is not in a sandbox, so there is no"
note "strong identity to carry and the portal will not invent one."
refute "an unsandboxed caller is refused rather than given the portal's own id" \
  env DBUS_SESSION_BUS_ADDRESS="$ALICE_BUS" runas alice aidctl portal
note "That matters more than it looks: passing an unidentifiable caller through"
note "would label every unsandboxed app on the machine as the portal itself,"
note "and they would all silently share one grant."

note "Now a caller with a sandbox. Flatpak writes .flatpak-info into the"
note "sandbox root, so /proc/<pid>/root/.flatpak-info reads it from outside."
note "There is no mount namespace here, so the file goes at the real root and"
note "every process looks confined — enough to prove the read path and the"
note "parse, not enough to prove the isolation, which is flatpak's to provide."
note "Which section of that file counts, and which labels are refused, is"
note "covered by unit tests in the portal itself."
cat > /.flatpak-info <<'INFO'
[Instance]
name=decoy.not.the.app
[Application]
name=org.example.Notes
runtime=org.freedesktop.Platform
INFO
env DBUS_SESSION_BUS_ADDRESS="$ALICE_BUS" runas alice aidctl portal >/tmp/portal-id.txt 2>&1
run cat /tmp/portal-id.txt
contains "the portal reports the application id" /tmp/portal-id.txt 'org\.example\.Notes'
contains "and says which sandbox said so" /tmp/portal-id.txt 'flatpak'
lacks "the decoy in another section was not taken" /tmp/portal-id.txt 'decoy'

note "End to end: a session opened through the portal, on the app's behalf."
env DBUS_SESSION_BUS_ADDRESS="$ALICE_BUS" runas alice \
  aidctl generate --via-portal --max-tokens 8 "who am I" >/tmp/portal-gen.txt 2>&1
run cat /tmp/portal-gen.txt

if [ "$(cat /tmp/portal-cgroup)" = yes ]; then
  contains "a session opened through the portal generates" /tmp/portal-gen.txt \
    'identity portal:org\.example\.Notes'
  lacks "and it did not fall back to a uid" /tmp/portal-gen.txt 'identity uid:'
  note "The daemon recorded it as the strong class, not as a guess:"
  tail -4 /var/lib/ai-daemon/audit.jsonl | sed 's/^/    /'
  contains "the audit log carries the application id" /var/lib/ai-daemon/audit.jsonl \
    '"identity":"portal:org\.example\.Notes"'
  contains "in the portal trust class" /var/lib/ai-daemon/audit.jsonl '"class":"portal"'
  note "And the grant is keyed on the app, so it survives a relaunch — which is"
  note "the practical point of all this. A key that changes every launch turns"
  note "a consent dialog into something people click through."
  run aidctl grants
  check "the grant is keyed on the application id" \
    bash -c "aidctl grants | grep -q 'portal:org.example.Notes'"
else
  note "STOPS HERE, and the reason is the container rather than the code."
  note ""
  note "The daemon identifies a portal by the caller's systemd unit, read from"
  note "/proc/<pid>/cgroup — world-readable, and not something a process can"
  note "choose for itself, which is exactly why it is what gets checked. This"
  note "container has no systemd and a read-only cgroupfs:"
  sed 's/^/    /' /tmp/portal-cgroup.err
  note "so nothing can be put in a cgroup named after a unit, and the daemon"
  note "sees a caller with no unit at all. The other two ways it could have"
  note "recognised the portal are closed for good reasons: /proc/<pid>/exe is"
  note "unreadable across uids and the portal must run as the user, and a uid"
  note "check cannot work for the same reason. The same limitation as seccomp"
  note "in section 8 — environmental, named, and not routed around."
  note ""
  note "What is proven above: the portal reads a real sandbox correctly,"
  note "refuses what it cannot vouch for, and refuses a caller-chosen id."
  note "What is proven below: the daemon refuses an unrecognised introducer."
  note "What the daemon *accepts* is covered by unit tests over the same"
  note "function the D-Bus path calls (dbusapi::tests::introducers)."
  contains "the daemon refused, because it could not see a unit to trust" \
    /tmp/portal-gen.txt 'only xdg-desktop-portal may assert an application identity'
  contains "and said so in its log, naming the id it would not take" /tmp/daemon.log \
    'asserted portal_app_id=org\.example\.Notes without being a portal'
fi

note "What stops an app asserting its own identity. Two separate refusals,"
note "because either one alone would be a bypass."
note "One: the portal will not let a caller choose the id it forwards."
refute "an app that sets portal_app_id itself is refused by the portal" \
  runas alice busctl --address="$ALICE_BUS" call \
  io.github.agraves.AIPortal1 /io/github/agraves/AIPortal1 \
  org.freedesktop.portal.AI CreateSession 'sa{sv}' default 1 portal_app_id s org.evil.App
note "Two: the daemon will not take the claim from a caller that is not on its"
note "list of introducers, whatever the claim says."
refute "and asserting it straight to the daemon is refused there too" \
  runas alice busctl --system call io.github.agraves.AIDaemon1 \
  /io/github/agraves/AIDaemon1/Manager io.github.agraves.AIDaemon1.Manager \
  CreateSession 'sa{sv}' default 1 portal_app_id s org.evil.App
contains "the daemon logged the attempt rather than only refusing it" /tmp/daemon.log \
  'asserted portal_app_id=org.evil.App without being a portal'
check "the list of who may introduce an app is configuration, not a constant" \
  grep -q '^portal_units' /etc/ai-daemon/config.toml

rm -f /.flatpak-info

# ---------------------------------------------------------------------------
section "18. Being preempted is not the same as being dead"
# ---------------------------------------------------------------------------
note "The daemon gives up on a backend that says nothing for a long time,"
note "because a backend can stop answering without closing its socket and the"
note "session would otherwise wait for ever holding a decode slot. But §8's"
note "preemption makes the daemon itself silence background work: every"
note "background request is paused whenever an interactive one is running, and"
note "a paused backend emits nothing — that is what pausing is."
note ""
note "So the two look identical from the waiting end, and the question is"
note "whether the daemon can tell them apart. This box's silence window is"
note "eight seconds; the interactive request below runs for about twelve."

SILENCE=$(sed -n 's/^backend_silence_seconds = //p' /etc/ai-daemon/config.toml.d/70-container.conf)
note "configured silence window: ${SILENCE}s"
check "the window is short enough for this test to reach it" test "$SILENCE" -lt 10

# Both counts sit inside the session's 4096-token context; an earlier draft
# asked for 8000 and was refused before any of this was exercised.
runas alice aidctl generate --priority background --max-tokens 1500 --usage \
  "a batch job that will be held still" >/tmp/preempted.txt 2>&1 &
BG=$!
# Let it be admitted, attached and actually generating before the interactive
# request arrives — a request that has not started yet is not a preempted one.
sleep 1
START=$(date +%s%N)
runas alice aidctl generate --max-tokens 3000 --usage \
  "one long interactive turn, held down the whole time" >/tmp/holder.txt 2>&1
HELD=$(( ($(date +%s%N) - START) / 1000000 ))
wait $BG
note "the interactive request ran for ${HELD}ms, and the background one was"
note "paused for all of it"
check "the interactive request really did outlast the silence window" \
  test "$HELD" -gt $(( SILENCE * 1000 ))

run cat /tmp/preempted.txt
# Every token it asked for, which is what the mock's finish=length means —
# a stronger claim than "it ended somehow": nothing was lost to the pause.
contains "the preempted request produced all 1500 of its tokens" /tmp/preempted.txt \
  'completion=1500 attachment=0 finish=length'
lacks "and was not killed as a silent backend" /tmp/preempted.txt 'went silent'
lacks "nor reported as any other backend failure" /tmp/preempted.txt 'backend-failed'
note "Without the paused clock this fails as backend-failed at eight seconds, on"
note "a request the daemon itself had silenced, throwing away the tokens"
note "already generated — on exactly the workload preemption exists to protect."
contains "and the interactive request it was yielding to produced all of its" \
  /tmp/holder.txt 'completion=3000 attachment=0 finish=length'

note "The window still fires for a backend that is genuinely quiet while free"
note "to speak, which is the whole reason it exists — covered by unit tests"
note "over wait_for_event, where a fake clock beats a twenty-second wait."

# ---------------------------------------------------------------------------
section "19. A model's capabilities are what it can be asked for"
# ---------------------------------------------------------------------------
note "manifest.capabilities was written at install, shown in ListModels,"
note "documented as intersected with the backend's own claims — and consulted"
note "nowhere. The mock backend embeds, so every model installed against it"
note "embedded, whatever its manifest said. Both halves of that documented"
note "promise are enforced now, and both are refusals rather than warnings."

note "Half one: a model cannot grant what the backend cannot do. Refused at"
note "install, where the person who typed it is still watching."
refute "a capability no configured backend serves is refused at install" \
  aidctl install --name impossible --source file:///tmp/weights.bin \
  --digest "$DIGEST" --format mock --backend mock \
  --capability generate --capability video-in
run cat /tmp/check.out
check "and nothing was installed under that name" \
  bash -c "! aidctl models | grep -q '^impossible '"
note "Refused rather than silently narrowed: an administrator who asked for a"
note "capability and got a model without it would have no way to tell."

note "Half two: a backend cannot grant what the model is not. The mock embeds;"
note "this model does not claim to."
check "a generate-only model installs" \
  aidctl install --name text-only --source file:///tmp/weights.bin \
  --digest "$DIGEST" --format mock --backend mock --capability generate
check "and it generates" runas alice aidctl generate --model text-only --max-tokens 8 "hello"
runas alice aidctl embed --model text-only "embed me" >/tmp/cap-embed.txt 2>&1
run cat /tmp/cap-embed.txt
refute "but embedding it is refused, though the backend would oblige" \
  runas alice aidctl embed --model text-only "embed me"
contains "the refusal names the model, not the machine" /tmp/cap-embed.txt 'model text-only does not offer embed'
contains "and says what it does offer" /tmp/cap-embed.txt 'it offers: generate'
contains "and carries the remedy, which is not guessable" /tmp/cap-embed.txt 'aidctl install --capability embed'
note "Without the remedy a client reads 'cannot embed' and concludes the"
note "machine cannot, when the fix is one administrator command."

note "The same model installed with the capability named works, which is what"
note "makes the refusal above a policy rather than an outage."
check "a model that claims embed installs" \
  aidctl install --name text-and-embed --source file:///tmp/weights.bin \
  --digest "$DIGEST" --format mock --backend mock --capability generate --capability embed
runas alice aidctl embed --model text-and-embed "embed me" >/tmp/cap-embed2.txt 2>&1
run cat /tmp/cap-embed2.txt
contains "and embeds" /tmp/cap-embed2.txt 'dim='

note "The session's hello reports the intersection, so a client can ask before"
note "it tries rather than finding out per request."
runas alice aidctl generate --model text-only --max-tokens 4 "what can you do" \
  >/tmp/cap-hello.txt 2>&1
run head -2 /tmp/cap-hello.txt
contains "the hello lists what this session can be asked for" /tmp/cap-hello.txt '^capabilities: generate$'
runas alice aidctl generate --model text-and-embed --max-tokens 4 "and you" \
  >/tmp/cap-hello2.txt 2>&1
contains "a model that claims more reports more" /tmp/cap-hello2.txt '^capabilities: generate, embed$'
note "It used to report the backend's whole list — ten entries, including"
note "image-out — which told a client what the machine could do and left the"
note "model to disagree at request time."
note "It used to report the backend's whole list, which told a client what the"
note "machine could do and left the model to disagree at request time."

note "The compatibility break this represents, measured rather than estimated:"
note "aidctl install has always defaulted to --capability generate, so every"
note "model installed before this commit does today whatever its backend can"
note "and will refuse tomorrow whatever its manifest omits."
note ""
note "This suite is the evidence. Turning the enforcement on broke six checks"
note "in sections 7, 8 and 16 — media output, raw pixels, and embeddings on"
note "the remote model — none of which had anything to do with capabilities."
note "They broke because the fixtures declared generate and embed and were"
note "then handed screenshots and asked for pictures, and the manifest was"
note "decoration so nobody noticed. The fixtures now name what they use."
note ""
note "That is the shape of the break for a real install too: it lands where"
note "somebody has been relying on a capability their model never claimed,"
note "which is everywhere the field was decoration. The decision to take it"
note "is in the review attached to this branch."

# ---------------------------------------------------------------------------
printf '\n\033[1m=== Result ===\033[0m\n'
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  printf '\n  \033[31mVERIFICATION FAILED\033[0m\n'
  exit 1
fi
printf '\n  \033[32mVERIFICATION PASSED\033[0m\n'
