# Provisioning: how to ship this so the strongest claim holds

The pitch is a chokepoint: applications get inference and nothing else — no
provider key, no egress, no way to widen what they were handed. Half of that
is code in this repository. The other half is how the machine is provisioned,
and it is the load-bearing half: **if the only provider credential on the
machine lives where no application can read it, an application that goes
direct has nothing to authenticate with.** It does not need to be blocked; it
cannot succeed. Everything else — the shim's gate, `ai-run`'s namespace — is
defence in depth behind that fact.

This page is the paragraph that makes it true, written as defaults for a
distribution and rules of thumb for an administrator.

## The one rule

**No application is ever given a provider API key.** Not in its config, not in
its keyring entry, not in an environment variable in its unit file. An
application that wants inference is pointed at the daemon — the native D-Bus
API, or the shim for anything that already speaks OpenAI or Anthropic — and
the daemon holds whatever credentials the machine's owner has decided to
trust it with.

If a remote provider is configured at all, its key lives in one place:

```
/etc/ai-daemon/remote.key      0400 ai-daemon-remote:ai-daemon
```

Readable by the remote backend's own uid and nobody else — not by the daemon,
which never talks to the network, and not by any human account. The packaged
unit files already run each process as its own user; the mode above is what
`packaging/verify/boot.sh` sets and what an installer should set.

## What the defaults already do

The package ships with everything that could violate the rule turned off:

- **No remote provider is configured.** `remote.toml.example` is
  documentation; nothing reads it until an administrator copies it into place
  and writes a key file. A default install never sends bytes off-machine.
- **The shim is off.** `systemctl enable --now ai-daemon-shim` is a decision,
  and the shim holds no credentials either way — it translates HTTP into
  sessions and lets the daemon answer.
- **The daemon has no network** (`PrivateNetwork=yes`), so it could not leak a
  key it does not hold even if it held one.

So a distribution that installs the package and does nothing else is already
compliant. Provisioning only has teeth where an administrator adds a remote
provider or migrates existing applications, which is where the rest of this
page points.

## Migrating a machine that already has keys

The audit is one command per place keys accumulate:

```
grep -rl 'sk-[A-Za-z0-9_-]' /etc /home/*/.config 2>/dev/null   # the blunt version
```

For each application found holding a credential: point it at the shim
(`ANTHROPIC_BASE_URL` / OpenAI `base_url` — every serious client has the
knob, because organisations put gateways in front of these tools), give it a
token from `/etc/ai-daemon/shim.toml` so it arrives as itself, and delete its
key. `aidctl spend` then answers per-agent what used to be invisible, and
revoking one agent is one line rather than a key rotation.

A token in `shim.toml` is a name, not a secret worth stealing: it selects
which identity a caller is filed under, and what that identity may do is
policy, enforced daemon-side. The provider key it replaced bought the holder
unmetered spend on someone else's account.

## For the case you cannot rule out

A widget that ships its own key, or a user who pastes one in, still exists.
That is what `ai-run` is for — a network namespace with no route anywhere and
the daemon's socket left reachable:

```
ai-run -- the-widget
```

The widget keeps its inference and loses its egress; a key inside it has
nowhere to go. This is confinement as a *composition*, not a sandbox claim:
`ai-run` removes exactly one capability, and stacks under `systemd-run` or
`bwrap` for the rest.

## For application developers

Target the daemon and ship no key. The whole client is small enough to read
in one sitting — `examples/think.py` is forty lines including its comments —
and what your application gets in exchange for a key it no longer holds:
inference that works offline against local weights, an identity the OS
asserts for you, and a user who can see what your application spends and say
no to it in one place.
