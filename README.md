# ai-daemon — /dev/ai

LLM inference as a first-class, OS-mediated Linux resource: a device tree
(`/dev/ai/auto` plus one node per provider) where a node is a trust boundary,
opening it is the egress approval, and a session fd is an unforgeable,
delegable capability. The broker (`aid`) holds provider credentials, enforces
policy keyed by kernel-attested identity, meters tokens and spend per cgroup,
and writes a hash-chained audit of every conversation on the box.

The founding design record is `notes/2026-08-25-dev-ai-design.md`. Nothing is
implemented yet; the `aid` target exists so the project has a home and a gate.

```
swift build && .build/debug/aid --help
```
