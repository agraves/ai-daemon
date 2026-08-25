import Foundation

// aid — the /dev/ai broker.
//
// LLM inference as a first-class OS resource: a device tree (`/dev/ai/auto`
// plus one node per provider) where a node is a trust boundary, opening it is
// the egress approval, and a session fd is an unforgeable, delegable
// capability. The broker holds provider credentials, enforces policy keyed by
// kernel-attested identity, meters tokens and spend, and writes a
// hash-chained audit of every conversation on the box.
//
// Design record: notes/2026-08-25-dev-ai-design.md. The shape deliberately
// mirrors the paperclipper daemon's own philosophy — credentials live in the
// broker, callers get a vocabulary, identity comes from the substrate rather
// than the payload — ported down a layer, onto Linux, with the kernel
// contributing what it already knows how to contribute: identity and fds.
//
// Nothing is implemented yet. This target exists so the project has a home
// and the gates keep it honest while it grows.

let version = "0.0.0"

let arguments = CommandLine.arguments.dropFirst()
switch arguments.first {
case "--version":
    print("aid \(version)")
case "--help", nil:
    print("""
        aid \(version) — the /dev/ai broker (not yet implemented)

        Will provide:
          /dev/ai/auto           opaque routing, pinned per session, admin-controlled
          /dev/ai/<provider>     explicit egress consent, one node per provider
          policy                 kernel-attested identity → models, limits, preludes
          accounting             tokens and spend metered per cgroup
          audit                  hash-chained record of every request and reply

        Design: notes/2026-08-25-dev-ai-design.md (this repository)
        """)
default:
    FileHandle.standardError.write(Data("aid: nothing is implemented yet — see --help\n".utf8))
    exit(2)
}
