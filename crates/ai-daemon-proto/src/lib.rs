//! The frozen surfaces of ai-daemon.
//!
//! Three contracts live here because three different parties depend on them
//! and none of them should have to read the daemon to know what it will send:
//!
//! * [`frame`] — the client-facing data plane (§12). Length-prefixed frames on
//!   the per-session Unix socket, CBOR for structure and raw bytes for BLOBs.
//! * [`backend`] — the provider plugin protocol (§7). The same framing, over a
//!   socketpair, so a segfaulting CUDA stack costs one backend and not the
//!   policy engine.
//! * [`manifest`] — what the model registry stores about a model (§6).
//!
//! Both protocols are versioned by an explicit `proto` integer exchanged in the
//! first frame. A peer that does not recognise the version says so and closes
//! rather than guessing; there is no negotiation ladder in v1 because there is
//! only one rung.

pub mod backend;
pub mod frame;
pub mod manifest;

/// Version of the client data-plane protocol (§12).
///
/// v2 adds what §12 deferred — parallel tool calls, fine-grained logit
/// control — and what §11 deferred, media output. A v1 client is still served:
/// [`MIN_DATA_PROTO`] is what the daemon accepts, and a session remembers
/// which version its client asked for. Nothing v2 adds is sent to a client
/// that did not ask for v2, so the addition cannot break a reader that has
/// never heard of it.
pub const DATA_PROTO: u32 = 2;

/// The oldest client protocol still served.
pub const MIN_DATA_PROTO: u32 = 1;

/// Version of the backend provider protocol (§7).
///
/// v2 alongside the client's: media generation, parallel tool calls and the
/// extra sampling controls all need somewhere to be expressed. Backends
/// declare what they speak in their hello, and both shipped backends were
/// updated with it — a third-party backend still speaking v1 keeps working,
/// because everything v2 adds is something the daemon only asks for when the
/// backend has said it can.
pub const BACKEND_PROTO: u32 = 2;

/// The oldest backend protocol still driven.
pub const MIN_BACKEND_PROTO: u32 = 1;
