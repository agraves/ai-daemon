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
pub const DATA_PROTO: u32 = 1;

/// Version of the backend provider protocol (§7).
pub const BACKEND_PROTO: u32 = 1;
