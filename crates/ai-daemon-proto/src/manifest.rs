//! What the registry knows about a model (§6).
//!
//! Weights are stored by digest and referenced by name, so two apps asking for
//! `llama-3.1-8b-q4` get one file and one mmap. The manifest is the mapping
//! plus everything the daemon must know *before* loading: whether it fits,
//! whether the backend can read it, and what licence the user agreed to.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Requirements {
    /// Bytes of weights. Also the file size the digest is taken over.
    pub weights_bytes: u64,
    /// Minimum memory to load at the default context length, weights included.
    #[serde(default)]
    pub min_memory_bytes: u64,
    #[serde(default)]
    pub default_ctx: u32,
    #[serde(default)]
    pub max_ctx: u32,
}

impl Default for Requirements {
    fn default() -> Self {
        Requirements { weights_bytes: 0, min_memory_bytes: 0, default_ctx: 4096, max_ctx: 4096 }
    }
}

/// Prompt-template metadata. The daemon does not render templates — backends
/// do — but it carries them so a backend that has no opinion can be told one.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Template {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chat_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bos: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eos: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Human name, unique in a store: `llama-3.1-8b-q4`.
    pub name: String,
    /// `sha256:<hex>` over the weights file. The only identity that counts.
    pub digest: String,
    /// `gguf` in v1.
    pub format: String,
    #[serde(default)]
    pub quantization: String,
    /// SPDX identifier, or the licence's own name where it has no SPDX id.
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub requirements: Requirements,
    #[serde(default)]
    pub template: Template,
    /// Which backend should load this. Empty means "first one that declares
    /// the format".
    #[serde(default)]
    pub backend: String,
    /// Model-level capability claims: `generate`, `embed`, `vision`, `audio-in`.
    /// Intersected with the backend's own claims; a model cannot grant what the
    /// backend cannot do, and a backend cannot grant what the model is not.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Where it came from, for the audit record. Never re-fetched from.
    #[serde(default)]
    pub source: String,
}

/// The three aliases every install has, so apps can ask for a role rather than
/// a model and let the machine's owner decide what fills it (§6).
pub const WELL_KNOWN_ALIASES: [&str; 3] = ["default", "fast", "embed"];
