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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    /// Human name, unique in a store: `llama-3.1-8b-q4`.
    pub name: String,
    /// `sha256:<hex>` over the weights file. The only identity that counts.
    ///
    /// One exception, and it is visible in the string rather than hidden: a
    /// remote model has no weights on this machine, so there is nothing to
    /// hash and its digest reads `remote:<endpoint-model-id>`. That is an
    /// identifier, not a content hash, and it makes no integrity claim —
    /// which is exactly why it does not wear a `sha256:` prefix it could not
    /// honour. Use `Manifest::is_remote` rather than testing the prefix.
    pub digest: String,
    /// `gguf` in v1, or `remote` for a model that lives on somebody else's
    /// machine.
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
    /// Model-level capability claims: `generate`, `embed`, `vision`,
    /// `audio-in`, `image-out`, `audio-out`.
    ///
    /// Intersected with the backend's own claims, and both halves of that are
    /// enforced rather than described:
    ///
    /// * *A model cannot grant what the backend cannot do* — at install, where
    ///   a manifest claiming a capability its backend does not serve is
    ///   refused outright rather than installed to fail later.
    /// * *A backend cannot grant what the model is not* — at request, where a
    ///   session on a model that does not claim `embed` is refused it even
    ///   though the backend would happily oblige.
    ///
    /// The list is what the session reports in its hello, so a client can ask
    /// before it tries.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Where it came from, for the audit record. Never re-fetched from.
    #[serde(default)]
    pub source: String,
}

/// The three aliases every install has, so apps can ask for a role rather than
/// a model and let the machine's owner decide what fills it (§6).
impl Manifest {
    /// Does this model claim to do `capability`?
    ///
    /// An empty list means the manifest predates the field and says nothing,
    /// which is treated as `generate` — the only thing every model does and
    /// the only thing `aidctl install` has ever defaulted to. It is not
    /// treated as "everything", because a list that means everything when
    /// absent is a list nobody can rely on.
    pub fn serves(&self, capability: &str) -> bool {
        if self.capabilities.is_empty() {
            return capability == "generate";
        }
        self.capabilities.iter().any(|claim| claim == capability)
    }

    /// True when the weights are not on this machine and never will be.
    ///
    /// The distinction is load-bearing in three places: there is no blob to
    /// resolve, there is no digest to verify, and the user has to be told —
    /// so it is a method rather than a scattering of `== "remote"`.
    pub fn is_remote(&self) -> bool {
        self.format == REMOTE_FORMAT
    }
}

/// The format string a model served by a remote provider carries.
pub const REMOTE_FORMAT: &str = "remote";

pub const WELL_KNOWN_ALIASES: [&str; 3] = ["default", "fast", "embed"];

#[cfg(test)]
mod capability_tests {
    use super::*;

    fn model(capabilities: &[&str]) -> Manifest {
        Manifest {
            name: "m".into(),
            capabilities: capabilities.iter().map(|c| c.to_string()).collect(),
            ..Manifest::default()
        }
    }

    #[test]
    fn a_model_serves_what_it_claims_and_nothing_else() {
        let m = model(&["generate", "vision"]);
        assert!(m.serves("generate"));
        assert!(m.serves("vision"));
        assert!(!m.serves("embed"), "the backend can embed; this model does not claim to");
        assert!(!m.serves("audio-in"));
    }

    /// An embedding-only model is a legitimate install, so `generate` is not
    /// special-cased into always being true.
    #[test]
    fn a_model_that_only_embeds_does_not_generate() {
        let m = model(&["embed"]);
        assert!(m.serves("embed"));
        assert!(!m.serves("generate"));
    }

    /// An empty list means the manifest predates the field. Read as
    /// `generate`, which is what `aidctl install` has always defaulted to —
    /// not as "everything", because a list that means everything when absent
    /// is a list nobody can rely on.
    #[test]
    fn an_empty_list_means_generate_rather_than_anything() {
        let m = model(&[]);
        assert!(m.serves("generate"));
        assert!(!m.serves("embed"));
        assert!(!m.serves("vision"));
    }
}
