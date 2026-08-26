//! The provider plugin protocol (§7).
//!
//! A backend is a separate process the daemon spawns, speaking this protocol
//! over a `SOCK_SEQPACKET`-shaped socketpair on fd 3 with the same framing as
//! the client data plane. Out-of-process is the whole point: a backend links
//! CUDA, ROCm, SYCL and vendor NPU userspace, any of which may abort the
//! process it lives in, and none of which may take the policy engine with it.
//!
//! Requests carry a `req_id`; replies echo it, so one backend multiplexes many
//! sessions on one socket. Ordering within a `req_id` is guaranteed; between
//! them it is not.

use serde::{Deserialize, Serialize};

use crate::frame::{Message, Params, ToolCall, ToolSchema, Usage};

/// What a backend says it can do, in its `hello` reply.
///
/// The daemon treats every field as a claim it will police: declaring
/// `vision` does not grant a session vision, it makes vision *possible* for
/// models this backend loads, still subject to policy (§5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendInfo {
    pub name: String,
    pub version: String,
    /// Weight formats understood, e.g. `["gguf"]`.
    pub formats: Vec<String>,
    /// Quantizations understood, e.g. `["q4_k_m", "q8_0", "f16"]`.
    #[serde(default)]
    pub quantizations: Vec<String>,
    /// Device nodes this backend intends to open, e.g. `["/dev/dri/renderD128"]`.
    /// Declared so the daemon can refuse a backend whose claims exceed the
    /// unit's `DeviceAllow` rather than discovering it at load time.
    #[serde(default)]
    pub devices: Vec<String>,
    /// Bytes of accelerator memory the backend believes it may use, if it can
    /// tell. `None` means "unknown", which the scheduler treats as "assume it
    /// is the whole device".
    #[serde(default)]
    pub device_memory: Option<u64>,
    /// `generate`, `embed`, `logprobs`, `grammar`, `vision`, `audio-in`, `tools`.
    pub capabilities: Vec<String>,
    /// False for a backend that sends bytes off this machine (§7). The daemon
    /// propagates this into every consent prompt and session info; it is never
    /// summarised away.
    #[serde(default = "yes")]
    pub local: bool,
}

fn yes() -> bool {
    true
}

/// A decoded attachment as it reaches a backend: raw only. Nothing that
/// arrived encoded gets this far without passing through `ai-daemon-decode`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawAttachment {
    pub id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub w: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fmt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<u32>,
    #[serde(with = "serde_bytes_compat")]
    pub data: Vec<u8>,
}

/// ciborium encodes `Vec<u8>` as an array of integers unless told otherwise;
/// for multi-megabyte pixel buffers that is a 3x size penalty, so force a
/// byte string.
mod serde_bytes_compat {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let value = ciborium::Value::deserialize(d)?;
        match value {
            ciborium::Value::Bytes(b) => Ok(b),
            ciborium::Value::Array(items) => items
                .into_iter()
                .map(|i| {
                    i.as_integer()
                        .and_then(|n| u8::try_from(n).ok())
                        .ok_or_else(|| serde::de::Error::custom("attachment byte out of range"))
                })
                .collect(),
            _ => Err(serde::de::Error::custom("attachment data must be bytes")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum BackendRequest {
    Hello {
        proto: u32,
    },
    /// Make a model resident. `path` is already digest-verified by the daemon;
    /// the backend is not asked to trust the registry, only to read the file.
    Load {
        model_id: String,
        path: String,
        digest: String,
        #[serde(default)]
        n_ctx: u32,
    },
    Unload {
        model_id: String,
    },
    Generate {
        req_id: u64,
        model_id: String,
        session_id: String,
        messages: Vec<Message>,
        #[serde(default)]
        params: Params,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grammar: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tools: Option<Vec<ToolSchema>>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        attachments: Vec<RawAttachment>,
    },
    Embed {
        req_id: u64,
        model_id: String,
        inputs: Vec<String>,
    },
    Tokenize {
        req_id: u64,
        model_id: String,
        text: String,
    },
    Cancel {
        req_id: u64,
    },
    /// Scheduler preemption (§8). A backend must honour these at a token
    /// boundary — not mid-decode, and not later than the next token.
    Pause {
        req_id: u64,
    },
    Resume {
        req_id: u64,
    },
    /// Reclaim a session's KV cache. The daemon has already told the client
    /// `context-evicted`; the next `generate` for that session will replay.
    DropCache {
        session_id: String,
    },
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "ev", rename_all = "snake_case")]
pub enum BackendEvent {
    Hello {
        proto: u32,
        info: BackendInfo,
    },
    Loaded {
        model_id: String,
        /// Bytes of KV cache one token of context costs for this model. The
        /// scheduler's whole budget (§8) is this number times context length.
        kv_bytes_per_token: u64,
        n_ctx: u32,
    },
    Unloaded {
        model_id: String,
    },
    Token {
        req_id: u64,
        tok: String,
    },
    ToolCall {
        req_id: u64,
        tool_call: ToolCall,
    },
    Vectors {
        req_id: u64,
        vectors: Vec<Vec<f32>>,
    },
    Tokens {
        req_id: u64,
        tokens: Vec<u32>,
    },
    Done {
        req_id: u64,
        usage: Usage,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        finish_reason: Option<String>,
    },
    Error {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        req_id: Option<u64>,
        code: String,
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame;

    /// A megapixel of RGBA is four megabytes. ciborium encodes `Vec<u8>` as an
    /// array of integers unless told otherwise, which would make that twelve —
    /// so this test is about a 3x wire cost, not about tidiness.
    #[test]
    fn attachment_bytes_are_a_cbor_byte_string_not_an_array() {
        let attachment = RawAttachment {
            id: "img1".into(),
            kind: "image".into(),
            w: Some(2),
            h: Some(2),
            fmt: Some("rgba8".into()),
            rate: None,
            data: vec![0xff; 16],
        };
        let mut encoded = Vec::new();
        ciborium::into_writer(&attachment, &mut encoded).unwrap();
        // A 16-byte byte string is 0x50 | length; an array would be 0x90.
        assert!(
            encoded.windows(2).any(|w| w == [0x50, 0xff]),
            "expected a CBOR byte string header in {encoded:02x?}"
        );
        assert!(encoded.len() < 60, "{} bytes is array-shaped", encoded.len());

        let back: RawAttachment = ciborium::from_reader(&encoded[..]).unwrap();
        assert_eq!(back.data, attachment.data);
    }

    #[test]
    fn backend_requests_round_trip_through_the_frame_layer() {
        let request = BackendRequest::Load {
            model_id: "m".into(),
            path: "/var/lib/ai-daemon/models/blobs/sha256/abc".into(),
            digest: "sha256:abc".into(),
            n_ctx: 4096,
        };
        let mut buffer = Vec::new();
        frame::write_cbor(&mut buffer, &request).unwrap();
        let back: BackendRequest = frame::read_typed(&mut &buffer[..]).unwrap().unwrap();
        match back {
            BackendRequest::Load { model_id, n_ctx, .. } => {
                assert_eq!(model_id, "m");
                assert_eq!(n_ctx, 4096);
            }
            other => panic!("came back as {other:?}"),
        }
    }
}
