//! Framing and client-facing frame types for the session data plane.
//!
//! Wire shape, deliberately dull:
//!
//! ```text
//! u32 be length | u8 kind | payload[length]
//! kind 0x01 = CBOR value
//! kind 0x02 = BLOB (opaque bytes, belongs to the most recent `attach`)
//! ```
//!
//! One tag byte instead of two socket protocols: attachments are large and
//! must not pay CBOR's byte-string copy, but they still need backpressure and
//! ordering relative to the request that references them, so they ride the
//! same stream.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

pub const KIND_CBOR: u8 = 0x01;
pub const KIND_BLOB: u8 = 0x02;

/// Hard ceiling on any single frame, before policy limits apply.
///
/// This is not the attachment budget (§5, §11) — it is the "an allocation this
/// large is a bug or an attack" line, checked before anything is read into
/// memory.
pub const MAX_FRAME: u32 = 64 * 1024 * 1024;

/// The most BLOB payload put in any one frame. Longer payloads are split
/// across several, which every reader already absorbs: a BLOB is always
/// preceded by a header declaring its total length, and the loops that consume
/// them read until they have that many bytes rather than assuming one frame.
///
/// Well under [`MAX_FRAME`] on purpose. The limit is what a peer will accept;
/// this is what we choose to send, and leaving room between them means a
/// writer cannot produce a frame its own reader would refuse.
pub const BLOB_CHUNK: usize = 8 * 1024 * 1024;

/// The most *decoded* attachment payload one request can carry.
///
/// Chunking does not help here and this is the ceiling that matters. Decoded
/// attachments travel to a backend inside the CBOR of a single `generate`
/// request, not as BLOBs, so they are bounded by [`MAX_FRAME`] however the
/// blob writers behave — with room left for the rest of the request, which is
/// what the subtraction is.
pub const MAX_ATTACHMENT_PAYLOAD: u64 = MAX_FRAME as u64 - 4 * 1024 * 1024;

#[derive(Debug)]
pub enum Frame {
    Cbor(ciborium::Value),
    Blob(Vec<u8>),
}

pub fn write_cbor<W: Write, T: Serialize>(w: &mut W, value: &T) -> io::Result<()> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| io::Error::other(e.to_string()))?;
    write_raw(w, KIND_CBOR, &buf)
}

/// Write a BLOB payload, splitting it across frames if it is large.
///
/// Two things this gets right that writing one frame did not.
///
/// A payload longer than [`MAX_FRAME`] used to fail on the write — after the
/// header announcing its length had already gone out. The reader would take
/// the header, loop for the bytes, hit EOF and report the peer as having
/// stopped mid-payload: a crash diagnosis for a framing limit. `MAX_DECODED`
/// in the decoder is four times `MAX_FRAME`, so the two constants promised
/// different things and the failure lied about which one had been hit.
///
/// And an empty payload writes *no* frames rather than one empty one. The
/// reader stops as soon as it has the declared length, so at zero it reads
/// nothing — an empty frame would be left in the stream and desynchronise
/// every frame after it.
pub fn write_blob<W: Write>(w: &mut W, bytes: &[u8]) -> io::Result<()> {
    for chunk in bytes.chunks(BLOB_CHUNK) {
        write_raw(w, KIND_BLOB, chunk)?;
    }
    Ok(())
}

fn write_raw<W: Write>(w: &mut W, kind: u8, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::other("frame exceeds u32 length"))?;
    if len > MAX_FRAME {
        return Err(io::Error::other("frame exceeds MAX_FRAME"));
    }
    let mut header = [0u8; 5];
    header[..4].copy_from_slice(&len.to_be_bytes());
    header[4] = kind;
    w.write_all(&header)?;
    w.write_all(payload)?;
    w.flush()
}

/// Read one frame. `Ok(None)` means the peer closed cleanly between frames.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Option<Frame>> {
    let mut header = [0u8; 5];
    if !read_exact_or_eof(r, &mut header)? {
        return Ok(None);
    }
    let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    if len > MAX_FRAME {
        return Err(io::Error::other(format!("frame of {len} bytes exceeds MAX_FRAME")));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload)?;
    match header[4] {
        KIND_CBOR => {
            let value: ciborium::Value = ciborium::from_reader(&payload[..])
                .map_err(|e| io::Error::other(format!("malformed CBOR frame: {e}")))?;
            Ok(Some(Frame::Cbor(value)))
        }
        KIND_BLOB => Ok(Some(Frame::Blob(payload))),
        other => Err(io::Error::other(format!("unknown frame kind {other:#04x}"))),
    }
}

/// Read a CBOR frame and deserialize it, rejecting a BLOB where structure was
/// expected. Most call sites want this rather than [`read_frame`].
pub fn read_typed<R: Read, T: for<'de> Deserialize<'de>>(r: &mut R) -> io::Result<Option<T>> {
    match read_frame(r)? {
        None => Ok(None),
        Some(Frame::Blob(_)) => Err(io::Error::other("expected a CBOR frame, got a BLOB")),
        Some(Frame::Cbor(value)) => {
            let typed = value
                .deserialized()
                .map_err(|e| io::Error::other(format!("unexpected frame shape: {e}")))?;
            Ok(Some(typed))
        }
    }
}

fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Client -> daemon
// ---------------------------------------------------------------------------

/// A chat message. `attachments` names ids introduced by [`Request::Attach`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    #[serde(default)]
    pub content: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<String>,
    /// Set on `role: "tool"` messages to name the call being answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Params {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<String>>,

    // Everything below is protocol v2, and every field is optional so that a
    // backend which cannot honour one may ignore it. A client that needs to
    // know whether it was honoured asks the session for its capabilities
    // rather than inferring from the output.
    /// Keep only the k most likely tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
    /// Drop tokens below this fraction of the most likely one's probability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_p: Option<f32>,
    /// Penalty applied to tokens already produced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repeat_penalty: Option<f32>,
    /// Per-token additive bias, keyed by token id. The fine-grained control
    /// §12 deferred: it is how a client suppresses or insists on a token
    /// without a grammar, and the only way to say "never this one" is a large
    /// negative bias rather than a rule.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub logit_bias: BTreeMap<u32, f32>,
    /// How many alternatives to report per emitted token. Needs the backend's
    /// `logprobs` capability; ignored by backends without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logprobs: Option<u32>,
}

/// A tool the *client* is offering to execute. The daemon compiles the schema
/// into a decoding grammar and emits [`Event::ToolCall`]; it never runs
/// anything (§10).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// JSON Schema for the arguments object.
    #[serde(default)]
    pub json_schema: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttachKind {
    Image,
    Audio,
}

/// Attachment metadata. Exactly one of the raw-data shapes or `encoded` must
/// describe the BLOB that follows (§11).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttachMeta {
    /// Raw image: pixel dimensions and layout, e.g. `rgb8` / `rgba8`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub w: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fmt: Option<String>,
    /// Raw audio: mono float32 PCM at this sample rate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<u32>,
    /// Encoded bytes instead of raw: the container/codec hint handed to
    /// `ai-daemon-decode`. The daemon links no codecs itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoded: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// First frame on the socket. Lets a client discover the session it was
    /// handed without a D-Bus round trip.
    Hello { #[serde(default)] proto: u32 },
    /// Introduce an attachment; the BLOB frame(s) totalling `len` follow.
    Attach {
        id: String,
        kind: AttachKind,
        #[serde(default)]
        meta: AttachMeta,
        len: u64,
    },
    Generate {
        messages: Vec<Message>,
        #[serde(default = "default_true")]
        stream: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        params: Option<Params>,
        /// Caller-supplied GBNF. Mutually exclusive with `tools`, which
        /// compiles its own.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grammar: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tools: Option<Vec<ToolSchema>>,
    },
    /// Answer a [`Event::ToolCall`] and resume the same session, KV cache warm.
    ToolResult { id: String, content: String },
    Embed { inputs: Vec<String> },
    Tokenize { text: String },
    Cancel,

    /// Answer several outstanding tool calls at once (protocol v2).
    ///
    /// The batch form exists because the daemon can now emit several calls in
    /// one turn: answering them one at a time would make the client serialise
    /// work the model deliberately parallelised.
    ToolResults { results: Vec<ToolResultItem> },

    /// Generate an image or a clip (§11's deferred output half, protocol v2).
    ///
    /// A separate op rather than a flag on `generate` because it is a
    /// different model class with a different resource profile, and because
    /// it needs its own capability in the grant table — a user may reasonably
    /// let an app write text and not let it synthesise a voice.
    GenerateMedia {
        kind: MediaKind,
        prompt: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        params: Option<Params>,
        /// How many to produce. Bounded by policy, not by the client.
        #[serde(default = "one")]
        count: u32,
    },
}

fn one() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultItem {
    pub id: String,
    pub content: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MediaKind {
    Image,
    Audio,
}

impl MediaKind {
    pub fn as_str(self) -> &'static str {
        match self {
            MediaKind::Image => "image",
            MediaKind::Audio => "audio",
        }
    }

    /// The backend capability a request of this kind needs.
    pub fn capability(self) -> &'static str {
        match self {
            MediaKind::Image => "image-out",
            MediaKind::Audio => "audio-out",
        }
    }
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Daemon -> client
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    /// JSON object, as a string, exactly as the grammar produced it.
    pub arguments: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Usage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    #[serde(default)]
    pub attachment_tokens: u64,
    /// Bytes of media produced. Not tokens, because generated media is not
    /// priced in them and pretending otherwise would put a number in the
    /// audit log that means nothing.
    #[serde(default)]
    pub media_bytes: u64,
}

/// Session facts a client may want without asking D-Bus again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session: String,
    pub model: String,
    pub identity: String,
    /// False when the resolved provider is remote (§7). Never inferred by the
    /// client; always stated by the daemon.
    pub local: bool,
    pub capabilities: Vec<String>,
    pub max_context: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Event {
    Hello {
        ok: bool,
        proto: u32,
        session: SessionInfo,
    },
    Token {
        tok: String,
        /// Alternatives considered for this position, most likely first.
        /// Present only when the client asked for `logprobs` and the backend
        /// offers the capability — absent, not empty, when it did not, so a
        /// client can tell "not asked for" from "nothing else was possible".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        logprobs: Option<Vec<TokenProb>>,
    },
    /// One tool call. Still what a protocol v1 client is sent, even when the
    /// model produced several, because a v1 client has no way to answer more
    /// than one and silently dropping the rest would be worse than not
    /// offering them.
    ToolCall {
        tool_call: ToolCall,
    },
    /// Several at once (protocol v2). The model decided these are independent;
    /// the client can run them in parallel and answer with `tool_results`.
    ToolCalls {
        tool_calls: Vec<ToolCall>,
    },
    /// Describes the BLOB frames that follow it, exactly as `attach` does in
    /// the other direction (protocol v2).
    Media {
        media: MediaOut,
    },
    Vectors {
        vectors: Vec<Vec<f32>>,
    },
    Tokens {
        tokens: Vec<u32>,
    },
    /// Out-of-band scheduler notice, e.g. `context-evicted` (§8).
    Notice {
        event: String,
        #[serde(default)]
        detail: String,
    },
    Done {
        done: bool,
        usage: Usage,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        finish_reason: Option<String>,
    },
    Error {
        error: ErrorBody,
    },
}

/// One alternative the sampler considered, and what it thought of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenProb {
    pub tok: String,
    /// Natural log of the probability, the convention every sampler reports.
    pub logprob: f32,
}

/// The header for a generated image or clip. The bytes follow as BLOB frames,
/// totalling `len` — the same shape an attachment uses arriving, so a client
/// that can read one can read the other.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaOut {
    pub id: String,
    pub kind: MediaKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub w: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h: Option<u32>,
    /// `rgb8` or `rgba8` for an image; absent for audio.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fmt: Option<String>,
    /// Sample rate for audio; absent for an image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<u32>,
    pub len: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Stable, matchable string: `attachment-unsupported`, `policy-denied`,
    /// `rate-limited`, `no-such-model`, `backend-failed`, `protocol`.
    pub code: String,
    pub message: String,
}

impl Event {
    pub fn error(code: &str, message: impl Into<String>) -> Event {
        Event::Error {
            error: ErrorBody { code: code.to_string(), message: message.into() },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_and_blob_frames_round_trip_in_order() {
        let mut buffer = Vec::new();
        write_cbor(&mut buffer, &Request::Hello { proto: DATA_PROTO_FOR_TEST }).unwrap();
        write_blob(&mut buffer, b"raw pixels").unwrap();
        write_cbor(&mut buffer, &Request::Cancel).unwrap();

        let mut cursor = &buffer[..];
        match read_frame(&mut cursor).unwrap().unwrap() {
            Frame::Cbor(value) => {
                let request: Request = value.deserialized().unwrap();
                assert!(matches!(request, Request::Hello { .. }));
            }
            other => panic!("expected CBOR, got {other:?}"),
        }
        match read_frame(&mut cursor).unwrap().unwrap() {
            Frame::Blob(bytes) => assert_eq!(bytes, b"raw pixels"),
            other => panic!("expected a BLOB, got {other:?}"),
        }
        assert!(matches!(read_frame(&mut cursor).unwrap(), Some(Frame::Cbor(_))));
        assert!(read_frame(&mut cursor).unwrap().is_none(), "clean EOF between frames");
    }

    const DATA_PROTO_FOR_TEST: u32 = crate::DATA_PROTO;

    #[test]
    fn a_length_over_the_ceiling_is_refused_before_allocating() {
        let mut header = Vec::new();
        header.extend_from_slice(&(MAX_FRAME + 1).to_be_bytes());
        header.push(KIND_CBOR);
        let error = read_frame(&mut &header[..]).unwrap_err();
        assert!(error.to_string().contains("MAX_FRAME"), "{error}");
    }

    #[test]
    fn a_truncated_payload_is_an_error_not_a_short_frame() {
        let mut buffer = Vec::new();
        write_blob(&mut buffer, b"0123456789").unwrap();
        buffer.truncate(buffer.len() - 3);
        assert!(read_frame(&mut &buffer[..]).is_err());
    }

    #[test]
    fn an_unknown_frame_kind_is_refused_rather_than_ignored() {
        let mut buffer = vec![0, 0, 0, 1, 0x7f, b'x'];
        let error = read_frame(&mut &mut &buffer[..]).unwrap_err();
        assert!(error.to_string().contains("unknown frame kind"), "{error}");
        buffer.clear();
    }

    #[test]
    fn read_typed_refuses_a_blob_where_structure_was_expected() {
        let mut buffer = Vec::new();
        write_blob(&mut buffer, b"not a request").unwrap();
        let error = read_typed::<_, Request>(&mut &buffer[..]).unwrap_err();
        assert!(error.to_string().contains("expected a CBOR frame"), "{error}");
    }

    #[test]
    fn events_deserialize_to_the_variant_they_were_written_as() {
        for event in [
            Event::Token { tok: "hi".into(), logprobs: None },
            Event::Notice { event: "context-evicted".into(), detail: "replay".into() },
            Event::Done {
                done: true,
                usage: Usage { prompt_tokens: 3, completion_tokens: 4, ..Usage::default() },
                finish_reason: Some("stop".into()),
            },
            Event::error("policy-denied", "no"),
        ] {
            let mut buffer = Vec::new();
            write_cbor(&mut buffer, &event).unwrap();
            let back: Event = read_typed(&mut &buffer[..]).unwrap().unwrap();
            assert_eq!(
                std::mem::discriminant(&event),
                std::mem::discriminant(&back),
                "{event:?} came back as {back:?}"
            );
        }
    }
}

#[cfg(test)]
mod chunking_tests {
    use super::*;

    /// The contradiction: the decoder is handed a 256 MiB output budget and a
    /// frame caps at 64 MiB, so a legal decode used to fail on the write —
    /// after its header had gone out, which made the reader report the peer as
    /// having stopped mid-payload.
    #[test]
    fn a_payload_larger_than_one_frame_round_trips() {
        let payload = vec![0x5au8; (MAX_FRAME as usize) + 1024];
        let mut buffer = Vec::new();
        write_blob(&mut buffer, &payload).expect("a long payload must be writable");

        // Read it the way every consumer does: until the declared length.
        let mut cursor = &buffer[..];
        let mut received: Vec<u8> = Vec::new();
        while received.len() < payload.len() {
            match read_frame(&mut cursor).unwrap() {
                Some(Frame::Blob(mut chunk)) => received.append(&mut chunk),
                other => panic!("expected a BLOB, got {other:?}"),
            }
        }
        assert_eq!(received, payload);
        assert!(read_frame(&mut cursor).unwrap().is_none(), "nothing left over");
    }

    #[test]
    fn no_frame_written_is_larger_than_one_can_be_read() {
        let mut buffer = Vec::new();
        write_blob(&mut buffer, &vec![7u8; 3 * BLOB_CHUNK + 5]).unwrap();
        let mut cursor = &buffer[..];
        let mut frames = 0;
        while let Some(frame) = read_frame(&mut cursor).unwrap() {
            match frame {
                Frame::Blob(chunk) => {
                    assert!(chunk.len() as u32 <= MAX_FRAME, "{} bytes", chunk.len());
                    frames += 1;
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(frames, 4);
    }

    /// An empty payload must write nothing at all. The reader stops as soon as
    /// it has the declared length, so at zero it reads nothing — one empty
    /// frame would sit unread and desynchronise every frame after it.
    #[test]
    fn an_empty_payload_leaves_nothing_in_the_stream() {
        let mut buffer = Vec::new();
        write_blob(&mut buffer, b"").unwrap();
        assert!(buffer.is_empty(), "an empty attachment must not emit a frame");

        // The shape that used to desynchronise: empty attachment, then a request.
        let mut stream = Vec::new();
        write_blob(&mut stream, b"").unwrap();
        write_cbor(&mut stream, &Request::Cancel).unwrap();
        let next: Option<Request> = read_typed(&mut &stream[..]).unwrap();
        assert!(matches!(next, Some(Request::Cancel)), "got {next:?}");
    }

    #[test]
    fn the_attachment_ceiling_leaves_room_inside_a_frame() {
        assert!(MAX_ATTACHMENT_PAYLOAD < MAX_FRAME as u64);
        assert!(BLOB_CHUNK as u32 <= MAX_FRAME);
    }
}
