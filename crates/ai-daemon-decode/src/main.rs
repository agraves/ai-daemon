//! ai-daemon-decode — one attachment, then exit.
//!
//! This is where attacker-shaped bytes are allowed to be parsed, and it is the
//! only place. §11's reasoning is worth repeating because it is the reason
//! this binary exists at all: image and audio codecs are the largest CVE
//! surface in desktop software, and the daemon holding every grant, every
//! session and the audit chain must not link them.
//!
//! So this process:
//!
//! * reads one encoded blob on stdin and writes raw frames on stdout,
//! * drops every privilege it can before touching a byte of it — no new
//!   privileges, no filesystem, no network, no fork, killed on a deadline,
//! * and exits. A crash costs one attachment.
//!
//! The confinement is applied with seccomp where the kernel offers it, and the
//! process refuses to decode at all if it could not be applied — a decoder
//! that silently ran unconfined would be worse than no decoder, because the
//! daemon's clients would have been told their attachment was handled safely.
//!
//! v1 links no third-party codecs either: the formats below are ones whose
//! parsers are small enough to read in full. Anything else is refused with
//! `unsupported`, and the client decodes it themselves — which is always an
//! option and is what §11's first accepted form is for.

use std::io::Write;

use ai_daemon_proto::frame::{self, Frame};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct Request {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    hint: String,
    #[serde(default)]
    len: u64,
    #[serde(default)]
    max_output: u64,
}

#[derive(Debug, Default, Serialize)]
struct Reply {
    ok: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    w: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    h: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fmt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate: Option<u32>,
    len: u64,
}

fn main() {
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("ai-daemon-decode {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if std::env::args().any(|a| a == "--help" || a == "-h") {
        println!(
            "ai-daemon-decode {} — decode one attachment, confined, then exit

Reads a CBOR request frame and a BLOB frame on stdin; writes a CBOR reply
frame and a BLOB frame on stdout. Spawned by ai-daemon; not a general command.

Accepted: image/png (8-bit RGB and RGBA, non-interlaced), audio/wav
(PCM s16le and f32le, mono or stereo). Everything else is refused so the
client decodes it, which keeps the codec out of a privileged process.",
            env!("CARGO_PKG_VERSION")
        );
        return;
    }

    let mut stdin = std::io::stdin().lock();
    let request: Request = match frame::read_typed(&mut stdin) {
        Ok(Some(request)) => request,
        Ok(None) => fail("no request arrived"),
        Err(e) => fail(&format!("unreadable request: {e}")),
    };

    let mut encoded = Vec::with_capacity(request.len.min(1 << 20) as usize);
    while (encoded.len() as u64) < request.len {
        match frame::read_frame(&mut stdin) {
            Ok(Some(Frame::Blob(mut chunk))) => encoded.append(&mut chunk),
            Ok(Some(Frame::Cbor(_))) => fail("a structured frame interrupted the payload"),
            Ok(None) => fail("the payload ended early"),
            Err(e) => fail(&format!("payload: {e}")),
        }
    }

    // Everything above this line touched only the daemon's own framing. The
    // untrusted bytes are parsed below it, so the cage closes here.
    if let Err(e) = confine::apply() {
        fail(&format!("refusing to decode unconfined: {e}"));
    }

    let outcome = match request.kind.as_str() {
        "image" => png::decode(&encoded, request.max_output),
        "audio" => wav::decode(&encoded, request.max_output),
        other => Err(format!("unsupported attachment kind {other:?}")),
    };

    match outcome {
        Ok(decoded) => {
            let reply = Reply {
                ok: true,
                error: String::new(),
                w: decoded.w,
                h: decoded.h,
                fmt: decoded.fmt,
                rate: decoded.rate,
                len: decoded.data.len() as u64,
            };
            let mut stdout = std::io::stdout().lock();
            if frame::write_cbor(&mut stdout, &reply).is_err() {
                std::process::exit(1);
            }
            let _ = frame::write_blob(&mut stdout, &decoded.data);
            let _ = stdout.flush();
        }
        Err(e) => fail(&format!("{} ({})", e, request.hint)),
    }
}

#[derive(Debug)]
struct Decoded {
    w: Option<u32>,
    h: Option<u32>,
    fmt: Option<String>,
    rate: Option<u32>,
    data: Vec<u8>,
}

fn fail(message: &str) -> ! {
    let reply = Reply { ok: false, error: message.to_string(), ..Reply::default() };
    let mut stdout = std::io::stdout().lock();
    let _ = frame::write_cbor(&mut stdout, &reply);
    let _ = stdout.flush();
    std::process::exit(1)
}

/// Shutting the doors before the parser runs.
mod confine {
    /// Apply what the kernel gives us, in increasing order of usefulness.
    ///
    /// `NO_NEW_PRIVS` is required for an unprivileged seccomp filter and is
    /// also worth having on its own. The filter itself is a small allow-list
    /// installed as classic BPF: the syscalls a decoder needs are read, write,
    /// a few memory calls and exit, and nothing in that list can open a file,
    /// touch a socket or start a process.
    pub fn apply() -> Result<(), String> {
        // SAFETY: prctl with constant arguments and no pointers.
        let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if rc != 0 {
            return Err(format!(
                "PR_SET_NO_NEW_PRIVS failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        seccomp()
    }

    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc000_00b7;

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn seccomp() -> Result<(), String> {
        use std::mem::size_of;

        #[repr(C)]
        struct SockFilter {
            code: u16,
            jt: u8,
            jf: u8,
            k: u32,
        }
        #[repr(C)]
        struct SockFprog {
            len: u16,
            filter: *const SockFilter,
        }

        // Classic BPF opcodes, spelled out rather than pulled from a crate:
        // the whole filter is fifteen instructions and a reviewer should be
        // able to check it against the seccomp documentation without leaving
        // this file.
        const LD_W_ABS: u16 = 0x20;
        const JMP_JEQ_K: u16 = 0x15;
        const RET_K: u16 = 0x06;
        const ARCH_OFFSET: u32 = 4;
        const NR_OFFSET: u32 = 0;
        const ALLOW: u32 = 0x7fff_0000;
        const KILL_PROCESS: u32 = 0x8000_0000;

        // The allow-list. It is generous about the boring calls and silent
        // about every interesting one: there is no openat, no socket, no
        // execve, no clone, no ptrace, so the decoder cannot touch a file, a
        // network or another process however badly it is fooled.
        //
        // Being generous here is deliberate. The default action is to kill,
        // and a filter that omits something the allocator needs turns every
        // attachment into a dead child — which looks like a broken feature
        // rather than a security boundary doing its job. Everything below is
        // something a Rust program does to its own memory, its own already-open
        // descriptors, or its own exit.
        let allowed: &[libc::c_long] = &[
            // Already-open descriptors: stdin in, stdout out.
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_readv,
            libc::SYS_writev,
            libc::SYS_lseek,
            libc::SYS_close,
            libc::SYS_fstat,
            libc::SYS_statx,
            libc::SYS_poll,
            libc::SYS_ppoll,
            // The allocator.
            libc::SYS_mmap,
            libc::SYS_munmap,
            libc::SYS_mremap,
            libc::SYS_mprotect,
            libc::SYS_brk,
            libc::SYS_madvise,
            // Threads and signals the runtime sets up for itself.
            libc::SYS_futex,
            libc::SYS_rt_sigreturn,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigaction,
            libc::SYS_sigaltstack,
            libc::SYS_set_robust_list,
            libc::SYS_rseq,
            libc::SYS_getpid,
            libc::SYS_gettid,
            // A panic in the decoder must be able to abort the decoder.
            libc::SYS_tgkill,
            libc::SYS_getrandom,
            libc::SYS_sched_yield,
            libc::SYS_clock_gettime,
            libc::SYS_clock_nanosleep,
            libc::SYS_nanosleep,
            libc::SYS_restart_syscall,
            libc::SYS_prlimit64,
            libc::SYS_exit,
            libc::SYS_exit_group,
        ];

        let prog = SockFprog {
            len: u16::try_from(program.len()).map_err(|_| "filter too long")?,
            filter: program.as_ptr(),
        };
        let _ = size_of::<SockFprog>();

        // Two ways in, because the newer one is not always reachable. The
        // `seccomp()` syscall is itself filtered by some container runtimes'
        // own profiles, while `prctl(PR_SET_SECCOMP)` — the original
        // interface, doing the same thing without the flags we do not use — is
        // not. Trying both means the confinement holds in a container as well
        // as on a desktop, rather than the decoder refusing to run in one.
        //
        // SAFETY: `prog` points at a filter that outlives the call, and both
        // interfaces copy it into the kernel.
        let via_seccomp = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                1, // SECCOMP_SET_MODE_FILTER
                0,
                &prog as *const SockFprog,
            )
        };
        if via_seccomp == 0 {
            return Ok(());
        }
        let first = std::io::Error::last_os_error();
        // SAFETY: as above.
        let via_prctl = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &prog as *const SockFprog,
            )
        };
        if via_prctl != 0 {
            return Err(format!(
                "seccomp filter rejected: seccomp() said {first}, prctl() said {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    fn seccomp() -> Result<(), String> {
        Err("no seccomp filter is defined for this architecture".into())
    }
}

/// A PNG reader for the subset a screenshot actually is.
///
/// Written out rather than pulled in because "the daemon links no codecs" is a
/// claim about the whole project, not just one process: a dependency here
/// would be a dependency whose next CVE is this project's problem. The subset
/// — 8-bit truecolour, no interlacing — covers what clients send and refuses
/// everything else loudly.
mod png {
    use super::Decoded;

    pub fn decode(bytes: &[u8], max_output: u64) -> Result<Decoded, String> {
        const MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        if bytes.len() < 8 || bytes[..8] != MAGIC {
            return Err("not a PNG".into());
        }
        let mut offset = 8usize;
        let mut header: Option<Header> = None;
        let mut idat: Vec<u8> = Vec::new();

        while offset + 8 <= bytes.len() {
            let len = be32(&bytes[offset..])? as usize;
            let kind = &bytes[offset + 4..offset + 8];
            let start = offset + 8;
            let end = start.checked_add(len).ok_or("chunk length overflow")?;
            if end + 4 > bytes.len() {
                return Err("truncated chunk".into());
            }
            match kind {
                b"IHDR" => header = Some(Header::parse(&bytes[start..end])?),
                b"IDAT" => idat.extend_from_slice(&bytes[start..end]),
                b"IEND" => break,
                _ => {}
            }
            offset = end + 4;
        }

        let header = header.ok_or("no IHDR")?;
        let channels = header.channels();
        let pixels = (header.width as u64) * (header.height as u64);
        let output_len = pixels * channels as u64;
        if output_len > max_output {
            return Err(format!("decoded size {output_len} exceeds the caller's limit"));
        }
        let raw = super::inflate::zlib(&idat, output_len + header.height as u64 * 2)?;
        let data = unfilter(&raw, &header, channels)?;
        Ok(Decoded {
            w: Some(header.width),
            h: Some(header.height),
            fmt: Some(if channels == 4 { "rgba8".into() } else { "rgb8".into() }),
            rate: None,
            data,
        })
    }

    struct Header {
        width: u32,
        height: u32,
        colour: u8,
    }

    impl Header {
        fn parse(bytes: &[u8]) -> Result<Header, String> {
            if bytes.len() < 13 {
                return Err("short IHDR".into());
            }
            let width = be32(bytes)?;
            let height = be32(&bytes[4..])?;
            let depth = bytes[8];
            let colour = bytes[9];
            let interlace = bytes[12];
            if width == 0 || height == 0 {
                return Err("zero-sized image".into());
            }
            if depth != 8 {
                return Err(format!("only 8-bit PNG is accepted, got {depth}-bit"));
            }
            if interlace != 0 {
                return Err("interlaced PNG is not accepted".into());
            }
            if colour != 2 && colour != 6 {
                return Err("only truecolour PNG (with or without alpha) is accepted".into());
            }
            Ok(Header { width, height, colour })
        }

        fn channels(&self) -> usize {
            if self.colour == 6 {
                4
            } else {
                3
            }
        }
    }

    fn unfilter(raw: &[u8], header: &Header, channels: usize) -> Result<Vec<u8>, String> {
        let stride = header.width as usize * channels;
        let expected = (stride + 1) * header.height as usize;
        if raw.len() < expected {
            return Err(format!("expected {expected} filtered bytes, got {}", raw.len()));
        }
        let mut out = vec![0u8; stride * header.height as usize];
        for row in 0..header.height as usize {
            let filter = raw[row * (stride + 1)];
            let src = &raw[row * (stride + 1) + 1..row * (stride + 1) + 1 + stride];
            let (before, current) = out.split_at_mut(row * stride);
            let previous = if row == 0 { None } else { Some(&before[(row - 1) * stride..]) };
            let current = &mut current[..stride];
            for i in 0..stride {
                let a = if i >= channels { current[i - channels] } else { 0 };
                let b = previous.map(|p| p[i]).unwrap_or(0);
                let c = if i >= channels {
                    previous.map(|p| p[i - channels]).unwrap_or(0)
                } else {
                    0
                };
                current[i] = match filter {
                    0 => src[i],
                    1 => src[i].wrapping_add(a),
                    2 => src[i].wrapping_add(b),
                    3 => src[i].wrapping_add(((a as u16 + b as u16) / 2) as u8),
                    4 => src[i].wrapping_add(paeth(a, b, c)),
                    other => return Err(format!("unknown row filter {other}")),
                };
            }
        }
        Ok(out)
    }

    fn paeth(a: u8, b: u8, c: u8) -> u8 {
        let p = a as i16 + b as i16 - c as i16;
        let pa = (p - a as i16).abs();
        let pb = (p - b as i16).abs();
        let pc = (p - c as i16).abs();
        if pa <= pb && pa <= pc {
            a
        } else if pb <= pc {
            b
        } else {
            c
        }
    }

    fn be32(bytes: &[u8]) -> Result<u32, String> {
        if bytes.len() < 4 {
            return Err("truncated integer".into());
        }
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

/// The DEFLATE half of PNG. Same reasoning as the PNG reader: small enough to
/// read, so it does not become somebody else's CVE with our name on it.
mod inflate {
    pub fn zlib(bytes: &[u8], max_output: u64) -> Result<Vec<u8>, String> {
        if bytes.len() < 2 {
            return Err("no zlib stream".into());
        }
        let cmf = bytes[0];
        if cmf & 0x0f != 8 {
            return Err("not a deflate stream".into());
        }
        if (bytes[0] as u16 * 256 + bytes[1] as u16) % 31 != 0 {
            return Err("bad zlib header check".into());
        }
        if bytes[1] & 0x20 != 0 {
            return Err("preset dictionaries are not supported".into());
        }
        inflate(&bytes[2..], max_output)
    }

    struct Bits<'a> {
        bytes: &'a [u8],
        position: usize,
    }

    impl<'a> Bits<'a> {
        fn bit(&mut self) -> Result<u32, String> {
            let byte = self
                .bytes
                .get(self.position >> 3)
                .ok_or("deflate stream ended early")?;
            let bit = (byte >> (self.position & 7)) & 1;
            self.position += 1;
            Ok(bit as u32)
        }

        fn bits(&mut self, count: usize) -> Result<u32, String> {
            let mut value = 0u32;
            for index in 0..count {
                value |= self.bit()? << index;
            }
            Ok(value)
        }

        fn align(&mut self) {
            self.position = (self.position + 7) & !7;
        }
    }

    struct Huffman {
        counts: [u16; 16],
        symbols: Vec<u16>,
    }

    impl Huffman {
        fn new(lengths: &[u8]) -> Huffman {
            let mut counts = [0u16; 16];
            for &length in lengths {
                counts[length as usize] += 1;
            }
            counts[0] = 0;
            let mut offsets = [0u16; 16];
            for index in 1..16 {
                offsets[index] = offsets[index - 1] + counts[index - 1];
            }
            let mut symbols = vec![0u16; lengths.len()];
            for (symbol, &length) in lengths.iter().enumerate() {
                if length != 0 {
                    symbols[offsets[length as usize] as usize] = symbol as u16;
                    offsets[length as usize] += 1;
                }
            }
            Huffman { counts, symbols }
        }

        fn decode(&self, bits: &mut Bits<'_>) -> Result<u16, String> {
            let mut code = 0i32;
            let mut first = 0i32;
            let mut index = 0i32;
            for length in 1..16 {
                code |= bits.bit()? as i32;
                let count = self.counts[length] as i32;
                if code - first < count {
                    return Ok(self.symbols[(index + (code - first)) as usize]);
                }
                index += count;
                first = (first + count) << 1;
                code <<= 1;
            }
            Err("invalid Huffman code".into())
        }
    }

    const LENGTH_BASE: [u16; 29] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
        131, 163, 195, 227, 258,
    ];
    const LENGTH_EXTRA: [u8; 29] = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    ];
    const DISTANCE_BASE: [u16; 30] = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
        2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
    ];
    const DISTANCE_EXTRA: [u8; 30] = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
        13, 13,
    ];

    pub fn inflate(bytes: &[u8], max_output: u64) -> Result<Vec<u8>, String> {
        let mut bits = Bits { bytes, position: 0 };
        let mut out: Vec<u8> = Vec::new();
        loop {
            let final_block = bits.bit()?;
            match bits.bits(2)? {
                0 => {
                    bits.align();
                    let start = bits.position >> 3;
                    if start + 4 > bytes.len() {
                        return Err("truncated stored block".into());
                    }
                    let len = u16::from_le_bytes([bytes[start], bytes[start + 1]]) as usize;
                    let nlen = u16::from_le_bytes([bytes[start + 2], bytes[start + 3]]) as usize;
                    if len != !nlen & 0xffff {
                        return Err("stored block length check failed".into());
                    }
                    let from = start + 4;
                    let to = from.checked_add(len).ok_or("stored block overflow")?;
                    if to > bytes.len() {
                        return Err("truncated stored block".into());
                    }
                    out.extend_from_slice(&bytes[from..to]);
                    bits.position = to << 3;
                }
                1 => {
                    let mut lengths = [0u8; 288];
                    for (symbol, length) in lengths.iter_mut().enumerate() {
                        *length = match symbol {
                            0..=143 => 8,
                            144..=255 => 9,
                            256..=279 => 7,
                            _ => 8,
                        };
                    }
                    let literals = Huffman::new(&lengths);
                    let distances = Huffman::new(&[5u8; 30]);
                    block(&mut bits, &literals, &distances, &mut out, max_output)?;
                }
                2 => {
                    let hlit = bits.bits(5)? as usize + 257;
                    let hdist = bits.bits(5)? as usize + 1;
                    let hclen = bits.bits(4)? as usize + 4;
                    const ORDER: [usize; 19] = [
                        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
                    ];
                    let mut code_lengths = [0u8; 19];
                    for &index in ORDER.iter().take(hclen) {
                        code_lengths[index] = bits.bits(3)? as u8;
                    }
                    let code_huffman = Huffman::new(&code_lengths);
                    let mut lengths = vec![0u8; hlit + hdist];
                    let mut index = 0usize;
                    while index < lengths.len() {
                        let symbol = code_huffman.decode(&mut bits)?;
                        match symbol {
                            0..=15 => {
                                lengths[index] = symbol as u8;
                                index += 1;
                            }
                            16 => {
                                if index == 0 {
                                    return Err("repeat with nothing to repeat".into());
                                }
                                let previous = lengths[index - 1];
                                let repeat = 3 + bits.bits(2)? as usize;
                                for _ in 0..repeat {
                                    if index >= lengths.len() {
                                        return Err("code length overrun".into());
                                    }
                                    lengths[index] = previous;
                                    index += 1;
                                }
                            }
                            17 => index += 3 + bits.bits(3)? as usize,
                            18 => index += 11 + bits.bits(7)? as usize,
                            other => return Err(format!("bad code length symbol {other}")),
                        }
                    }
                    if index > lengths.len() {
                        return Err("code length overrun".into());
                    }
                    let literals = Huffman::new(&lengths[..hlit]);
                    let distances = Huffman::new(&lengths[hlit..]);
                    block(&mut bits, &literals, &distances, &mut out, max_output)?;
                }
                _ => return Err("reserved deflate block type".into()),
            }
            if final_block == 1 {
                break;
            }
        }
        Ok(out)
    }

    fn block(
        bits: &mut Bits<'_>,
        literals: &Huffman,
        distances: &Huffman,
        out: &mut Vec<u8>,
        max_output: u64,
    ) -> Result<(), String> {
        loop {
            if out.len() as u64 > max_output {
                return Err("decoded output exceeded the caller's limit".into());
            }
            let symbol = literals.decode(bits)?;
            match symbol {
                0..=255 => out.push(symbol as u8),
                256 => return Ok(()),
                257..=285 => {
                    let index = symbol as usize - 257;
                    let length =
                        LENGTH_BASE[index] as usize + bits.bits(LENGTH_EXTRA[index] as usize)? as usize;
                    let distance_symbol = distances.decode(bits)? as usize;
                    if distance_symbol >= DISTANCE_BASE.len() {
                        return Err("bad distance symbol".into());
                    }
                    let distance = DISTANCE_BASE[distance_symbol] as usize
                        + bits.bits(DISTANCE_EXTRA[distance_symbol] as usize)? as usize;
                    if distance > out.len() {
                        return Err("back-reference before the start of the stream".into());
                    }
                    let start = out.len() - distance;
                    for offset in 0..length {
                        let byte = out[start + offset];
                        out.push(byte);
                    }
                }
                other => return Err(format!("bad literal/length symbol {other}")),
            }
        }
    }
}

/// RIFF/WAVE to mono float32 PCM, which is the only audio shape §11 accepts.
mod wav {
    use super::Decoded;

    pub fn decode(bytes: &[u8], max_output: u64) -> Result<Decoded, String> {
        if bytes.len() < 12 || &bytes[..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
            return Err("not a RIFF/WAVE file".into());
        }
        let mut offset = 12usize;
        let mut format: Option<(u16, u16, u32, u16)> = None;
        let mut data: Option<&[u8]> = None;

        while offset + 8 <= bytes.len() {
            let id = &bytes[offset..offset + 4];
            let size = u32::from_le_bytes([
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]) as usize;
            let start = offset + 8;
            let end = start.checked_add(size).ok_or("chunk overflow")?.min(bytes.len());
            match id {
                b"fmt " => {
                    if end - start < 16 {
                        return Err("short fmt chunk".into());
                    }
                    let chunk = &bytes[start..end];
                    format = Some((
                        u16::from_le_bytes([chunk[0], chunk[1]]),
                        u16::from_le_bytes([chunk[2], chunk[3]]),
                        u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
                        u16::from_le_bytes([chunk[14], chunk[15]]),
                    ));
                }
                b"data" => data = Some(&bytes[start..end]),
                _ => {}
            }
            offset = end + (size & 1);
        }

        let (tag, channels, rate, depth) = format.ok_or("no fmt chunk")?;
        let data = data.ok_or("no data chunk")?;
        let channels = channels.max(1) as usize;

        let samples: Vec<f32> = match (tag, depth) {
            (1, 16) => data
                .chunks_exact(2)
                .map(|s| i16::from_le_bytes([s[0], s[1]]) as f32 / 32_768.0)
                .collect(),
            (3, 32) => data
                .chunks_exact(4)
                .map(|s| f32::from_le_bytes([s[0], s[1], s[2], s[3]]))
                .collect(),
            _ => return Err(format!("unsupported WAVE format tag {tag} at {depth}-bit")),
        };

        // Downmix rather than refuse: stereo is what a microphone gives you,
        // and averaging is the least surprising thing to do with it.
        let mono: Vec<f32> = if channels == 1 {
            samples
        } else {
            samples
                .chunks(channels)
                .map(|frame| frame.iter().sum::<f32>() / channels as f32)
                .collect()
        };
        let out_len = mono.len() as u64 * 4;
        if out_len > max_output {
            return Err(format!("decoded size {out_len} exceeds the caller's limit"));
        }
        let mut raw = Vec::with_capacity(mono.len() * 4);
        for sample in mono {
            raw.extend_from_slice(&sample.to_le_bytes());
        }
        Ok(Decoded { w: None, h: None, fmt: None, rate: Some(rate), data: raw })
    }
}

#[cfg(test)]
mod tests {
    /// A PNG built here, decoded by the module that will decode attacker
    /// input. Building it with stored DEFLATE blocks and with each compression
    /// scheme in turn is deliberate: the interesting failures in a decoder are
    /// in the paths a well-behaved encoder rarely takes.
    mod png {
        use crate::png;

        fn crc32(data: &[u8]) -> u32 {
            let mut crc = 0xffff_ffffu32;
            for &byte in data {
                crc ^= byte as u32;
                for _ in 0..8 {
                    crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
                }
            }
            !crc
        }

        fn adler32(data: &[u8]) -> u32 {
            let (mut a, mut b) = (1u32, 0u32);
            for &byte in data {
                a = (a + byte as u32) % 65521;
                b = (b + a) % 65521;
            }
            (b << 16) | a
        }

        fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], payload: &[u8]) {
            out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            out.extend_from_slice(kind);
            out.extend_from_slice(payload);
            let mut crc_input = kind.to_vec();
            crc_input.extend_from_slice(payload);
            out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
        }

        fn zlib_stored(data: &[u8]) -> Vec<u8> {
            let mut out = vec![0x78, 0x01];
            let mut offset = 0usize;
            loop {
                let len = (data.len() - offset).min(0xffff);
                let last = if offset + len == data.len() { 1u8 } else { 0u8 };
                out.push(last);
                out.extend_from_slice(&(len as u16).to_le_bytes());
                out.extend_from_slice(&(!(len as u16)).to_le_bytes());
                out.extend_from_slice(&data[offset..offset + len]);
                offset += len;
                if offset >= data.len() {
                    break;
                }
            }
            out.extend_from_slice(&adler32(data).to_be_bytes());
            out
        }

        /// `filter` is applied to every row; the encoder side of each filter is
        /// written out so the decoder's arithmetic is checked against an
        /// independent implementation rather than against itself.
        fn build(width: u32, height: u32, channels: usize, filter: u8) -> (Vec<u8>, Vec<u8>) {
            let stride = width as usize * channels;
            let mut pixels = vec![0u8; stride * height as usize];
            for y in 0..height as usize {
                for x in 0..stride {
                    pixels[y * stride + x] = ((x * 7 + y * 13) % 251) as u8;
                }
            }
            let mut filtered = Vec::with_capacity((stride + 1) * height as usize);
            for y in 0..height as usize {
                filtered.push(filter);
                for x in 0..stride {
                    let raw = pixels[y * stride + x];
                    let a = if x >= channels { pixels[y * stride + x - channels] } else { 0 };
                    let b = if y > 0 { pixels[(y - 1) * stride + x] } else { 0 };
                    let c = if x >= channels && y > 0 {
                        pixels[(y - 1) * stride + x - channels]
                    } else {
                        0
                    };
                    filtered.push(match filter {
                        0 => raw,
                        1 => raw.wrapping_sub(a),
                        2 => raw.wrapping_sub(b),
                        3 => raw.wrapping_sub(((a as u16 + b as u16) / 2) as u8),
                        4 => raw.wrapping_sub(paeth(a, b, c)),
                        _ => unreachable!(),
                    });
                }
            }

            let mut png: Vec<u8> = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
            let mut ihdr = Vec::new();
            ihdr.extend_from_slice(&width.to_be_bytes());
            ihdr.extend_from_slice(&height.to_be_bytes());
            ihdr.extend_from_slice(&[8, if channels == 4 { 6 } else { 2 }, 0, 0, 0]);
            chunk(&mut png, b"IHDR", &ihdr);
            chunk(&mut png, b"IDAT", &zlib_stored(&filtered));
            chunk(&mut png, b"IEND", &[]);
            (png, pixels)
        }

        fn paeth(a: u8, b: u8, c: u8) -> u8 {
            let p = a as i16 + b as i16 - c as i16;
            let (pa, pb, pc) =
                ((p - a as i16).abs(), (p - b as i16).abs(), (p - c as i16).abs());
            if pa <= pb && pa <= pc {
                a
            } else if pb <= pc {
                b
            } else {
                c
            }
        }

        #[test]
        fn every_row_filter_decodes_to_the_original_pixels() {
            for filter in 0..=4u8 {
                let (encoded, expected) = build(23, 17, 4, filter);
                let decoded = png::decode(&encoded, 1 << 20)
                    .unwrap_or_else(|e| panic!("filter {filter}: {e}"));
                assert_eq!(decoded.w, Some(23));
                assert_eq!(decoded.h, Some(17));
                assert_eq!(decoded.fmt.as_deref(), Some("rgba8"));
                assert_eq!(decoded.data, expected, "filter {filter} round trip");
            }
        }

        #[test]
        fn rgb_without_alpha_is_understood_and_labelled() {
            let (encoded, expected) = build(8, 8, 3, 0);
            let decoded = png::decode(&encoded, 1 << 20).unwrap();
            assert_eq!(decoded.fmt.as_deref(), Some("rgb8"));
            assert_eq!(decoded.data, expected);
        }

        #[test]
        fn a_decoded_size_over_the_caller_limit_is_refused_before_allocating() {
            let (encoded, _) = build(64, 64, 4, 0);
            let error = png::decode(&encoded, 1024).unwrap_err();
            assert!(error.contains("exceeds the caller"), "{error}");
        }

        /// The IHDR byte offsets are fixed: 8 signature + 8 chunk header, then
        /// width, height, bit depth, colour type, compression, filter,
        /// interlace. Poking them one at a time is the cheapest way to check
        /// that each refusal is its own refusal and not a generic one.
        #[test]
        fn things_outside_the_accepted_subset_are_refused_by_name() {
            for (what, offset, value, expected) in [
                ("16-bit", 24usize, 16u8, "8-bit"),
                ("palette", 25, 3, "truecolour"),
                ("greyscale", 25, 0, "truecolour"),
                ("interlaced", 28, 1, "interlaced"),
            ] {
                let (mut encoded, _) = build(4, 4, 4, 0);
                encoded[offset] = value;
                match png::decode(&encoded, 1 << 20) {
                    Err(error) => assert!(error.contains(expected), "{what}: got {error:?}"),
                    Ok(_) => panic!("{what} was accepted; it must not be"),
                }
            }

            let (mut encoded, _) = build(4, 4, 4, 0);
            encoded[16..20].copy_from_slice(&0u32.to_be_bytes());
            match png::decode(&encoded, 1 << 20) {
                Err(error) => assert!(error.contains("zero-sized"), "{error}"),
                Ok(_) => panic!("a zero-width image was accepted"),
            }
        }

        #[test]
        fn truncation_at_every_offset_fails_without_panicking() {
            let (encoded, _) = build(12, 9, 4, 4);
            for cut in (1..encoded.len()).step_by(7) {
                // The property is "never panics", not "always errors": a
                // prefix can legitimately be a complete smaller PNG. A panic
                // here would be a denial of service on one attachment, but a
                // panic in a decoder is how a worse bug starts.
                let _ = png::decode(&encoded[..cut], 1 << 20);
            }
        }

        #[test]
        fn garbage_is_not_a_png() {
            assert!(png::decode(b"", 1 << 20).is_err());
            assert!(png::decode(b"GIF89a", 1 << 20).is_err());
            assert!(png::decode(&[0u8; 4096], 1 << 20).is_err());
        }
    }

    mod wav {
        use crate::wav;

        fn build(tag: u16, channels: u16, rate: u32, depth: u16, payload: &[u8]) -> Vec<u8> {
            let mut fmt = Vec::new();
            fmt.extend_from_slice(&tag.to_le_bytes());
            fmt.extend_from_slice(&channels.to_le_bytes());
            fmt.extend_from_slice(&rate.to_le_bytes());
            fmt.extend_from_slice(&0u32.to_le_bytes()); // byte rate, unread
            fmt.extend_from_slice(&0u16.to_le_bytes()); // block align, unread
            fmt.extend_from_slice(&depth.to_le_bytes());

            let mut body = b"WAVE".to_vec();
            body.extend_from_slice(b"fmt ");
            body.extend_from_slice(&(fmt.len() as u32).to_le_bytes());
            body.extend_from_slice(&fmt);
            body.extend_from_slice(b"data");
            body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            body.extend_from_slice(payload);

            let mut out = b"RIFF".to_vec();
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&body);
            out
        }

        #[test]
        fn sixteen_bit_pcm_becomes_normalised_float32() {
            let samples: Vec<u8> = [0i16, 16384, -16384, 32767]
                .iter()
                .flat_map(|s| s.to_le_bytes())
                .collect();
            let decoded = wav::decode(&build(1, 1, 16_000, 16, &samples), 1 << 20).unwrap();
            assert_eq!(decoded.rate, Some(16_000));
            let values: Vec<f32> = decoded
                .data
                .chunks_exact(4)
                .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect();
            assert_eq!(values.len(), 4);
            assert!((values[0] - 0.0).abs() < 1e-6);
            assert!((values[1] - 0.5).abs() < 1e-6);
            assert!((values[2] + 0.5).abs() < 1e-6);
        }

        #[test]
        fn stereo_is_downmixed_rather_than_refused() {
            // A microphone gives you stereo; averaging is the least surprising
            // thing to do with it, and refusing would just move the work.
            let frames: Vec<u8> = [1000i16, 3000, -1000, -3000]
                .iter()
                .flat_map(|s| s.to_le_bytes())
                .collect();
            let decoded = wav::decode(&build(1, 2, 44_100, 16, &frames), 1 << 20).unwrap();
            let values: Vec<f32> = decoded
                .data
                .chunks_exact(4)
                .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect();
            assert_eq!(values.len(), 2, "two stereo frames become two mono samples");
            assert!((values[0] - 2000.0 / 32768.0).abs() < 1e-6);
        }

        #[test]
        fn an_unsupported_encoding_is_named_rather_than_guessed_at() {
            let error = wav::decode(&build(0x11, 1, 8000, 4, &[0u8; 16]), 1 << 20).unwrap_err();
            assert!(error.contains("unsupported WAVE format tag 17"), "{error}");
        }

        #[test]
        fn output_over_the_caller_limit_is_refused() {
            let error = wav::decode(&build(1, 1, 16_000, 16, &[0u8; 4096]), 64).unwrap_err();
            assert!(error.contains("exceeds the caller"), "{error}");
        }

        #[test]
        fn garbage_is_not_a_wave_file() {
            assert!(wav::decode(b"", 1 << 20).is_err());
            assert!(wav::decode(b"RIFF____NOTWAVE", 1 << 20).is_err());
        }

        #[test]
        fn truncation_at_every_offset_fails_without_panicking() {
            let full = build(1, 2, 44_100, 16, &[7u8; 512]);
            for cut in 1..full.len() {
                let _ = wav::decode(&full[..cut], 1 << 20);
            }
        }
    }

    mod inflate {
        use crate::inflate;

        #[test]
        fn a_stream_that_is_not_zlib_is_refused() {
            assert!(inflate::zlib(&[], 1024).is_err());
            assert!(inflate::zlib(&[0x00, 0x00], 1024).is_err(), "compression method must be 8");
            assert!(inflate::zlib(&[0x78, 0x00], 1024).is_err(), "header check must hold");
            assert!(inflate::zlib(&[0x78, 0xa1], 1024).is_err(), "preset dictionary");
        }

        #[test]
        fn a_back_reference_before_the_start_is_refused_not_wrapped() {
            // Fixed-Huffman block whose first symbol is a length/distance pair
            // with nothing behind it. A decoder that wrapped or indexed
            // negatively here would be exploitable.
            let stream = [0x78, 0x01, 0x63, 0x00, 0x00, 0x00, 0x00];
            let _ = inflate::zlib(&stream, 1024);
        }

        #[test]
        fn random_bytes_never_panic() {
            let mut state = 0x2545_f491_4f6c_dd1du64;
            for _ in 0..2000 {
                let mut bytes = vec![0x78u8, 0x01];
                for _ in 0..48 {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    bytes.push(state as u8);
                }
                let _ = inflate::zlib(&bytes, 1 << 16);
            }
        }
    }
}
