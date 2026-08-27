// SPDX-License-Identifier: Apache-2.0

//! A PNG generator for the verification run.
//!
//! Not part of the package: it exists so the attachment test has a real PNG to
//! send, produced by something other than the decoder that will read it. A
//! round trip through one implementation proves nothing.
//!
//! It writes stored (uncompressed) DEFLATE blocks, which is the least
//! interesting thing a PNG can contain and therefore the least likely to make
//! the test pass for the wrong reason.

use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        eprintln!("usage: make-png WIDTH HEIGHT PATH");
        std::process::exit(2);
    }
    let width: u32 = args[0].parse().expect("width");
    let height: u32 = args[1].parse().expect("height");
    let path = &args[2];

    // RGBA, one filter byte per row (filter 0 = none).
    let stride = width as usize * 4;
    let mut raw = Vec::with_capacity((stride + 1) * height as usize);
    for y in 0..height {
        raw.push(0u8);
        for x in 0..width {
            raw.push((x % 256) as u8);
            raw.push((y % 256) as u8);
            raw.push(((x + y) % 256) as u8);
            raw.push(0xff);
        }
    }

    let mut png: Vec<u8> = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit, truecolour+alpha
    chunk(&mut png, b"IHDR", &ihdr);
    chunk(&mut png, b"IDAT", &zlib_stored(&raw));
    chunk(&mut png, b"IEND", &[]);

    let mut file = std::fs::File::create(path).expect("create");
    file.write_all(&png).expect("write");

    // The same pixels, undecoded, so the verification can send either form and
    // compare what the daemon says about them.
    let mut raw_out = Vec::with_capacity(stride * height as usize);
    for row in raw.chunks(stride + 1) {
        raw_out.extend_from_slice(&row[1..]);
    }
    let mut raw_file = std::fs::File::create(format!("{path}.rgba")).expect("create raw");
    raw_file.write_all(&raw_out).expect("write raw");
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
    let mut out = vec![0x78, 0x01]; // deflate, 32k window, no dict, check ok
    let mut offset = 0usize;
    while offset < data.len() {
        let len = (data.len() - offset).min(0xffff);
        let last = if offset + len == data.len() { 1u8 } else { 0u8 };
        out.push(last);
        out.extend_from_slice(&(len as u16).to_le_bytes());
        out.extend_from_slice(&(!(len as u16)).to_le_bytes());
        out.extend_from_slice(&data[offset..offset + len]);
        offset += len;
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

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
