// SPDX-License-Identifier: Apache-2.0

//! A stand-in for somebody else's inference service.
//!
//! The remote backend's whole job is to talk OpenAI-compatible HTTP to a
//! machine that is not this one. Verifying it needs something on the other
//! end, and it cannot be a real provider: no network in the build, no key, and
//! a test that costs money and varies by the day is not a test.
//!
//! Written to fail *loudly and implausibly* rather than the way a real service
//! would. That is deliberate and learned: a double that fails the way the real
//! peer fails produces a confident wrong diagnosis. This one answers 418 with
//! the reason in the body when it is unhappy, which is never a thing a real
//! endpoint does, so nobody can mistake the double's problem for the code's.
//!
//! It is not packaged. It is compiled into the verification box beside
//! make-png, the same way, and for the same reason.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

const KEY: &str = "verification-key";

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(8099);
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind");
    eprintln!("stub-endpoint: listening on 127.0.0.1:{port}");
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        std::thread::spawn(move || serve(stream));
    }
}

fn serve(mut stream: TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().expect("dup"));
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let path = request_line.split_whitespace().nth(1).unwrap_or("/").to_string();

    let mut length = 0usize;
    let mut authorized = false;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-length:") {
            length = value.trim().parse().unwrap_or(0);
        }
        if lower.starts_with("authorization:") {
            authorized = line.trim().ends_with(KEY);
        }
    }
    let mut body = vec![0u8; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let body = String::from_utf8_lossy(&body).to_string();

    // The one thing worth asserting about a remote provider's transport: that
    // it presents the credential. A 401 here is what a real service does, and
    // it is the failure the daemon must surface rather than swallow.
    if !authorized {
        let payload = "{\"error\":{\"message\":\"no key, no tokens\"}}";
        let _ = write!(
            stream,
            "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        return;
    }

    if path.ends_with("/embeddings") {
        let payload = "{\"data\":[{\"embedding\":[0.25,-0.5,0.75,1.0]}]}";
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        return;
    }
    if !path.ends_with("/chat/completions") {
        let payload = format!("the stub has no {path} — this is the double's fault, not the daemon's");
        let _ = write!(
            stream,
            "HTTP/1.1 418 I'm a teapot\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        return;
    }

    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
         Cache-Control: no-cache\r\nConnection: close\r\n\r\n"
    );

    // Tools take priority: an endpoint offered tools answers with calls.
    // On the presence of the tools key only: if the backend did not forward
    // the schemas, this answers with text and the check that wanted two calls
    // fails, which is the failure worth having.
    if body.contains("\"tools\":[") {
        for (index, (name, city)) in [("get_weather", "elsewhere"), ("get_time", "utc")]
            .into_iter()
            .enumerate()
        {
            let chunk = format!(
                "{{\"choices\":[{{\"delta\":{{\"tool_calls\":[{{\"id\":\"remote-{index}\",\
                 \"function\":{{\"name\":\"{name}\",\"arguments\":\"{{\\\"where\\\":\\\"{city}\\\"}}\"}}}}]}}}}]}}"
            );
            if send(&mut stream, &chunk).is_err() {
                return;
            }
        }
        let _ = stream.write_all(b"data: [DONE]\n\n");
        return;
    }

    // What provenance markers the daemon put in the prompt, reported back as
    // tokens. The mock backend counts characters rather than echoing them, so
    // this stand-in is the only place in the run that can say what actually
    // reached a backend — which is the thing worth asserting about marking.
    let markers = format!(
        "markers:policy={},from-app={},tool={},defanged={}",
        body.matches("<policy nonce=").count(),
        body.matches("<from-app nonce=").count(),
        body.matches("<tool-output nonce=").count(),
        body.matches("[nonce removed]").count()
    );
    if body.contains("report the markers") {
        let chunk = format!("{{\"choices\":[{{\"delta\":{{\"content\":\"{markers}\"}}}}]}}");
        let _ = send(&mut stream, &chunk);
        let done = "{\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\
                    \"usage\":{\"prompt_tokens\":11,\"completion_tokens\":1}}";
        let _ = send(&mut stream, done);
        let _ = stream.write_all(b"data: [DONE]\n\n");
        return;
    }

    // A long answer, so the cancel check has something to interrupt. The
    // endpoint keeps sending until the transfer is torn down; if cancellation
    // does not reach the far end, this runs for a minute and the check says so.
    let slow = body.contains("keep going");
    let wants_logprobs = body.contains("\"logprobs\":true");
    let count = if slow { 600 } else { 6 };

    for index in 0..count {
        let logprobs = if wants_logprobs {
            ",\"logprobs\":{\"content\":[{\"top_logprobs\":[\
             {\"token\":\"remote\",\"logprob\":-0.25},{\"token\":\"other\",\"logprob\":-1.75}]}]}"
        } else {
            ""
        };
        let chunk = format!(
            "{{\"choices\":[{{\"delta\":{{\"content\":\"remote-{index} \"}}{logprobs}}}]}}"
        );
        if send(&mut stream, &chunk).is_err() {
            // The daemon cancelled: curl is gone and the pipe is shut. Exactly
            // what a cancelled transfer looks like from over here.
            eprintln!("stub-endpoint: peer went away at token {index}");
            return;
        }
        if slow {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    let done = "{\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\
                \"usage\":{\"prompt_tokens\":11,\"completion_tokens\":6}}";
    let _ = send(&mut stream, done);
    let _ = stream.write_all(b"data: [DONE]\n\n");
}

fn send(stream: &mut TcpStream, chunk: &str) -> std::io::Result<()> {
    stream.write_all(format!("data: {chunk}\n\n").as_bytes())?;
    stream.flush()
}
