//! A stand-in for `llama-server`, used by `tests/chat.rs` to drive the
//! Core's model broker without a model. It takes the same arguments, answers
//! `/health` and `/v1/chat/completions`, and checks the API key. What it
//! streams is chosen by a word in the last message, so one server can play
//! every scenario:
//!
//! - `SCENARIO:slow` streams 400 tokens, one every 50 ms (for cancelling).
//! - `SCENARIO:hostile` streams terminal escapes and invisible characters.
//! - `SCENARIO:garbage` sends one token, then an event that is not JSON.
//! - `SCENARIO:error` sends an error event with a multi-line message.
//! - `SCENARIO:huge` streams more text than a reply may hold.
//! - `SCENARIO:die` exits in the middle of the reply.
//! - `SCENARIO:cut` closes the connection cleanly before the end marker.
//! - `SCENARIO:length` stops at the token limit (`finish_reason: "length"`).
//! - anything else streams a short greeting.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let value = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|at| args.get(at + 1))
            .cloned()
    };
    let port = value("--port").expect("--port");
    let key = value("--api-key").expect("--api-key");
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).expect("bind");
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let key = key.clone();
        std::thread::spawn(move || serve(stream, &key));
    }
}

fn serve(stream: TcpStream, key: &str) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut stream = stream;
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let (mut length, mut authorized) = (0usize, false);
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
        if let Some(n) = lower.strip_prefix("content-length:") {
            length = n.trim().parse().unwrap_or(0);
        }
        if line == format!("Authorization: Bearer {key}") {
            authorized = true;
        }
    }
    let mut body = vec![0u8; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let body = String::from_utf8_lossy(&body);
    if !authorized {
        let _ = stream.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n");
        return;
    }
    if request_line.starts_with("GET /health") {
        let _ =
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}");
        return;
    }
    if !body.contains("\"stream\":true") {
        // The Core's speed check after a load.
        let json =
            r#"{"choices":[{"message":{"content":"ok"}}],"timings":{"predicted_per_second":50.0}}"#;
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{json}",
            json.len()
        );
        return;
    }
    let _ = stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
    );
    let scenario = body
        .rsplit("SCENARIO:")
        .next()
        .filter(|_| body.contains("SCENARIO:"))
        .map(|rest| {
            rest.chars()
                .take_while(char::is_ascii_alphabetic)
                .collect::<String>()
        })
        .unwrap_or_default();
    let token = |stream: &mut TcpStream, text: &str| {
        let event = format!(
            "data: {{\"choices\":[{{\"delta\":{{\"content\":{}}}}}]}}\n\n",
            json_string(text)
        );
        stream.write_all(event.as_bytes()).is_ok()
    };
    match scenario.as_str() {
        "slow" => {
            for _ in 0..400 {
                if !token(&mut stream, "lento ") {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        "hostile" => {
            token(&mut stream, "red\u{1b}[31m text\u{202e} hidden\u{200b}!");
        }
        "garbage" => {
            token(&mut stream, "first");
            let _ = stream.write_all(b"data: {not json\n\n");
        }
        "error" => {
            let _ = stream
                .write_all(b"data: {\"error\":{\"message\":\"boom\\nsecond line\\u001b[0m\"}}\n\n");
            return;
        }
        "huge" => {
            let piece = "x".repeat(1024);
            for _ in 0..80 {
                if !token(&mut stream, &piece) {
                    return;
                }
            }
        }
        "cut" => {
            token(&mut stream, "half");
            return;
        }
        "length" => {
            token(&mut stream, "partial");
            let _ = stream.write_all(
                b"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"length\"}]}

data: [DONE]

",
            );
            return;
        }
        "die" => {
            token(&mut stream, "about to");
            let _ = stream.flush();
            std::thread::sleep(Duration::from_millis(100));
            std::process::exit(3);
        }
        _ => {
            token(&mut stream, "Olá");
            token(&mut stream, " mundo");
        }
    }
    let _ = stream.write_all(
        b"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"timings\":{\"prompt_n\":5,\"predicted_n\":2,\"predicted_per_second\":50.0}}\n\ndata: [DONE]\n\n",
    );
}

fn json_string(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
