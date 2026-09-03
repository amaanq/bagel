//! Minimal, correct HTTP/1.x request-head reader built on `httparse`.
//!
//! Reads until the header terminator regardless of how the kernel splits the
//! stream, then hands back both the parsed view and the raw bytes so a proxy
//! can replay the request verbatim. Two independent bounds protect the reader:
//! a per-read idle timeout and a total deadline, so a slow client cannot pin a
//! connection open by trickling one byte at a time.

use std::io;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

const MAX_HEAD: usize = 16 * 1024;
const MAX_HEADERS: usize = 128;

/// A parsed request head plus the raw bytes it was parsed from.
#[derive(Debug, Clone)]
pub struct Head {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    /// Raw request head, up to and including the final `\r\n\r\n`.
    pub raw: Vec<u8>,
    /// Any bytes read past the head (the start of the body).
    pub body: Vec<u8>,
}

impl Head {
    /// Look up a header value case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Read a request head with a per-read idle timeout and a default total budget.
pub async fn read_head<S>(stream: &mut S, idle: Duration) -> io::Result<Option<Head>>
where
    S: AsyncRead + Unpin,
{
    read_head_full(stream, idle, Duration::from_secs(30), Vec::new()).await
}

/// Read a request head, seeding the buffer with `prefix` (bytes already read
/// from the stream, e.g. leftover from a PROXY header). Bounded by both a
/// per-read `idle` timeout and a `total` deadline across the whole head.
pub async fn read_head_full<S>(
    stream: &mut S,
    idle: Duration,
    total: Duration,
    prefix: Vec<u8>,
) -> io::Result<Option<Head>>
where
    S: AsyncRead + Unpin,
{
    let deadline = Instant::now() + total;
    let mut buf = prefix;
    let mut chunk = [0u8; 4096];

    loop {
        if let Some(head) = try_parse(&buf) {
            return Ok(Some(head));
        }
        if buf.len() > MAX_HEAD {
            return Ok(None);
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        let wait = idle.min(remaining);

        match timeout(wait, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => return Ok(None),
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                // A read timing out only ends the connection once the total
                // budget is also spent; otherwise keep waiting.
                if Instant::now() >= deadline {
                    return Ok(None);
                }
            }
        }
    }
}

fn try_parse(buf: &[u8]) -> Option<Head> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf) {
        Ok(httparse::Status::Complete(len)) => Some(Head {
            method: req.method.unwrap_or_default().to_string(),
            path: req.path.unwrap_or_default().to_string(),
            headers: req
                .headers
                .iter()
                .map(|h| {
                    (
                        h.name.to_string(),
                        String::from_utf8_lossy(h.value).into_owned(),
                    )
                })
                .collect(),
            raw: buf[..len].to_vec(),
            body: buf[len..].to_vec(),
        }),
        // Partial means keep reading; an error means give up on this connection.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn parses_across_split_reads() {
        let (mut client, mut server) = tokio::io::duplex(64);

        tokio::spawn(async move {
            client
                .write_all(b"GET /wp-admin HTTP/1.1\r\nHost: ex")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            client
                .write_all(b"ample.com\r\nUser-Agent: bot\r\n\r\nBODY")
                .await
                .unwrap();
        });

        let head = read_head(&mut server, Duration::from_secs(1))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(head.method, "GET");
        assert_eq!(head.path, "/wp-admin");
        assert_eq!(head.header("host"), Some("example.com"));
        assert_eq!(head.header("USER-AGENT"), Some("bot"));
        assert_eq!(head.body, b"BODY");
        assert!(head.raw.ends_with(b"\r\n\r\n"));
    }

    #[tokio::test]
    async fn honours_prefix_bytes() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            client.write_all(b"HTTP/1.1\r\n\r\n").await.unwrap();
        });
        // The request line arrives via the prefix, the rest over the wire.
        let head = read_head_full(
            &mut server,
            Duration::from_secs(1),
            Duration::from_secs(5),
            b"GET /x ".to_vec(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(head.path, "/x");
    }

    #[tokio::test]
    async fn total_deadline_stops_a_trickle() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            // Never sends the header terminator.
            for _ in 0..100 {
                if client.write_all(b"X").await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
        let head = read_head_full(
            &mut server,
            Duration::from_secs(1),
            Duration::from_millis(100),
            Vec::new(),
        )
        .await
        .unwrap();
        assert!(head.is_none(), "trickle should hit the total deadline");
    }

    #[tokio::test]
    async fn early_close_yields_none() {
        let (client, mut server) = tokio::io::duplex(64);
        drop(client);
        let head = read_head(&mut server, Duration::from_secs(1))
            .await
            .unwrap();
        assert!(head.is_none());
    }
}
