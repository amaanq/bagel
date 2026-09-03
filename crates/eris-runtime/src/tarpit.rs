//! The tarpit: send the response head immediately, then dribble the body out in
//! randomly-delayed, TCP-segment-sized chunks until it drains or the deadline
//! is hit. The head is never reordered, so the response stays valid while the
//! client waits.
//!
//! Chunk sizes are deliberately segment-shaped (tens to ~a thousand bytes)
//! rather than a handful of bytes: a real congested server emits recognisable
//! TCP segments, and a stream of one-to-four-byte writes is itself a tarpit
//! fingerprint. Believability comes from looking like a slow *real* transfer.

use rand::RngExt;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// Hold `client` in the tarpit while slowly feeding it `response`, one
/// `chunk_min..=chunk_max`-byte segment at a time.
#[allow(clippy::too_many_arguments)]
pub async fn tarpit(
    mut client: TcpStream,
    response: Vec<u8>,
    min_delay_ms: u64,
    max_delay_ms: u64,
    max_secs: u64,
    chunk_min: usize,
    chunk_max: usize,
    write_timeout_secs: u64,
    shutdown: CancellationToken,
) -> u64 {
    let split = find(&response, b"\r\n\r\n").map_or(response.len(), |i| i + 4);
    let (head, body) = response.split_at(split);

    if !write(&mut client, head, write_timeout_secs, &shutdown).await {
        return 0;
    }

    let deadline = Instant::now() + Duration::from_secs(max_secs);
    let mut pos = 0;
    let mut sent = head.len() as u64;
    let chunk_lo = chunk_min.max(1);
    let chunk_hi = chunk_max.max(chunk_lo);

    while pos < body.len() {
        if Instant::now() >= deadline {
            break;
        }

        let remaining = body.len() - pos;
        // Scope the RNG so no non-Send handle is held across an await point.
        let (chunk, delay) = {
            let mut rng = rand::rng();
            let chunk = rng.random_range(chunk_lo..=chunk_hi).min(remaining);
            let delay = rng.random_range(min_delay_ms..=max_delay_ms.max(min_delay_ms));
            (chunk, delay)
        };

        if !write(
            &mut client,
            &body[pos..pos + chunk],
            write_timeout_secs,
            &shutdown,
        )
        .await
        {
            break;
        }
        pos += chunk;
        sent += chunk as u64;

        if !sleep(Duration::from_millis(delay), &shutdown).await {
            break;
        }
    }

    let _ = client.shutdown().await;
    sent
}

/// Hold an SSH client by periodically sending harmless, invalid banner lines.
pub async fn ssh(
    mut client: TcpStream,
    min_delay_ms: u64,
    max_delay_ms: u64,
    max_secs: u64,
    line_length: usize,
    write_timeout_secs: u64,
    shutdown: CancellationToken,
) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(max_secs);
    let mut sent = 0;
    while Instant::now() < deadline {
        let (line, delay) = {
            let mut rng = rand::rng();
            let len = rng.random_range(1..=line_length);
            let mut line = Vec::with_capacity(len + 1);
            for _ in 0..len {
                line.push(rng.random_range(0x20_u8..=0x7e));
            }
            // A line beginning `SSH-` is the protocol version string: the peer
            // would take it as the banner's end and escape the trap. The RFC
            // lets the server send any number of other lines first, so just
            // make sure we never accidentally emit the terminator.
            if line.starts_with(b"SSH-") {
                line[0] = b'x';
            }
            line.push(b'\n');
            let delay = rng.random_range(min_delay_ms..=max_delay_ms.max(min_delay_ms));
            (line, delay)
        };
        if !write(&mut client, &line, write_timeout_secs, &shutdown).await
            || !sleep(Duration::from_millis(delay), &shutdown).await
        {
            break;
        }
        sent += line.len() as u64;
    }
    let _ = client.shutdown().await;
    sent
}

async fn write(
    client: &mut TcpStream,
    bytes: &[u8],
    write_timeout_secs: u64,
    shutdown: &CancellationToken,
) -> bool {
    tokio::select! {
        () = shutdown.cancelled() => false,
        result = timeout(Duration::from_secs(write_timeout_secs), async {
            client.write_all(bytes).await?;
            client.flush().await
        }) => matches!(result, Ok(Ok(()))),
    }
}

async fn sleep(delay: Duration, shutdown: &CancellationToken) -> bool {
    tokio::select! {
        () = shutdown.cancelled() => false,
        () = tokio::time::sleep(delay) => true,
    }
}

/// First index of `needle` within `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[test]
    fn find_locates_header_terminator() {
        assert_eq!(find(b"abc\r\n\r\nbody", b"\r\n\r\n"), Some(3));
        assert_eq!(find(b"no terminator", b"\r\n\r\n"), None);
    }

    #[tokio::test]
    async fn dribbles_full_body_with_zero_delay() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec();
        let expected = response.clone();

        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            tarpit(sock, response, 0, 0, 5, 1, 4, 5, CancellationToken::new()).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn ssh_lines_are_printable_and_newline_terminated() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            ssh(sock, 0, 0, 1, 8, 1, CancellationToken::new()).await;
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut line = vec![0; 9];
        let n = client.read(&mut line).await.unwrap();
        assert!(n >= 2 && line[n - 1] == b'\n');
        assert!(line[..n - 1].iter().all(|b| (0x20..=0x7e).contains(b)));
    }
}
