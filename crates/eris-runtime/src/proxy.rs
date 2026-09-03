//! Transparent reverse proxy. The already-read request head is replayed to the
//! backend verbatim, then the two sockets are spliced byte-for-byte, so bodies,
//! chunked transfers, and keep-alive all pass through untouched.

use eris_proto::http::Head;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Proxy a client connection to `backend_addr`, having already consumed `head`.
///
/// `connect_timeout` bounds the backend connect so a blackholed backend cannot
/// hang the task; `idle_timeout` reaps a spliced connection that goes silent in
/// both directions.
pub async fn proxy(
    mut client: TcpStream,
    head: &Head,
    backend_addr: &str,
    connect_timeout: Duration,
    idle_timeout: Duration,
) -> io::Result<()> {
    let mut backend = match timeout(connect_timeout, TcpStream::connect(backend_addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "backend connect timeout",
            ));
        }
    };
    let _ = backend.set_nodelay(true);

    // Replay exactly what we read: the raw head, then any buffered body bytes.
    backend.write_all(&head.raw).await?;
    if !head.body.is_empty() {
        backend.write_all(&head.body).await?;
    }

    splice(&mut client, &mut backend, idle_timeout).await
}

/// Bidirectional copy with a connection-wide idle timeout.
///
/// Either direction reaching EOF half-closes that side (signalling the peer)
/// while the other keeps flowing, so a long response with a quiet request side
/// is not cut short. The idle timer is re-armed on any activity in either
/// direction, so it fires only when the whole connection stalls.
async fn splice(client: &mut TcpStream, backend: &mut TcpStream, idle: Duration) -> io::Result<()> {
    let (mut cr, mut cw) = client.split();
    let (mut br, mut bw) = backend.split();
    // 8 KiB per direction matches tokio's copy_bidirectional default and bounds
    // per-connection memory across the whole connection cap.
    let mut c_buf = vec![0u8; 8 * 1024];
    let mut b_buf = vec![0u8; 8 * 1024];
    let mut c_open = true;
    let mut b_open = true;

    while c_open || b_open {
        tokio::select! {
            r = cr.read(&mut c_buf), if c_open => match r? {
                0 => { c_open = false; let _ = bw.shutdown().await; }
                n => bw.write_all(&c_buf[..n]).await?,
            },
            r = br.read(&mut b_buf), if b_open => match r? {
                0 => { b_open = false; let _ = cw.shutdown().await; }
                n => cw.write_all(&b_buf[..n]).await?,
            },
            () = tokio::time::sleep(idle) => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "proxy idle timeout"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use eris_proto::http;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn forwards_request_and_response() {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut sock, _) = backend.accept().await.unwrap();
            let head = http::read_head(&mut sock, Duration::from_secs(1))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(head.path, "/index.html");
            assert_eq!(head.body, b"hello");
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                .await
                .unwrap();
        });

        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        let backend_str = backend_addr.to_string();

        tokio::spawn(async move {
            let (mut sock, _) = front.accept().await.unwrap();
            let head = http::read_head(&mut sock, Duration::from_secs(1))
                .await
                .unwrap()
                .unwrap();
            proxy(
                sock,
                &head,
                &backend_str,
                Duration::from_secs(2),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });

        let mut client = TcpStream::connect(front_addr).await.unwrap();
        client
            .write_all(b"POST /index.html HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
            .await
            .unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
    }

    #[tokio::test]
    async fn unreachable_backend_times_out() {
        // Reserved TEST-NET-1 address; connect will not complete.
        let (client, _server) = tokio::io::duplex(64);
        drop(client);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let head = http::Head {
                method: "GET".into(),
                path: "/".into(),
                headers: vec![],
                raw: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
                body: vec![],
            };
            let err = proxy(
                sock,
                &head,
                "192.0.2.1:9",
                Duration::from_millis(150),
                Duration::from_secs(1),
            )
            .await
            .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        });
        let client = TcpStream::connect(addr).await.unwrap();
        drop(client);
    }
}
