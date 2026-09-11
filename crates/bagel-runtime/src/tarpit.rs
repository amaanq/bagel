//! Segment-shaped pacing and the SSH banner tarpit.

use std::time::{
   Duration,
   Instant,
};

use rand::RngExt;
use tokio::{
   io::AsyncWriteExt,
   net::TcpStream,
   time::timeout,
};
use tokio_util::sync::CancellationToken;

/// Chunk sizing and pacing shared by the raw tarpit writer and paced HTTP
/// bodies elsewhere in the workspace.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Dribble {
   pub min_delay_ms: u64,
   pub max_delay_ms: u64,
   pub chunk_min:    usize,
   pub chunk_max:    usize,
}

impl Dribble {
   /// Choose a bounded segment length and delay without holding RNG state
   /// across await points.
   #[must_use]
   pub fn next(&self, remaining: usize) -> (usize, Duration) {
      let lo = self.chunk_min.max(1);
      let hi = self.chunk_max.max(lo);
      let mut rng = rand::rng();
      let chunk = rng.random_range(lo..=hi).min(remaining);
      let delay = rng.random_range(self.min_delay_ms..=self.max_delay_ms.max(self.min_delay_ms));
      (chunk, Duration::from_millis(delay))
   }
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
            line.push(rng.random_range(0x20_u8..=0x7E));
         }
         // Never emit `SSH-`, which terminates the banner exchange.
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

#[cfg(test)]
mod tests {
   use tokio::{
      io::AsyncReadExt,
      net::TcpListener,
   };

   use super::*;

   #[test]
   fn dribble_never_overshoots_and_always_advances() {
      let schedule = Dribble {
         min_delay_ms: 5,
         max_delay_ms: 3,
         chunk_min:    0,
         chunk_max:    10,
      };
      for remaining in 1..=12 {
         let (chunk, delay) = schedule.next(remaining);
         assert!((1..=remaining).contains(&chunk), "{chunk} for {remaining}");
         assert_eq!(delay, Duration::from_millis(5));
      }
      assert_eq!(schedule.next(0).0, 0);
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
      assert!(line[..n - 1].iter().all(|b| (0x20..=0x7E).contains(b)));
   }
}
