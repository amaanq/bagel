use std::{
   io,
   pin::Pin,
   task::{
      Context,
      Poll,
   },
};

use pin_project_lite::pin_project;
use tokio::io::{
   AsyncRead,
   AsyncWrite,
   ReadBuf,
};

pin_project! {
    /// An async stream wrapper that captures and replays the first bytes.
    pub struct PeekStream<S> {
        #[pin]
        inner: S,
        buffer: Vec<u8>,
        replay_pos: usize,
        peeked: bool,
    }
}

impl<S> PeekStream<S>
where
   S: AsyncRead + Unpin,
{
   pub fn new(inner: S, capacity: usize) -> Self {
      Self {
         inner,
         buffer: Vec::with_capacity(capacity),
         replay_pos: 0,
         peeked: false,
      }
   }

   /// Reads up to `max_bytes` into the peek buffer without consuming them, so
   /// subsequent reads replay the same bytes.
   pub async fn peek(&mut self, max_bytes: usize) -> io::Result<usize> {
      use tokio::io::AsyncReadExt as _;

      let mut buf = vec![0_u8; max_bytes];
      let n = self.inner.read(&mut buf).await?;
      buf.truncate(n);
      self.buffer = buf;
      self.peeked = true;
      Ok(n)
   }

   /// Read up to `max_bytes` more and append them to the peek buffer, for a
   /// header that arrived split across segments. Returns the bytes added.
   pub async fn peek_more(&mut self, max_bytes: usize) -> io::Result<usize> {
      use tokio::io::AsyncReadExt as _;

      let mut buf = vec![0_u8; max_bytes];
      let n = self.inner.read(&mut buf).await?;
      self.buffer.extend_from_slice(&buf[..n]);
      self.peeked = true;
      Ok(n)
   }

   pub fn peeked_data(&self) -> &[u8] {
      &self.buffer
   }

   /// Advance past the first `n` bytes of the peek buffer.
   /// Used after parsing a PROXY protocol header so that
   /// subsequent reads skip the consumed header bytes.
   pub fn advance(&mut self, n: usize) {
      if n >= self.buffer.len() {
         self.buffer.clear();
      } else {
         self.buffer = self.buffer[n..].to_vec();
      }
      self.replay_pos = 0;
   }
}

impl<S> AsyncRead for PeekStream<S>
where
   S: AsyncRead,
{
   fn poll_read(
      self: Pin<&mut Self>,
      cx: &mut Context<'_>,
      buf: &mut ReadBuf<'_>,
   ) -> Poll<io::Result<()>> {
      let this = self.project();

      if *this.replay_pos < this.buffer.len() {
         let remaining = &this.buffer[*this.replay_pos..];
         let to_copy = remaining.len().min(buf.remaining());
         buf.put_slice(&remaining[..to_copy]);
         *this.replay_pos += to_copy;
         return Poll::Ready(Ok(()));
      }

      this.inner.poll_read(cx, buf)
   }
}

impl<S> AsyncWrite for PeekStream<S>
where
   S: AsyncWrite,
{
   fn poll_write(
      self: Pin<&mut Self>,
      cx: &mut Context<'_>,
      buf: &[u8],
   ) -> Poll<io::Result<usize>> {
      self.project().inner.poll_write(cx, buf)
   }

   fn poll_write_vectored(
      self: Pin<&mut Self>,
      cx: &mut Context<'_>,
      bufs: &[io::IoSlice<'_>],
   ) -> Poll<io::Result<usize>> {
      self.project().inner.poll_write_vectored(cx, bufs)
   }

   fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      self.project().inner.poll_flush(cx)
   }

   fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      self.project().inner.poll_shutdown(cx)
   }
}

#[cfg(test)]
mod tests {
   use tokio::io::AsyncReadExt;

   use super::*;

   #[tokio::test]
   async fn peek_and_replay() {
      let data = b"Hello, World! This is test data.";
      let cursor = io::Cursor::new(data.to_vec());
      let mut stream = PeekStream::new(cursor, 16);

      let n = stream.peek(16).await.unwrap();
      assert!(n > 0);
      assert_eq!(stream.peeked_data(), &data[..n]);

      let mut buf = vec![0u8; 64];
      let read = stream.read(&mut buf).await.unwrap();
      assert_eq!(&buf[..read], &data[..n]); // replayed bytes

      let read2 = stream.read(&mut buf).await.unwrap();
      assert_eq!(&buf[..read2], &data[n..]);
   }
}
