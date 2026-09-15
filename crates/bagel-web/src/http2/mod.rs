use std::{
   collections::HashMap,
   fmt::{
      Display,
      Formatter,
      Result as FmtResult,
   },
   io,
   num::NonZeroU32,
   pin::Pin,
   sync::Arc,
   task::{
      Context,
      Poll,
   },
};

use parking_lot::Mutex;
use pin_project_lite::pin_project;
use tokio::io::{
   AsyncRead,
   AsyncWrite,
   ReadBuf,
};

use crate::{
   fingerprint::{
      Capture,
      CaptureError,
   },
   http2::{
      frame::{
         Frame,
         Priority,
         Settings,
      },
      hpack::PseudoHeaderOrder,
   },
};

mod frame;
mod hpack;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const CAPTURE_LIMIT: usize = 65536;

#[derive(Clone, Debug)]
pub struct Http2Fingerprint {
   settings:       Settings,
   window_update:  Option<NonZeroU32>,
   priorities:     Vec<Priority>,
   pseudo_headers: PseudoHeaderOrder,
}

impl Http2Fingerprint {
   #[must_use]
   pub fn policy_fields(&self) -> HashMap<String, String> {
      HashMap::from([
         ("http2_source".to_owned(), "transport".to_owned()),
         ("http2".to_owned(), self.to_string()),
         ("http2_settings".to_owned(), self.settings.to_string()),
         ("http2_window_update".to_owned(), self.window_update_text()),
         ("http2_priority".to_owned(), self.priority_text()),
         (
            "http2_pseudo_headers".to_owned(),
            self.pseudo_headers.to_string(),
         ),
      ])
   }

   fn window_update_text(&self) -> String {
      self
         .window_update
         .map_or_else(|| "00".to_owned(), |value| value.to_string())
   }

   fn priority_text(&self) -> String {
      if self.priorities.is_empty() {
         return "0".to_owned();
      }
      self
         .priorities
         .iter()
         .map(ToString::to_string)
         .collect::<Vec<_>>()
         .join(",")
   }
}

impl Display for Http2Fingerprint {
   #[expect(
      clippy::renamed_function_params,
      reason = "formatter keeps the argument name descriptive"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
      write!(
         formatter,
         "{}|{}|{}|{}",
         self.settings,
         self.window_update_text(),
         self.priority_text(),
         self.pseudo_headers
      )
   }
}

pin_project! {
   pub struct FingerprintStream<Stream> {
      #[pin]
      inner: Stream,
      observer: Option<Observer>,
      fingerprint: Arc<Mutex<Capture<Http2Fingerprint>>>,
   }
}

impl<Stream> FingerprintStream<Stream> {
   pub fn new(inner: Stream) -> Self {
      Self {
         inner,
         observer: Some(Observer::default()),
         fingerprint: Arc::new(Mutex::new(Capture::Failed(CaptureError::Incomplete))),
      }
   }

   pub fn fingerprint(&self) -> Arc<Mutex<Capture<Http2Fingerprint>>> {
      Arc::clone(&self.fingerprint)
   }
}

impl<Stream: AsyncRead> AsyncRead for FingerprintStream<Stream> {
   fn poll_read(
      self: Pin<&mut Self>,
      cx: &mut Context<'_>,
      buf: &mut ReadBuf<'_>,
   ) -> Poll<io::Result<()>> {
      let projected = self.project();
      let filled = buf.filled().len();
      let result = projected.inner.poll_read(cx, buf);
      if let Some(observer) = projected.observer {
         let incoming = &buf.filled()[filled..];
         if !incoming.is_empty() {
            match observer.feed(incoming) {
               Ok(Some(capture)) => {
                  *projected.fingerprint.lock() = capture;
                  *projected.observer = None;
               },
               Err(error) => {
                  *projected.fingerprint.lock() = Capture::Failed(error);
                  *projected.observer = None;
               },
               Ok(None) => {},
            }
         }
      }
      result
   }
}

impl<Stream: AsyncWrite> AsyncWrite for FingerprintStream<Stream> {
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

   fn is_write_vectored(&self) -> bool {
      self.inner.is_write_vectored()
   }

   fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      self.project().inner.poll_flush(cx)
   }

   fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      self.project().inner.poll_shutdown(cx)
   }
}

#[derive(Default)]
struct Observer {
   buffer:   Vec<u8>,
   position: usize,
   frames:   usize,
   capture:  Option<ConnectionCapture>,
}

impl Observer {
   fn feed(&mut self, incoming: &[u8]) -> Result<Option<Capture<Http2Fingerprint>>, CaptureError> {
      let available = (CAPTURE_LIMIT - self.buffer.len()).min(incoming.len());
      self.buffer.extend_from_slice(&incoming[..available]);
      if self.position == 0 {
         let prefix = &self.buffer[..self.buffer.len().min(PREFACE.len())];
         if !PREFACE.starts_with(prefix) {
            return Ok(Some(Capture::Unavailable));
         }
         if self.buffer.len() < PREFACE.len() {
            return Ok(None);
         }
         self.position = PREFACE.len();
      }
      while let Some((frame, consumed)) = Frame::decode(&self.buffer[self.position..])? {
         if self.frames >= 128 {
            return Err(CaptureError::Limited);
         }
         self.frames += 1;
         self.position += consumed;
         let Some(capture) = &mut self.capture else {
            let Frame::Settings(settings) = frame else {
               return Err(CaptureError::Invalid);
            };
            self.capture = Some(ConnectionCapture::new(settings));
            continue;
         };
         if let Some(pseudo_headers) = capture.frame(frame)? {
            let completed = self.capture.take().expect("capture started with SETTINGS");
            let fingerprint = Http2Fingerprint {
               settings: completed.settings,
               window_update: completed.window_update,
               priorities: completed.priorities,
               pseudo_headers,
            };
            if fingerprint.to_string().len() > 4096 {
               return Err(CaptureError::Limited);
            }
            return Ok(Some(Capture::Complete(fingerprint)));
         }
      }
      if self.buffer.len() == CAPTURE_LIMIT {
         return Err(CaptureError::Limited);
      }
      Ok(None)
   }
}

struct ConnectionCapture {
   settings:      Settings,
   window_update: Option<NonZeroU32>,
   priorities:    Vec<Priority>,
   headers:       HeaderBlock,
}

enum HeaderBlock {
   Pending,
   Continuing {
      stream:  NonZeroU32,
      encoded: Vec<u8>,
   },
}

impl ConnectionCapture {
   const fn new(settings: Settings) -> Self {
      Self {
         settings,
         window_update: None,
         priorities: Vec::new(),
         headers: HeaderBlock::Pending,
      }
   }

   fn frame(&mut self, frame: Frame<'_>) -> Result<Option<PseudoHeaderOrder>, CaptureError> {
      match (&mut self.headers, frame) {
         (HeaderBlock::Pending, Frame::Headers(fragment)) => {
            if fragment.is_complete() {
               return PseudoHeaderOrder::try_from(fragment.block()).map(Some);
            }
            self.headers = HeaderBlock::Continuing {
               stream:  fragment.stream(),
               encoded: fragment.block().to_vec(),
            };
         },
         (HeaderBlock::Continuing { stream, encoded }, Frame::Continuation(fragment)) => {
            if *stream != fragment.stream() {
               return Err(CaptureError::Invalid);
            }
            encoded.extend_from_slice(fragment.block());
            if fragment.is_complete() {
               return PseudoHeaderOrder::try_from(encoded.as_slice()).map(Some);
            }
         },
         (HeaderBlock::Pending, Frame::WindowUpdate { stream, increment }) => {
            if stream == 0 {
               self.window_update.get_or_insert(increment);
            }
         },
         (HeaderBlock::Pending, Frame::Priority(priority)) => self.priorities.push(priority),
         (HeaderBlock::Pending, Frame::Settings(_) | Frame::SettingsAck | Frame::Other) => {},
         (HeaderBlock::Pending, Frame::Continuation(_)) | (HeaderBlock::Continuing { .. }, _) => {
            return Err(CaptureError::Invalid);
         },
      }
      Ok(None)
   }
}
