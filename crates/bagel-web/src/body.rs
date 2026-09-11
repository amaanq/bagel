//! The single body type every request and response in the data plane carries,
//! and the response shapes the handlers build from it.

use std::{
   future::Future as _,
   io,
   pin::Pin,
   task::{
      Context,
      Poll,
   },
   time::Duration,
};

use bytes::Bytes;
use http::{
   HeaderValue,
   StatusCode,
   header,
};
use http_body::{
   Body as HttpBody,
   Frame,
   SizeHint,
};
use http_body_util::{
   BodyExt as _,
   Empty,
   Full,
   combinators::UnsyncBoxBody,
};
use pin_project_lite::pin_project;
use tokio::time::{
   Instant,
   Sleep,
   sleep,
};

pub type BodyError = Box<dyn std::error::Error + Send + Sync>;

/// Request and response aliases for the default body.
pub type Request<T = Body> = http::Request<T>;
pub type Response<T = Body> = http::Response<T>;

const BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const BODY_TOTAL_TIMEOUT: Duration = Duration::from_mins(5);

pin_project! {
   pub struct TimeoutBody<B> {
      #[pin]
      inner: B,
      #[pin]
      timer: Sleep,
      timeout: Duration,
      deadline: Instant,
   }
}

impl<B> TimeoutBody<B> {
   fn new(inner: B, timeout: Duration) -> Self {
      Self {
         inner,
         timer: sleep(timeout),
         timeout,
         deadline: Instant::now() + BODY_TOTAL_TIMEOUT,
      }
   }
}

impl<B> HttpBody for TimeoutBody<B>
where
   B: HttpBody<Data = Bytes>,
   B::Error: Into<BodyError>,
{
   type Data = Bytes;
   type Error = BodyError;

   fn poll_frame(
      self: Pin<&mut Self>,
      cx: &mut Context<'_>,
   ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
      let mut this = self.project();
      if Instant::now() >= *this.deadline {
         return Poll::Ready(Some(Err(
            io::Error::new(io::ErrorKind::TimedOut, "body total timeout").into(),
         )));
      }
      match this.inner.as_mut().poll_frame(cx) {
         Poll::Ready(Some(Ok(frame))) => {
            this.timer.reset(Instant::now() + *this.timeout);
            Poll::Ready(Some(Ok(frame)))
         },
         Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error.into()))),
         Poll::Ready(None) => Poll::Ready(None),
         Poll::Pending => {
            if this.timer.as_mut().poll(cx).is_ready() {
               Poll::Ready(Some(Err(
                  io::Error::new(io::ErrorKind::TimedOut, "body idle timeout").into(),
               )))
            } else {
               Poll::Pending
            }
         },
      }
   }

   fn is_end_stream(&self) -> bool {
      self.inner.is_end_stream()
   }

   fn size_hint(&self) -> SizeHint {
      self.inner.size_hint()
   }
}

/// Erased response body shared by upstream and generated responses.
pub struct Body(UnsyncBoxBody<Bytes, BodyError>);

impl Body {
   #[must_use]
   pub fn empty() -> Self {
      Self::new(Empty::<Bytes>::new())
   }

   pub fn new<B>(body: B) -> Self
   where
      B: HttpBody<Data = Bytes> + Send + 'static,
      B::Error: Into<BodyError>,
   {
      Self(body.map_err(Into::into).boxed_unsync())
   }

   pub fn with_idle_timeout<B>(body: B) -> Self
   where
      B: HttpBody<Data = Bytes> + Send + 'static,
      B::Error: Into<BodyError>,
   {
      Self::new(TimeoutBody::new(body, BODY_IDLE_TIMEOUT))
   }
}

impl Default for Body {
   fn default() -> Self {
      Self::empty()
   }
}

impl From<Bytes> for Body {
   fn from(bytes: Bytes) -> Self {
      Self::new(Full::new(bytes))
   }
}

impl From<String> for Body {
   fn from(text: String) -> Self {
      Self::from(Bytes::from(text))
   }
}

impl From<&'static str> for Body {
   fn from(text: &'static str) -> Self {
      Self::from(Bytes::from_static(text.as_bytes()))
   }
}

impl From<Vec<u8>> for Body {
   fn from(bytes: Vec<u8>) -> Self {
      Self::from(Bytes::from(bytes))
   }
}

impl HttpBody for Body {
   type Data = Bytes;
   type Error = BodyError;

   fn poll_frame(
      mut self: Pin<&mut Self>,
      cx: &mut Context<'_>,
   ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
      Pin::new(&mut self.0).poll_frame(cx)
   }

   fn is_end_stream(&self) -> bool {
      self.0.is_end_stream()
   }

   /// Preserve the exact size hint so Hyper can emit `Content-Length`.
   fn size_hint(&self) -> SizeHint {
      self.0.size_hint()
   }
}

#[must_use]
pub fn text(status: StatusCode, body: &'static str) -> Response {
   with_type(status, "text/plain; charset=utf-8", Body::from(body))
}

#[must_use]
pub fn html(status: StatusCode, body: String) -> Response {
   with_type(status, "text/html; charset=utf-8", Body::from(body))
}

/// A bare status line, carrying neither a body nor a content type.
#[must_use]
pub fn status(status: StatusCode) -> Response {
   let mut resp = Response::new(Body::empty());
   *resp.status_mut() = status;
   resp
}

fn with_type(code: StatusCode, content_type: &'static str, body: Body) -> Response {
   let mut resp = Response::new(body);
   *resp.status_mut() = code;
   resp
      .headers_mut()
      .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
   resp
}
