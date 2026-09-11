use std::{
   convert::Infallible,
   future::Future as _,
   pin::Pin,
   task::{
      Context,
      Poll,
   },
   time::{
      Duration,
      Instant,
   },
};

use bagel_deception::Page;
use bagel_runtime::tarpit::Dribble;
use bytes::Bytes;
use http::{
   HeaderName,
   HeaderValue,
   StatusCode,
   header,
};
use http_body::{
   Body as HttpBody,
   Frame,
   SizeHint,
};
use tokio::{
   sync::OwnedSemaphorePermit,
   time::Sleep,
};

use crate::body::{
   Body,
   Response,
};

/// A response body paid out in segment sized pieces with tarpit pauses.
pub struct DribbleBody {
   data:     Bytes,
   pos:      usize,
   schedule: Dribble,
   deadline: Instant,
   sleep:    Option<Pin<Box<Sleep>>>,
   _permit:  OwnedSemaphorePermit,
}

impl HttpBody for DribbleBody {
   type Data = Bytes;
   type Error = Infallible;

   fn poll_frame(
      self: Pin<&mut Self>,
      cx: &mut Context<'_>,
   ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
      let this = self.get_mut();
      if this.pos >= this.data.len() || Instant::now() >= this.deadline {
         return Poll::Ready(None);
      }
      if let Some(sleep) = this.sleep.as_mut() {
         match sleep.as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(()) => this.sleep = None,
         }
      }
      let (len, delay) = this.schedule.next(this.data.len() - this.pos);
      let chunk = this.data.slice(this.pos..this.pos + len);
      this.pos += len;
      let remaining = this.deadline.saturating_duration_since(Instant::now());
      this.sleep = Some(Box::pin(tokio::time::sleep(delay.min(remaining))));
      Poll::Ready(Some(Ok(Frame::data(chunk))))
   }

   fn is_end_stream(&self) -> bool {
      self.pos >= self.data.len()
   }

   fn size_hint(&self) -> SizeHint {
      SizeHint::with_exact((self.data.len() - self.pos) as u64)
   }
}

/// Frame a deceptive page as a paced response.
#[must_use]
pub fn response(
   page: Page,
   schedule: Dribble,
   max_secs: u64,
   permit: OwnedSemaphorePermit,
) -> Response {
   let status = StatusCode::from_u16(page.status_code()).unwrap_or(StatusCode::OK);
   let mut builder = Response::builder().status(status);
   for (name, value) in &page.headers {
      if name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("connection") {
         continue;
      }
      if let (Ok(name), Ok(value)) = (
         HeaderName::from_bytes(name.as_bytes()),
         HeaderValue::from_str(value),
      ) {
         builder = builder.header(name, value);
      }
   }
   let data = Bytes::from(page.body);
   let length = data.len();
   let body = DribbleBody {
      data,
      pos: 0,
      schedule,
      deadline: Instant::now() + Duration::from_secs(max_secs),
      sleep: None,
      _permit: permit,
   };
   builder
      .header(header::CONTENT_LENGTH, length)
      .body(Body::new(body))
      .expect("smear response parts are valid")
}
