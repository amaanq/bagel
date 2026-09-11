use http::{
   StatusCode,
   header,
};

use super::{
   types::{
      ChallengeContext,
      IssueResult,
   },
   url,
};
use crate::body::{
   Body,
   Response,
};

/// Issues a token cookie and redirects, so the client proves only that it can
/// store a cookie and follow a redirect.
#[derive(Clone)]
pub struct CookieChallenge;

impl CookieChallenge {
   /// Issue: immediately mark as passed, return a 307 redirect with token in
   /// query. The verify endpoint will set the cookie and redirect back.
   pub fn issue(&self, ctx: &ChallengeContext<'_>) -> IssueResult {
      let redirect = url::redirect_url(ctx.request_uri, ctx.challenge_name, &ctx.key_hex);

      let resp = Response::builder()
         .status(StatusCode::TEMPORARY_REDIRECT)
         .header(header::LOCATION, &redirect)
         .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
         .body(Body::empty())
         .unwrap();

      IssueResult::Response(resp)
   }
}
