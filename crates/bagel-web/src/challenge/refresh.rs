use std::collections::BTreeMap;

use http::{
   StatusCode,
   header,
};
use maud::{
   PreEscaped,
   html,
};

use super::{
   types::{
      ChallengeContext,
      IssueResult,
      challenge_page,
      chrome,
   },
   url,
};
use crate::{
   body::{
      Body,
      Response,
   },
   template::{
      self,
      Theme,
      Widget,
   },
};

/// How the refresh challenge delivers the redirect.
#[derive(Clone, Copy)]
pub enum RefreshMode {
   /// HTTP Refresh header.
   Header,
   /// `<meta http-equiv="refresh" content="0;url=...">` tag.
   Meta,
   /// JavaScript `window.location.href = '...'`.
   Javascript,
}

/// Refresh challenge: redirects the client via header, meta tag, or JS.
/// Proves the client can follow redirects and re-send with cookies.
#[derive(Clone)]
pub struct RefreshChallenge {
   pub mode: RefreshMode,
}

impl RefreshChallenge {
   pub fn issue(&self, ctx: &ChallengeContext<'_>, theme: Theme, http_code: u16) -> IssueResult {
      let verify = url::verify_url(
         ctx.challenge_name,
         &ctx.key_hex,
         &ctx.request_uri.to_string(),
      );

      let extra_meta: Vec<BTreeMap<String, String>> = match self.mode {
         RefreshMode::Meta => {
            vec![BTreeMap::from([
               ("http-equiv".to_owned(), "refresh".to_owned()),
               ("content".to_owned(), format!("0;url={verify}")),
            ])]
         },
         RefreshMode::Header | RefreshMode::Javascript => Vec::new(),
      };

      let extra = match self.mode {
         // `verify_url` escapes script-breaking characters.
         RefreshMode::Javascript => {
            html! {
               script { (PreEscaped(format!("window.location.href='{verify}';"))) }
            }
         },
         RefreshMode::Header | RefreshMode::Meta => html! {},
      };

      let chrome = chrome(ctx);
      let widget = Widget::card(template::card(&chrome, &extra));
      let page = challenge_page(ctx, &extra_meta, chrome.title, widget);
      let body = template::render_document(theme, &page);

      let status = StatusCode::from_u16(http_code).unwrap_or(StatusCode::IM_A_TEAPOT);

      let mut builder = Response::builder()
         .status(status)
         .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
         .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate");

      if matches!(self.mode, RefreshMode::Header) {
         builder = builder.header("Refresh", format!("0; url={verify}"));
      }

      IssueResult::Response(builder.body(Body::from(body)).unwrap())
   }
}
