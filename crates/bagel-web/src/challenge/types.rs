use std::{
   collections::{
      BTreeMap,
      HashMap,
   },
   net::IpAddr,
   sync::LazyLock,
};

use http::Uri;

use crate::body::Response;

/// Challenge key: 32-byte SHA-256 derived from challenge parameters.
pub type ChallengeKey = [u8; 32];

pub enum IssueResult {
   /// Transparent pass from a reputation check.
   Passed,
   /// Transparent fail (DNSBL listed).
   Failed,
   /// Serve this response to the client (challenge page, redirect).
   Response(Response),
   /// Skip this challenge when it lacks the required request context.
   Skip,
}

/// Whether a challenge blocks the response or runs transparently.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ChallengeClass {
   Transparent,
   /// Challenge requires serving a page to the client (e.g. `PoW`, cookie
   /// redirect).
   Blocking,
}

/// Context passed to challenge issue/verify methods.
pub struct ChallengeContext<'a> {
   pub challenge_name: &'a str,
   pub challenge_key:  &'a [u8; 32],
   pub key_hex:        String,
   pub host:           &'a str,
   pub client_ip:      Option<IpAddr>,
   pub request_uri:    &'a Uri,
   pub meta_tags:      Vec<BTreeMap<String, String>>,
   pub link_tags:      Vec<BTreeMap<String, String>>,
   /// Configurable strings from config (title overrides, etc.).
   pub strings:        &'a HashMap<String, String>,
   pub links:          &'a [LinkConfig],
   pub logo:           Option<&'a str>,
   /// Difficulty the issuing rule asked for, over the challenge's own.
   pub difficulty:     Option<u32>,
}

impl<'a> ChallengeContext<'a> {
   pub fn new(
      challenge_name: &'a str,
      challenge_key: &'a [u8; 32],
      host: &'a str,
      client_ip: Option<IpAddr>,
      request_uri: &'a Uri,
   ) -> Self {
      let key_hex = hex_encode(challenge_key);
      Self {
         challenge_name,
         challenge_key,
         key_hex,
         host,
         client_ip,
         request_uri,
         meta_tags: Vec::new(),
         link_tags: Vec::new(),
         strings: &EMPTY_STRINGS,
         links: &[],
         logo: None,
         difficulty: None,
      }
   }
}

static EMPTY_STRINGS: LazyLock<HashMap<String, String>> = LazyLock::new(HashMap::new);

use crate::{
   config::LinkConfig,
   hex_encode,
   template::{
      ChallengePage,
      Chrome,
      Widget,
   },
};

/// Resolve the card chrome from config, falling back to the built-in copy.
#[must_use]
pub fn chrome<'a>(ctx: &'a ChallengeContext<'a>) -> Chrome<'a> {
   Chrome {
      title:   ctx
         .strings
         .get("title-challenge")
         .map_or("Checking your browser...", String::as_str),
      message: ctx.strings.get("message-challenge").map_or(
         "This is an automated check. Please wait a moment.",
         String::as_str,
      ),
      links:   ctx.links,
      logo:    ctx.logo,
   }
}

/// Wrap a widget in the interstitial page, merging the origin's meta and link
/// tags with any the challenge adds.
#[must_use]
pub fn challenge_page<'a>(
   ctx: &'a ChallengeContext<'a>,
   extra_meta: &'a [BTreeMap<String, String>],
   title: &'a str,
   widget: Widget,
) -> ChallengePage<'a> {
   ChallengePage {
      title,
      meta_tags: ctx.meta_tags.iter().chain(extra_meta).collect(),
      link_tags: ctx.link_tags.iter().collect(),
      widget,
   }
}
