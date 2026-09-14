use bagel_solver::codec::pack_handoff;
use data_encoding::BASE64URL_NOPAD;
use http::{
   StatusCode,
   header,
};
use maud::html;
use ring::rand::{
   SecureRandom as _,
   SystemRandom,
};

use super::types::{
   ChallengeContext,
   ChallengeKey,
   IssueResult,
   challenge_page,
   chrome,
};
use crate::{
   body::{
      Body,
      Response,
   },
   config::CustomTheme,
   template::{
      self,
      LoaderData,
      Presentation,
      Theme,
      Widget,
   },
};

const RUNTIME: &str = "/__bagel/static/runtime.mjs";

/// SHA-256 proof-of-work challenge.
/// The client must find a nonce such that SHA-256(key || nonce) has
/// `difficulty` leading zero nibbles.
#[derive(Clone)]
pub struct PowSha256Challenge {
   pub difficulty: u32,
   /// How the solver appears when spliced into a proxied page.
   pub embed:      Presentation,
}

impl PowSha256Challenge {
   /// `background` settles in place. Embeds qualify, while interstitials
   /// reload.
   fn widget(
      &self,
      ctx: &ChallengeContext<'_>,
      presentation: Presentation,
      background: bool,
   ) -> Widget {
      let mut iv = [0_u8; 4];
      let _ = SystemRandom::new().fill(&mut iv);
      let difficulty = u8::try_from(self.difficulty).expect("difficulty is validated to 1..=64");
      let loader = LoaderData {
         payload: BASE64URL_NOPAD.encode(&pack_handoff(iv, ctx.challenge_key, difficulty)),
         verify_url: format!("/__bagel/{}/verify", ctx.challenge_name),
         background,
      };

      let widget = match presentation {
         Presentation::Hidden => Widget::hidden(),
         Presentation::Card => {
            Widget::card(template::card(
               &chrome(ctx),
               &html! { p class="bagel-status" role="status" aria-live="polite" { "Solving challenge..." } },
            ))
         },
      };

      widget.driven_by(RUNTIME, loader)
   }

   /// Renders the challenge page with the solver embedded, so the work runs
   /// in the client's JS engine rather than costing us anything.
   pub fn issue(
      &self,
      ctx: &ChallengeContext<'_>,
      theme: Theme,
      custom: &CustomTheme,
      http_code: u16,
   ) -> IssueResult {
      let chrome = chrome(ctx);
      let widget = self.widget(ctx, Presentation::Card, false);
      let page = challenge_page(ctx, &[], chrome.title, widget);
      let body = template::render_document(theme, custom, &page);

      let status = StatusCode::from_u16(http_code).unwrap_or(StatusCode::IM_A_TEAPOT);

      let resp = Response::builder()
         .status(status)
         .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
         .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
         .body(Body::from(body))
         .unwrap();

      IssueResult::Response(resp)
   }

   /// Build the solver for background delivery, spliced into the proxied
   /// origin page instead of blocking on an interstitial.
   #[must_use]
   pub fn embed_widget(&self, ctx: &ChallengeContext<'_>) -> Widget {
      self.widget(ctx, self.embed, true)
   }

   /// Verify a `PoW` solution from a nonce integer (big-endian, matching JS
   /// client).
   #[must_use]
   pub fn verify_nonce(&self, challenge_key: &ChallengeKey, nonce: u64) -> bool {
      let nonce_bytes = nonce.to_be_bytes();
      let mut buf = Vec::with_capacity(32 + 8);
      buf.extend_from_slice(challenge_key);
      buf.extend_from_slice(&nonce_bytes);
      let hash = ring::digest::digest(&ring::digest::SHA256, &buf);
      check_leading_zeros(hash.as_ref(), self.difficulty)
   }
}

/// Check that a hash has at least `required` leading zero nibbles (half-bytes).
fn check_leading_zeros(hash: &[u8], required: u32) -> bool {
   let mut zeros = 0_u32;
   for &byte in hash {
      if byte == 0 {
         zeros += 2;
      } else if byte < 0x10 {
         zeros += 1;
         break;
      } else {
         break;
      }
      if zeros >= required {
         return true;
      }
   }
   zeros >= required
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn pow_verify_big_endian() {
      let pow = PowSha256Challenge {
         difficulty: 1,
         embed:      Presentation::Hidden,
      };
      let key = [0u8; 32];

      // Brute-force a valid nonce for difficulty=1 using big-endian (matching
      // JS)
      let found = (0u64..100_000).any(|nonce| pow.verify_nonce(&key, nonce));
      assert!(found, "could not find valid nonce");
   }
}
