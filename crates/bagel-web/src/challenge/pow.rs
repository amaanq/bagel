use std::ops::RangeInclusive;

use bagel_solver::{
   codec::{
      Handoff,
      Kind,
      pack_handoff,
   },
   scratch,
   sha256::{
      KeyBlock,
      leading_zero_bits,
   },
};
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

/// A proof-of-work challenge solved by the wasm module. `pow-sha256` counts
/// zero nibbles of one digest, `pow-scratch` counts zero bits after a
/// scratchpad walk.
#[derive(Clone)]
pub struct PowChallenge {
   pub kind:        Kind,
   pub difficulty:  u32,
   pub blocks_log2: u8,
   /// How the solver appears when spliced into a proxied page.
   pub embed:       Presentation,
}

impl PowChallenge {
   /// Difficulties this proof can express.
   #[must_use]
   pub const fn difficulty_range(&self) -> RangeInclusive<u32> {
      match self.kind {
         Kind::Sha256 | Kind::Scratch => 1..=32,
      }
   }

   /// The difficulty a request must prove, after any rule override.
   #[must_use]
   pub fn level(&self, ctx: &ChallengeContext<'_>) -> u32 {
      ctx.difficulty.unwrap_or(self.difficulty)
   }

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
      let handoff = Handoff {
         key:         *ctx.challenge_key,
         kind:        self.kind,
         difficulty:  u8::try_from(self.level(ctx)).expect("difficulty is validated to fit"),
         blocks_log2: self.blocks_log2,
      };
      let loader = LoaderData {
         payload: BASE64URL_NOPAD.encode(&pack_handoff(iv, &handoff)),
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
   /// on the client rather than costing us anything.
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

   /// Check a nonce against the proof at the difficulty the client claims,
   /// which the caller has already bounded to `difficulty_range`.
   #[must_use]
   pub fn verify(&self, challenge_key: &ChallengeKey, nonce: u64, difficulty: u32) -> bool {
      let mut key = KeyBlock::new(challenge_key);
      match self.kind {
         Kind::Sha256 => {
            let mut buf = Vec::with_capacity(32 + 8);
            buf.extend_from_slice(challenge_key);
            buf.extend_from_slice(&nonce.to_be_bytes());
            let hash = ring::digest::digest(&ring::digest::SHA256, &buf);
            let digest: [u8; 32] = hash.as_ref().try_into().expect("sha256 output is 32 bytes");
            leading_zero_bits(&digest, difficulty)
         },
         Kind::Scratch => {
            let mut pad = vec![[0_u8; 32]; 1 << self.blocks_log2];
            scratch::satisfies(&mut pad, &mut key, nonce, self.blocks_log2, difficulty)
         },
      }
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn pow_verify_big_endian() {
      let pow = PowChallenge {
         kind:        Kind::Sha256,
         difficulty:  1,
         blocks_log2: 0,
         embed:       Presentation::Hidden,
      };
      let key = [0u8; 32];

      // Brute-force a valid nonce for difficulty=1 using big-endian (matching
      // JS)
      let found = (0u64..100_000).any(|nonce| pow.verify(&key, nonce, 1));
      assert!(found, "could not find valid nonce");
   }
}
