pub mod cookie;
pub mod dnsbl;
pub mod key;
pub mod pow;
pub mod refresh;
pub mod token;
pub mod types;
pub mod url;

use std::{
   collections::HashMap,
   net::IpAddr,
   time::Duration,
};

use bagel_solver::{
   codec::Kind,
   scratch,
};
use http::header;
use ring::signature::Ed25519KeyPair;

use self::{
   cookie::CookieChallenge,
   dnsbl::DnsblChallenge,
   pow::PowChallenge,
   refresh::{
      RefreshChallenge,
      RefreshMode,
   },
   token::{
      Token,
      TokenChallenge,
      cookie_name,
      derive_cookie_key,
      format_http_date,
      open_token,
      seal_token,
      unix_timestamp,
   },
   types::{
      ChallengeClass,
      ChallengeContext,
      ChallengeKey,
      IssueResult,
   },
};
use crate::{
   config::{
      CustomTheme,
      policy::ChallengeConfig,
   },
   error,
   ip_network_prefix,
   template::{
      Presentation,
      Theme,
      Widget,
   },
};

/// A registered challenge instance.
pub struct ChallengeRegistration {
   pub class:    ChallengeClass,
   pub duration: Duration,
   pub runtime:  ChallengeRuntime,
}

const MAX_CHALLENGE_DURATION_SECS: u64 = 365 * 24 * 60 * 60;

pub enum ChallengeRuntime {
   Cookie(CookieChallenge),
   Refresh(RefreshChallenge),
   Dnsbl(DnsblChallenge),
   Pow(PowChallenge),
}

/// How a challenge is redeemed at the verify endpoint.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Redemption {
   /// Following the redirect while carrying the key is the whole proof, so
   /// the key is never shown to the client before it is spent.
   Redirect,
   /// The page publishes the key, so the key proves nothing on its own and a
   /// solution must be posted against it.
   Solution,
   /// Settled server-side and never redeemed by the client.
   None,
}

impl ChallengeRuntime {
   #[must_use]
   pub const fn supports_background(&self) -> bool {
      matches!(self, Self::Pow(_))
   }

   #[must_use]
   pub const fn redemption(&self) -> Redemption {
      match self {
         Self::Cookie(_) | Self::Refresh(_) => Redemption::Redirect,
         Self::Pow(_) => Redemption::Solution,
         Self::Dnsbl(_) => Redemption::None,
      }
   }

   /// Issue a challenge. Async because DNSBL needs I/O.
   pub async fn issue(
      &self,
      ctx: &ChallengeContext<'_>,
      theme: Theme,
      custom: &CustomTheme,
      http_code: u16,
   ) -> IssueResult {
      match self {
         Self::Cookie(ch) => ch.issue(ctx),
         Self::Refresh(ch) => ch.issue(ctx, theme, custom, http_code),
         Self::Dnsbl(ch) => ch.issue(ctx).await,
         Self::Pow(ch) => ch.issue(ctx, theme, custom, http_code),
      }
   }

   /// The widget to splice into the proxied page for check-mode delivery, for
   /// runtimes that can prove themselves without an interstitial.
   #[must_use]
   pub fn embed_widget(&self, ctx: &ChallengeContext<'_>) -> Option<Widget> {
      match self {
         Self::Pow(ch) => Some(ch.embed_widget(ctx)),
         _ => None,
      }
   }
}

#[derive(Default)]
pub struct ChallengeRegistry {
   pub challenges: HashMap<String, ChallengeRegistration>,
}

impl ChallengeRegistry {
   pub fn build(configs: &[ChallengeConfig]) -> error::Result<Self> {
      let mut challenges = HashMap::new();

      for cfg in configs {
         if cfg.name.is_empty() || cfg.name.contains('/') {
            return Err(error::Error::Config(format!(
               "challenge name {:?} must be non-empty and contain no '/'",
               cfg.name
            )));
         }
         if !(1..=MAX_CHALLENGE_DURATION_SECS).contains(&cfg.duration_secs) {
            return Err(error::Error::Config(format!(
               "challenge '{}': duration must be between 1 second and 365 days",
               cfg.name
            )));
         }
         let duration = Duration::from_secs(cfg.duration_secs);
         let (class, runtime) = match cfg.runtime.as_str() {
            "cookie" => {
               (
                  ChallengeClass::Blocking,
                  ChallengeRuntime::Cookie(CookieChallenge),
               )
            },
            "refresh" => {
               let mode = match cfg
                  .parameters
                  .get("refresh-via")
                  .map_or("meta", String::as_str)
               {
                  "header" => RefreshMode::Header,
                  "javascript" | "js" => RefreshMode::Javascript,
                  "meta" => RefreshMode::Meta,
                  other => {
                     return Err(error::Error::Config(format!(
                        "challenge '{}': unknown refresh-via {other:?}, expected \"meta\", \
                         \"header\", or \"javascript\"",
                        cfg.name
                     )));
                  },
               };
               (
                  ChallengeClass::Blocking,
                  ChallengeRuntime::Refresh(RefreshChallenge { mode }),
               )
            },
            "dnsbl" => {
               let host = cfg
                  .parameters
                  .get("dnsbl-host")
                  .cloned()
                  .unwrap_or_else(|| "dnsbl.dronebl.org".to_owned());
               let ttl_secs = cfg.parameters.get("dnsbl-ttl").map_or(Ok(3600), |value| {
                  value.parse::<u64>().map_err(|_| {
                     error::Error::Config(format!(
                        "challenge '{}': dnsbl-ttl must be an integer",
                        cfg.name
                     ))
                  })
               })?;
               (
                  ChallengeClass::Transparent,
                  ChallengeRuntime::Dnsbl(DnsblChallenge::new(host, Duration::from_secs(ttl_secs))),
               )
            },
            runtime @ ("pow-sha256" | "pow-scratch") => {
               let (kind, default_difficulty) = if runtime == "pow-sha256" {
                  (Kind::Sha256, 4)
               } else {
                  (Kind::Scratch, 12)
               };
               let difficulty =
                  cfg.parameters
                     .get("difficulty")
                     .map_or(Ok(default_difficulty), |value| {
                        value.parse::<u32>().map_err(|_| {
                           error::Error::Config(format!(
                              "challenge '{}': difficulty must be an integer",
                              cfg.name
                           ))
                        })
                     })?;
               let blocks_log2 = match kind {
                  Kind::Sha256 => 0,
                  Kind::Scratch => {
                     let kib = cfg.parameters.get("memory").map_or(Ok(256), |value| {
                        value.parse::<u32>().map_err(|_| {
                           error::Error::Config(format!(
                              "challenge '{}': memory must be an integer in KiB",
                              cfg.name
                           ))
                        })
                     })?;
                     let blocks = kib
                        .checked_mul(32)
                        .filter(|blocks| blocks.is_power_of_two());
                     let log2 = blocks
                        .map(u32::trailing_zeros)
                        .and_then(|log2| u8::try_from(log2).ok());
                     match log2 {
                        Some(log2)
                           if (scratch::MIN_BLOCKS_LOG2..=scratch::MAX_BLOCKS_LOG2)
                              .contains(&log2) =>
                        {
                           log2
                        },
                        _ => {
                           return Err(error::Error::Config(format!(
                              "challenge '{}': memory must be a power of two between {} and {} KiB",
                              cfg.name,
                              (1_u32 << scratch::MIN_BLOCKS_LOG2) / 32,
                              (1_u32 << scratch::MAX_BLOCKS_LOG2) / 32
                           )));
                        },
                     }
                  },
               };
               let embed = match cfg.parameters.get("embed").map_or("hidden", String::as_str) {
                  "card" => Presentation::Card,
                  "hidden" => Presentation::Hidden,
                  other => {
                     return Err(error::Error::Config(format!(
                        "challenge '{}': unknown embed {other:?}, expected \"hidden\" or \"card\"",
                        cfg.name
                     )));
                  },
               };
               let pow = PowChallenge {
                  kind,
                  difficulty,
                  blocks_log2,
                  embed,
               };
               if !pow.difficulty_range().contains(&difficulty) {
                  return Err(error::Error::Config(format!(
                     "challenge '{}': difficulty must be between {} and {}",
                     cfg.name,
                     pow.difficulty_range().start(),
                     pow.difficulty_range().end()
                  )));
               }
               (ChallengeClass::Blocking, ChallengeRuntime::Pow(pow))
            },
            other => {
               return Err(error::Error::Config(format!(
                  "challenge '{}': unknown runtime '{other}'",
                  cfg.name
               )));
            },
         };

         if challenges
            .insert(cfg.name.clone(), ChallengeRegistration {
               class,
               duration,
               runtime,
            })
            .is_some()
         {
            return Err(error::Error::Config(format!(
               "duplicate challenge name '{}'",
               cfg.name
            )));
         }
      }

      Ok(Self { challenges })
   }

   #[must_use]
   pub fn get(&self, name: &str) -> Option<&ChallengeRegistration> {
      self.challenges.get(name)
   }
}

pub struct RequestChallengeState {
   pub token:      Option<Token>,
   pub modified:   bool,
   /// Background challenge fragments to inject into the proxied response.
   pub injections: Vec<String>,
}

impl RequestChallengeState {
   pub fn from_headers(
      headers: &header::HeaderMap,
      host: &str,
      public_key_bytes: &[u8],
      server_key_bytes: &[u8],
      client_ip: Option<IpAddr>,
   ) -> Self {
      let cname = cookie_name(host);

      let cookie_value = headers
         .get_all(header::COOKIE)
         .iter()
         .filter_map(|hv| hv.to_str().ok())
         .flat_map(|str_val| str_val.split(';'))
         .map(str::trim)
         .find_map(|cookie| {
            let (name, value) = cookie.split_once('=')?;
            (name.trim() == cname).then(|| value.trim().to_owned())
         });

      let network_prefix = client_ip.map(ip_network_prefix).unwrap_or_default();
      let cookie_key = derive_cookie_key(host, &network_prefix, server_key_bytes);

      if let Some(ref value) = cookie_value {
         match open_token(value, public_key_bytes, &cookie_key) {
            Ok(token) => {
               return Self {
                  token:      Some(token),
                  modified:   false,
                  injections: Vec::new(),
               };
            },
            Err(err) => {
               tracing::debug!(error = %err, "failed to open challenge token");
            },
         }
      }

      Self {
         token:      None,
         modified:   false,
         injections: Vec::new(),
      }
   }

   pub fn issue_challenge(&mut self, challenge_name: &str, key: &ChallengeKey, duration: Duration) {
      let now = unix_timestamp();
      let exp = now.saturating_add(duration.as_secs() as i64);

      let tc = TokenChallenge {
         key: key.to_vec(),
         result: Vec::new(),
         level: 0,
         ok: true,
         exp,
         nbf: now,
         iat: now,
      };

      let token = self.token.get_or_insert_with(|| {
         Token {
            state: HashMap::new(),
            exp,
            nbf: now,
            iat: now,
         }
      });

      token.state.insert(challenge_name.to_owned(), tc);
      if token.exp < exp {
         token.exp = exp;
      }

      self.modified = true;
   }

   /// A pass sealed at a higher level than `level` still counts, so a client
   /// that solved the hard variant is not asked again for the easy one.
   #[must_use]
   pub fn is_challenge_passed(
      &self,
      challenge_name: &str,
      expected_key: &ChallengeKey,
      level: u32,
   ) -> bool {
      if let Some(ref token) = self.token
         && let Some(tc) = token.state.get(challenge_name)
      {
         // Check each challenge against its own expiry.
         return tc.ok
            && tc.exp > unix_timestamp()
            && tc.level >= level
            && tc.key.len() == expected_key.len()
            && constant_time_eq::constant_time_eq(&tc.key, expected_key);
      }
      false
   }

   /// Seal the challenge state into a cookie. `host` must be the canonical
   /// host. IP literal hosts omit Domain and get host-only cookies.
   pub fn seal_cookie(
      &self,
      host: &str,
      host_is_ip: bool,
      signing_key: &Ed25519KeyPair,
      server_key_bytes: &[u8],
      client_ip: Option<IpAddr>,
   ) -> Option<String> {
      let token = self.token.as_ref()?;
      if !self.modified {
         return None;
      }

      let network_prefix = client_ip.map(ip_network_prefix).unwrap_or_default();
      let cookie_key = derive_cookie_key(host, &network_prefix, server_key_bytes);
      let cname = cookie_name(host);

      match seal_token(token, signing_key, &cookie_key) {
         Ok(sealed) => {
            let exp_str = format_http_date(token.exp);
            let domain = if host_is_ip {
               String::new()
            } else {
               format!(" Domain={host};")
            };

            Some(format!(
               "{cname}={sealed}; Path=/;{domain} Expires={exp_str}; SameSite=Lax"
            ))
         },
         Err(err) => {
            tracing::error!(error = %err, "failed to seal challenge token");
            None
         },
      }
   }
}
