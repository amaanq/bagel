use http::{
   HeaderMap,
   header::{
      HeaderName,
      HeaderValue,
   },
};
use regex::Regex;

use crate::config::policy::RuleSettings;

/// Parsed action attached to a rule.
#[derive(Clone)]
pub enum Action {
   /// Do nothing, evaluate children.
   None,
   /// Proxy to backend, stop processing.
   Pass,
   /// Return HTML error page.
   Deny {
      code: u16,
   },
   /// Return plain text error.
   Block {
      code: u16,
   },
   Code(u16),
   /// RST connection without response.
   Drop,
   /// Serve the named maze instead of the origin.
   Tarpit {
      maze: String,
   },
   /// Serve a deceptive page dribbled out at tarpit pace.
   Smear,
   /// Proxy to a different backend with optional URL rewrite.
   Proxy {
      match_re: Option<Regex>,
      rewrite:  String,
      backend:  String,
   },
   /// Add headers to request/response, then continue.
   Context {
      response_headers: HeaderMap,
      request_headers:  HeaderMap,
   },
   /// Issue challenges, stop if issued or all fail.
   Challenge(ChallengeAction),
   /// Issue challenges, continue regardless.
   Check(ChallengeAction),
   /// Emit an offense record with this kind, then continue.
   Report {
      kind: String,
   },
}

#[derive(Clone)]
pub struct ChallengeAction {
   pub challenges:  Vec<String>,
   pub http_code:   u16,
   pub pass_action: Box<Action>,
   pub fail_action: Box<Action>,
}

impl Action {
   pub const BLOCK: &str = "block";
   pub const CHALLENGE: &str = "challenge";
   pub const CHECK: &str = "check";
   pub const CODE: &str = "code";
   pub const CONTEXT: &str = "context";
   pub const DENY: &str = "deny";
   pub const DROP: &str = "drop";
   pub const NONE: &str = "none";
   pub const PASS: &str = "pass";
   pub const PROXY: &str = "proxy";
   pub const REPORT: &str = "report";
   pub const SMEAR: &str = "smear";
   pub const TARPIT: &str = "tarpit";

   /// Accepts the spellings [`Action::label`] produces, matched
   /// case-insensitively, and draws each variant's parameters from
   /// `settings`.
   pub fn parse(
      action_str: &str,
      settings: &RuleSettings,
      challenges: &[String],
      default_http_code: u16,
   ) -> Result<Self, String> {
      if !action_str.eq_ignore_ascii_case(Self::REPORT) && settings.kind.is_some() {
         return Err("kind is only valid on the report action".into());
      }
      Ok(match action_str.to_lowercase().as_str() {
         Self::NONE => Self::None,
         Self::PASS => Self::Pass,
         Self::DENY => {
            Self::Deny {
               code: settings.http_code.unwrap_or(403),
            }
         },
         Self::BLOCK => {
            Self::Block {
               code: settings.http_code.unwrap_or(403),
            }
         },
         Self::CODE => Self::Code(settings.http_code.unwrap_or(403)),
         Self::DROP => Self::Drop,
         Self::TARPIT => {
            let maze = settings
               .maze
               .clone()
               .filter(|name| !name.is_empty())
               .ok_or("tarpit action requires a maze")?;
            Self::Tarpit { maze }
         },
         Self::SMEAR => {
            if settings
               .maze
               .as_deref()
               .is_some_and(|maze| !maze.is_empty())
               || settings
                  .backend
                  .as_deref()
                  .is_some_and(|backend| !backend.is_empty())
               || settings.match_re.is_some()
               || settings.rewrite.is_some()
            {
               return Err("smear action takes no maze, backend, match, or rewrite".into());
            }
            Self::Smear
         },
         Self::REPORT => {
            let kind = settings
               .kind
               .clone()
               .filter(|name| !name.is_empty())
               .ok_or("report action requires a kind")?;
            if !kind
               .bytes()
               .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
            {
               return Err("report kind must be lowercase ascii, digits, `-` or `_`".into());
            }
            Self::Report { kind }
         },
         Self::PROXY => {
            let backend = settings
               .backend
               .clone()
               .filter(|name| !name.is_empty())
               .ok_or("proxy action requires a backend")?;
            let match_re = settings
               .match_re
               .as_deref()
               .map(Regex::new)
               .transpose()
               .map_err(|err| format!("invalid proxy match regex: {err}"))?;
            if match_re.is_some() != settings.rewrite.is_some() {
               return Err("proxy match and rewrite must be configured together".into());
            }
            Self::Proxy {
               match_re,
               rewrite: settings.rewrite.clone().unwrap_or_default(),
               backend,
            }
         },
         Self::CONTEXT => {
            Self::Context {
               response_headers: parse_headers(&settings.response_headers, "response")?,
               request_headers:  parse_headers(&settings.request_headers, "request")?,
            }
         },
         Self::CHALLENGE | Self::CHECK => {
            let ca = ChallengeAction {
               challenges:  challenges.to_vec(),
               http_code:   settings.http_code.unwrap_or(default_http_code),
               pass_action: sub_action(settings.pass_action.as_deref(), Self::Pass, "pass")?,
               fail_action: sub_action(
                  settings.fail_action.as_deref(),
                  Self::Deny { code: 403 },
                  "fail",
               )?,
            };
            if action_str.eq_ignore_ascii_case(Self::CHECK) {
               Self::Check(ca)
            } else {
               Self::Challenge(ca)
            }
         },
         other => return Err(format!("unknown action '{other}'")),
      })
   }

   /// Stable spelling used by parsing, metrics, traces, and defense rules.
   #[must_use]
   pub const fn label(&self) -> &'static str {
      match self {
         Self::None => Self::NONE,
         Self::Pass => Self::PASS,
         Self::Deny { .. } => Self::DENY,
         Self::Block { .. } => Self::BLOCK,
         Self::Code(_) => Self::CODE,
         Self::Drop => Self::DROP,
         Self::Tarpit { .. } => Self::TARPIT,
         Self::Smear => Self::SMEAR,
         Self::Proxy { .. } => Self::PROXY,
         Self::Context { .. } => Self::CONTEXT,
         Self::Challenge(_) => Self::CHALLENGE,
         Self::Check(_) => Self::CHECK,
         Self::Report { .. } => Self::REPORT,
      }
   }
}

fn sub_action(setting: Option<&str>, default: Action, kind: &str) -> Result<Box<Action>, String> {
   Ok(Box::new(match setting {
      None => default,
      Some(Action::PASS) => Action::Pass,
      Some(Action::DENY) => Action::Deny { code: 403 },
      Some(Action::BLOCK) => Action::Block { code: 403 },
      Some(Action::DROP) => Action::Drop,
      Some(Action::SMEAR) => Action::Smear,
      Some(other) => return Err(format!("unknown {kind}-action '{other}'")),
   }))
}

fn parse_headers(pairs: &[(String, String)], kind: &str) -> Result<HeaderMap, String> {
   let mut headers = HeaderMap::new();
   for (key, value) in pairs {
      let name = HeaderName::from_bytes(key.as_bytes())
         .map_err(|_| format!("invalid {kind} header name '{key}'"))?;
      let val = HeaderValue::from_str(value)
         .map_err(|_| format!("invalid {kind} header value for '{key}'"))?;
      headers.insert(name, val);
   }
   Ok(headers)
}
