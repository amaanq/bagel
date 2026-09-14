use std::{
   collections::HashMap,
   net::{
      IpAddr,
      SocketAddr,
   },
};

use bagel_solver::codec::unpack_solution;
use bytes::Bytes;
use data_encoding::BASE64URL_NOPAD;
use http::{
   Method,
   StatusCode,
   Uri,
   header,
   uri::Authority,
};
use http_body_util::{
   BodyExt as _,
   Limited,
};

use crate::{
   body::{
      self,
      Body,
      Request,
      Response,
   },
   challenge::{
      ChallengeRuntime,
      Redemption,
      RequestChallengeState,
      key::{
         bucket_expiry,
         derive_challenge_key,
      },
      token::{
         Token,
         TokenChallenge,
         cookie_name,
         derive_cookie_key,
         format_http_date,
         seal_token,
         unix_timestamp,
      },
      types::ChallengeKey,
      url::{
         parse_query_params,
         percent_decode,
      },
   },
   hex_encode,
   host::CanonicalHost,
   ip_network_prefix,
   server::handle_request,
   state::{
      SharedState,
      StateInner,
   },
};

const WIDGET_CSS: &str = include_str!("../assets/widget.css");
const RUNTIME_MJS: &str = include_str!("../assets/challenge/runtime.mjs");
const SOLVER_WASM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/solver.wasm"));

/// The endpoints bagel answers itself, under a prefix no origin owns.
enum Internal {
   Css,
   Runtime,
   Solver,
   Verify(String),
}

/// The challenge name is one path segment and arrives percent-encoded, the
/// same shape the router's `{challenge_name}` capture accepted.
fn internal_route(path: &str) -> Option<Internal> {
   match path {
      "/__bagel/static/widget.css" => return Some(Internal::Css),
      "/__bagel/static/runtime.mjs" => return Some(Internal::Runtime),
      "/__bagel/static/solver.wasm" => return Some(Internal::Solver),
      _ => {},
   }
   let name = path.strip_prefix("/__bagel/")?.strip_suffix("/verify")?;
   (!name.is_empty() && !name.contains('/')).then(|| Internal::Verify(percent_decode(name)))
}

/// Route one request, preferring the internal endpoints over the main
/// pipeline so no policy can shadow a verify.
pub async fn dispatch(shared: &SharedState, addr: SocketAddr, req: Request) -> Response {
   let Some(route) = internal_route(req.uri().path()) else {
      return handle_request(shared, addr, req).await;
   };

   let readable = req.method() == Method::GET || req.method() == Method::HEAD;
   let posted = req.method() == Method::POST;
   match route {
      Internal::Css if readable => asset(WIDGET_CSS.as_bytes(), "text/css; charset=utf-8"),
      Internal::Runtime if readable => {
         asset(
            RUNTIME_MJS.as_bytes(),
            "application/javascript; charset=utf-8",
         )
      },
      Internal::Solver if readable => asset(SOLVER_WASM, "application/wasm"),
      Internal::Css | Internal::Runtime | Internal::Solver => method_not_allowed("GET,HEAD"),
      Internal::Verify(name) if readable => handle_verify(shared, &name, &req),
      Internal::Verify(name) if posted => handle_pow_verify(shared, &name, req).await,
      Internal::Verify(_) => method_not_allowed("GET,HEAD,POST"),
   }
}

fn asset(content: &'static [u8], content_type: &'static str) -> Response {
   Response::builder()
      .status(StatusCode::OK)
      .header(header::CONTENT_TYPE, content_type)
      .header(header::CACHE_CONTROL, "public, max-age=86400")
      .body(Body::from(Bytes::from_static(content)))
      .expect("static asset response parts are valid")
}

fn method_not_allowed(allow: &'static str) -> Response {
   let mut resp = body::status(StatusCode::METHOD_NOT_ALLOWED);
   resp
      .headers_mut()
      .insert(header::ALLOW, http::HeaderValue::from_static(allow));
   resp
}

/// Match a presented key against the two expiry buckets accepted by issuance.
fn match_recent_key(
   challenge_name: &str,
   client_ip: Option<IpAddr>,
   duration_secs: i64,
   key_fingerprint: &[u8; 32],
   presented_hex: &str,
) -> Option<(ChallengeKey, i64)> {
   let step = duration_secs.max(1);
   let bucket = bucket_expiry(unix_timestamp(), step);
   for expiry in [bucket, bucket - step] {
      let key = derive_challenge_key(challenge_name, client_ip, expiry, key_fingerprint);
      if constant_time_eq::constant_time_eq(hex_encode(&key).as_bytes(), presented_hex.as_bytes()) {
         return Some((key, expiry));
      }
   }
   None
}

/// Confine the redirect to a same-origin path.
/// Reject decoded control bytes and absolute URLs.
fn safe_redirect(raw: &str) -> Option<String> {
   let looks_relative = raw.starts_with('/') && !raw.starts_with("//");
   let printable = raw
      .bytes()
      .all(|byte| byte.is_ascii_graphic() || byte == b' ');
   (looks_relative && printable).then(|| raw.to_owned())
}

/// Resolve the client IP the way the main handler does, honouring the
/// configured client-ip policy (header plus trusted proxies).
fn client_ip_for(state: &StateInner, req: &Request) -> Option<IpAddr> {
   let peer = req.extensions().get::<SocketAddr>().map(SocketAddr::ip)?;
   Some(state.client_ip(peer, req.headers()))
}

fn canonical_request_host(req: &Request) -> Option<CanonicalHost> {
   req.headers()
      .get(header::HOST)
      .and_then(|hv| hv.to_str().ok())
      .or_else(|| req.uri().authority().map(Authority::as_str))
      .and_then(|raw| CanonicalHost::parse(raw).ok())
}

fn query_param<'a>(uri: &'a Uri, key: &str) -> Option<&'a str> {
   parse_query_params(uri.query()?)
      .into_iter()
      .find_map(|(name, value)| (name == key).then_some(value))
}

fn challenge_cookie(host: &CanonicalHost, sealed: &str, expiry: i64) -> String {
   let cname = cookie_name(host.as_str());
   let exp_str = format_http_date(expiry);
   let domain = if host.is_ip() {
      String::new()
   } else {
      format!(" Domain={host};")
   };
   format!("{cname}={sealed}; Path=/;{domain} Expires={exp_str}; SameSite=Lax")
}

/// Generic verify handler: validates the hex key token, issues a signed cookie,
/// and redirects back to the original page.
fn handle_verify(shared: &SharedState, challenge_name: &str, req: &Request) -> Response {
   let state = shared.load();

   let Some(token_hex) = query_param(req.uri(), "__bagel_token") else {
      return body::text(StatusCode::BAD_REQUEST, "missing token");
   };

   let redirect =
      query_param(req.uri(), "__bagel_redirect").map_or_else(|| "/".to_owned(), percent_decode);
   let Some(redirect) = safe_redirect(&redirect) else {
      return body::text(StatusCode::BAD_REQUEST, "invalid redirect");
   };

   let Some(reg) = state.policy.challenges.get(challenge_name) else {
      return body::text(StatusCode::NOT_FOUND, "unknown challenge");
   };

   let Some(host) = canonical_request_host(req) else {
      return body::text(StatusCode::BAD_REQUEST, "invalid host");
   };
   let client_ip = client_ip_for(&state, req);

   if reg.runtime.redemption() != Redemption::Redirect {
      return body::text(StatusCode::BAD_REQUEST, "challenge needs a posted solution");
   }

   let Some((challenge_key, _)) = match_recent_key(
      challenge_name,
      client_ip,
      reg.duration.as_secs() as i64,
      &state.keys.key_fingerprint,
      token_hex,
   ) else {
      return body::text(StatusCode::FORBIDDEN, "invalid token");
   };

   let cookie = match seal_pass(
      &Client {
         state:   &state,
         headers: req.headers(),
         host:    &host,
         ip:      client_ip,
      },
      challenge_name,
      &challenge_key,
      Vec::new(),
      reg.duration,
   ) {
      Ok(cookie) => cookie,
      Err(resp) => return resp,
   };

   Response::builder()
      .status(StatusCode::TEMPORARY_REDIRECT)
      .header(header::LOCATION, &redirect)
      .header(header::SET_COOKIE, cookie)
      .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
      .body(Body::empty())
      .expect("verify redirect parts are valid")
}

/// The request identity a pass is sealed against.
#[derive(Clone, Copy)]
struct Client<'a> {
   state:   &'a StateInner,
   headers: &'a header::HeaderMap,
   host:    &'a CanonicalHost,
   ip:      Option<IpAddr>,
}

/// Expiry starts at now. Merge earlier passes because a rule may issue two
/// challenges.
fn seal_pass(
   who: &Client<'_>,
   challenge_name: &str,
   challenge_key: &ChallengeKey,
   result: Vec<u8>,
   duration: std::time::Duration,
) -> Result<String, Response> {
   let Client {
      state,
      headers,
      host,
      ip: client_ip,
   } = *who;
   let now = unix_timestamp();
   let expiry = now.saturating_add(duration.as_secs() as i64);

   let mut carried = RequestChallengeState::from_headers(
      headers,
      host.as_str(),
      &state.keys.public_key_bytes,
      &state.keys.pkcs8_seed,
      client_ip,
   );

   carried.token.get_or_insert_with(|| {
      Token {
         state: HashMap::new(),
         exp:   expiry,
         nbf:   now,
         iat:   now,
      }
   });

   let token = carried.token.as_mut().expect("inserted above");
   token
      .state
      .insert(challenge_name.to_owned(), TokenChallenge {
         key: challenge_key.to_vec(),
         result,
         ok: true,
         exp: expiry,
         nbf: now,
         iat: now,
      });
   if token.exp < expiry {
      token.exp = expiry;
   }

   let ip_prefix = client_ip.map(ip_network_prefix).unwrap_or_default();
   let cookie_key = derive_cookie_key(host.as_str(), &ip_prefix, &state.keys.pkcs8_seed);

   match seal_token(token, &state.keys.signing_key, &cookie_key) {
      Ok(sealed) => Ok(challenge_cookie(host, &sealed, token.exp)),
      Err(err) => {
         tracing::error!(error = %err, "failed to seal verify token");
         Err(body::text(StatusCode::INTERNAL_SERVER_ERROR, "token error"))
      },
   }
}

/// `PoW` verify handler: POST with the sealed solution the module produced,
/// base64url in the body.
async fn handle_pow_verify(shared: &SharedState, challenge_name: &str, req: Request) -> Response {
   let state = shared.load();

   let Some(reg) = state.policy.challenges.get(challenge_name) else {
      return body::text(StatusCode::NOT_FOUND, "unknown challenge");
   };

   let Some(host) = canonical_request_host(&req) else {
      return body::text(StatusCode::BAD_REQUEST, "invalid host");
   };
   let client_ip = client_ip_for(&state, &req);

   let (parts, incoming) = req.into_parts();
   let Ok(collected) = Limited::new(incoming, 4096).collect().await else {
      return body::text(StatusCode::BAD_REQUEST, "body too large");
   };

   let Some((presented_key, nonce)) = BASE64URL_NOPAD
      .decode(collected.to_bytes().trim_ascii())
      .ok()
      .and_then(|blob| unpack_solution(&blob))
   else {
      return body::text(StatusCode::BAD_REQUEST, "invalid solution");
   };

   let Some((challenge_key, _)) = match_recent_key(
      challenge_name,
      client_ip,
      reg.duration.as_secs() as i64,
      &state.keys.key_fingerprint,
      &hex_encode(&presented_key),
   ) else {
      return body::text(StatusCode::FORBIDDEN, "invalid challenge key");
   };

   let ChallengeRuntime::PowSha256(ref pow) = reg.runtime else {
      return body::text(StatusCode::BAD_REQUEST, "not a PoW challenge");
   };
   if !pow.verify_nonce(&challenge_key, nonce) {
      return body::text(StatusCode::FORBIDDEN, "invalid proof of work");
   }

   let cookie = match seal_pass(
      &Client {
         state:   &state,
         headers: &parts.headers,
         host:    &host,
         ip:      client_ip,
      },
      challenge_name,
      &challenge_key,
      nonce.to_be_bytes().to_vec(),
      reg.duration,
   ) {
      Ok(cookie) => cookie,
      Err(resp) => return resp,
   };

   Response::builder()
      .status(StatusCode::OK)
      .header(header::SET_COOKIE, cookie)
      .header(header::CONTENT_TYPE, "application/json")
      .body(Body::from(r#"{"ok":true}"#))
      .expect("pow verify response parts are valid")
}
