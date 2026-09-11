use std::{
   net::{
      IpAddr,
      SocketAddr,
   },
   pin::Pin,
   sync::Arc,
   task::{
      Context,
      Poll,
   },
};

use bagel_runtime::{
   OffenseKind,
   tarpit::Dribble,
};
use bytes::Bytes;
use http::{
   HeaderMap,
   HeaderValue,
   StatusCode,
   Uri,
   header,
};
use http_body::Frame;
use pin_project_lite::pin_project;

use super::maze::{
   MazeServe,
   serve_maze,
};
use crate::{
   SourceNetwork,
   body::{
      self,
      Body,
      BodyError,
      Request,
      Response,
   },
   challenge::{
      RequestChallengeState,
      url::strip_bagel_params,
   },
   host::CanonicalHost,
   metrics as bmetrics,
   net::DropHandle,
   proxy,
   rule::{
      PassMarker,
      PendingRequestHeaders,
      PendingResponseHeaders,
      ProxyMarker,
      RuleOutcome,
      TerminalRuleInfo,
      action::Action,
      condition::{
         ConditionContext,
         TrapVerdict,
      },
      scoring::ScoreMode,
   },
   state::{
      self,
      SharedState,
      StateInner,
   },
   template,
};

/// Main request handler: evaluate challenges, rules, then proxy to backend.
pub async fn handle_request(shared: &SharedState, addr: SocketAddr, mut req: Request) -> Response {
   let state = shared.load();

   req.extensions_mut().insert(addr);
   let drop_handle = req.extensions().get::<DropHandle>().cloned();

   let uri_authority = req.uri().authority().map(|auth| auth.as_str().to_owned());
   let header_host = req
      .headers()
      .get(header::HOST)
      .and_then(|hv| hv.to_str().ok())
      .map(str::to_owned);
   let canonical = match canonicalize_authority(uri_authority.as_deref(), header_host.as_deref()) {
      Ok(canonical) => canonical,
      Err(reason) => {
         tracing::debug!(reason, "rejected request authority");
         return body::text(StatusCode::BAD_REQUEST, "invalid request authority\n");
      },
   };
   let host = canonical.as_str().to_owned();

   let client_ip = Some(state.client_ip(addr.ip(), req.headers()));
   if let Some(ip) = client_ip {
      req.extensions_mut()
         .insert(SocketAddr::new(ip, addr.port()));
   }

   let Some(backend) = state.runtime.backends.select(&host) else {
      tracing::debug!(host, "no backend for host");
      let page = template::render_error(
         state.runtime.theme,
         503,
         "Service Unavailable",
         "No backend configured for this host.",
         None,
      );
      return body::html(StatusCode::SERVICE_UNAVAILABLE, page);
   };

   let source_network = client_ip.map(SourceNetwork::from_ip);

   // A recognized maze route is handled without touching normal rates or
   // rules and cannot be released by a broad pass rule.
   match state.maze_lookup(&host) {
      state::MazeLookup::Refused => {
         return body::text(StatusCode::SERVICE_UNAVAILABLE, "service unavailable\n");
      },
      state::MazeLookup::Table(table) => {
         let raw_path = req.uri().path().to_owned();
         let first_segment = raw_path
            .strip_prefix('/')
            .map(|path| path.split('/').next().unwrap_or(path));
         if let Some(runtime) = first_segment.and_then(|segment| table.by_prefix.get(segment)) {
            let ms = MazeServe {
               runtime,
               host: &host,
               client_ip,
               source: source_network,
               peer_network: SourceNetwork::from_ip(addr.ip()),
               method: req.method(),
               raw_path: &raw_path,
            };
            return serve_maze(&state, &ms).await;
         }
      },
      state::MazeLookup::NoMazes => {},
   }

   if state.config.bind.passthrough {
      return match proxy::proxy_request(&state.runtime.http_client, &backend, req).await {
         Ok(resp) | Err(resp) => resp,
      };
   }

   let (mut challenge_state, mut ctx, mut scope) =
      request_context(&state, &req, &host, client_ip, source_network);
   #[cfg(feature = "fcrdns")]
   if let (Some(verifier), Some(ip)) = (&state.runtime.crawler_verifier, client_ip) {
      ctx.crawler_verified = verifier.verify(ip).await;
   }

   // Scoring runs before rules so observation traces include requests a rule
   // later handles.
   let score_result = state
      .policy
      .scoring
      .as_ref()
      .and_then(|scoring| scoring.evaluate(&state.runtime.rhai_engine, &mut scope));
   if let Some(ref result) = score_result {
      bmetrics::record_score(&result.scorecard.name, result.score);
      for signal in &result.matched {
         bmetrics::record_signal_match(&result.scorecard.name, signal);
      }
      for signal in &result.errors {
         bmetrics::record_signal_error(&result.scorecard.name, signal);
      }
   }

   // Capture the URI before we enter the async rule evaluation.
   // We need this because &Request<Body> is not Send (Body is not Sync).
   let request_uri = req.uri().clone();
   let user_agent = req
      .headers()
      .get(header::USER_AGENT)
      .and_then(|hv| hv.to_str().ok())
      .unwrap_or("unknown")
      .to_owned();

   // Evaluate rules (async because challenges may need I/O)
   let mut terminal = Terminal::None;
   let base_headers = HeaderMap::new();

   let mut eval = crate::server::pipeline_evaluate::Eval {
      state:           &state,
      ctx:             &ctx,
      scope:           &mut scope,
      challenge_state: &mut challenge_state,
      host:            &host,
      request_uri:     &request_uri,
      user_agent:      &user_agent,
      headers:         &base_headers,
   };

   for rule in &state.policy.rules {
      let outcome =
         crate::server::pipeline_evaluate::evaluate_rule_recursive(rule, &mut eval).await;

      match outcome {
         RuleOutcome::Continue => {},
         RuleOutcome::Handled(resp) => {
            terminal = Terminal::Handled(resp);
            break;
         },
         RuleOutcome::Drop => {
            terminal = Terminal::Dropped {
               rule: Some(rule.name.clone()),
            };
            break;
         },
      }
   }

   let (terminal_rule, terminal_action) = match &terminal {
      Terminal::None => (None, None),
      Terminal::Handled(resp) => {
         resp
            .extensions()
            .get::<TerminalRuleInfo>()
            .map_or((None, None), |info| {
               (Some(info.rule.clone()), Some(info.action))
            })
      },
      Terminal::Dropped { rule } => (rule.clone(), Some(Action::DROP)),
   };

   let candidate = score_result.as_ref().and_then(|result| result.candidate);
   let candidate_status = match (&score_result, candidate) {
      (None, _) => "no_scorecard",
      (Some(_), None) => "no_candidate",
      (Some(_), Some(_)) if !matches!(terminal, Terminal::None) => "suppressed_by_rule",
      (Some(result), Some(_)) => {
         match result.scorecard.mode {
            ScoreMode::Observe => "observed",
            ScoreMode::Enforce => "applied",
         }
      },
   };

   if candidate_status == "applied"
      && let Some(threshold) = candidate
   {
      let outcome =
         crate::server::pipeline_evaluate::apply_candidate_action(&threshold.action, &mut eval)
            .await;
      match outcome {
         RuleOutcome::Continue => {},
         RuleOutcome::Handled(resp) => terminal = Terminal::Handled(resp),
         RuleOutcome::Drop => terminal = Terminal::Dropped { rule: None },
      }
   }

   let effective_action: &str = match &terminal {
      Terminal::Dropped { .. } => Action::DROP,
      Terminal::None => Action::PROXY,
      Terminal::Handled(resp) => {
         if resp.extensions().get::<PassMarker>().is_some() {
            Action::PASS
         } else if resp.extensions().get::<ProxyMarker>().is_some() {
            Action::PROXY
         } else if candidate_status == "applied" {
            candidate.map_or("unknown", |threshold| threshold.kind)
         } else {
            terminal_action.unwrap_or("unknown")
         }
      },
   };

   if let Some(ref result) = score_result {
      bmetrics::record_scoring_decision(
         &result.scorecard.name,
         result.scorecard.mode.as_str(),
         candidate_status,
         candidate.map_or("none", |threshold| threshold.kind),
      );
   }

   tracing::info!(
      target: "bagel::decision",
      policy_revision = state.policy.revision,
      scorecard = score_result.as_ref().map(|result| result.scorecard.name.as_str()),
      score_mode = score_result.as_ref().map(|result| result.scorecard.mode.as_str()),
      score = score_result.as_ref().map(|result| result.score),
      matched_signals = ?score_result.as_ref().map(|result| &result.matched),
      signal_errors = ?score_result.as_ref().map(|result| &result.errors),
      rate_available = ctx.rate.is_some(),
      rate_1s = ctx.rate.map_or(0, |snap| snap.last_1s),
      rate_10s = ctx.rate.map_or(0, |snap| snap.last_10s),
      rate_60s = ctx.rate.map_or(0, |snap| snap.last_60s),
      poison_returned = ctx.poison_returned,
      candidate_threshold = candidate.map(|threshold| threshold.value),
      candidate_action = candidate.map(|threshold| threshold.kind),
      candidate_status,
      terminal_rule,
      terminal_action,
      effective_action,
      "decision"
   );

   let offense_kind = match effective_action {
      Action::DROP => Some(OffenseKind::Drop),
      Action::SMEAR => Some(OffenseKind::Smear),
      Action::TARPIT => Some(OffenseKind::Tarpit),
      _ => None,
   };
   if let Some(kind) = offense_kind {
      let applied = score_result
         .as_ref()
         .filter(|_| candidate_status == "applied");
      let (kind, rule) = applied.map_or((kind, terminal_rule.as_deref()), |result| {
         (
            OffenseKind::Score {
               score: result.score,
            },
            Some(result.scorecard.name.as_str()),
         )
      });
      emit_offense(&state, client_ip, &host, rule, effective_action, kind, None);
   }

   finalize_response(
      req,
      terminal,
      FinalizeContext {
         state: &state,
         backend: &backend,
         host: &host,
         host_is_ip: canonical.is_ip(),
         client_ip,
         drop_handle,
      },
      challenge_state,
   )
   .await
}

fn request_context(
   state: &StateInner,
   req: &Request,
   host: &str,
   client_ip: Option<IpAddr>,
   source_network: Option<SourceNetwork>,
) -> (
   RequestChallengeState,
   ConditionContext,
   rhai::Scope<'static>,
) {
   let challenge_state = RequestChallengeState::from_headers(
      req.headers(),
      host,
      &state.keys.public_key_bytes,
      &state.keys.pkcs8_seed,
      client_ip,
   );

   let mut ctx = ConditionContext::from_request(req);
   host.clone_into(&mut ctx.host);
   if let Some(ip) = client_ip {
      ctx.remote_address = ip.to_string();
      ctx.remote_ip = Some(ip);
   }
   ctx.compute_network_membership(&state.policy.networks);
   if let (Some(classifier), Some(ip)) = (state.hooks.classifier.load().as_ref(), client_ip) {
      ctx.trap = Some(classify_request(classifier, req, ip));
   }

   if let Some(network) = source_network {
      ctx.rate = Some(state.runtime.rate_tracker.record(host, network));
      ctx.poison_returned = state.poison_returned(host, network);
   }
   if let Some(ip) = client_ip {
      ctx.lease_active = state
         .hooks
         .leases
         .load()
         .as_ref()
         .is_some_and(|leases| leases.contains(ip));
   }
   let scope = ctx.scope();
   (challenge_state, ctx, scope)
}

struct FinalizeContext<'a> {
   state:       &'a StateInner,
   backend:     &'a Arc<proxy::backend::Backend>,
   host:        &'a str,
   host_is_ip:  bool,
   client_ip:   Option<IpAddr>,
   drop_handle: Option<DropHandle>,
}

async fn finalize_response(
   mut req: Request,
   terminal: Terminal,
   context: FinalizeContext<'_>,
   challenge_state: RequestChallengeState,
) -> Response {
   let FinalizeContext {
      state,
      backend,
      host,
      host_is_ip,
      client_ip,
      drop_handle,
   } = context;
   let final_response = match terminal {
      Terminal::None => None,
      Terminal::Handled(resp) => Some(resp),
      Terminal::Dropped { .. } => {
         if let Some(handle) = drop_handle {
            handle.trigger();
            // The connection task cancels this future on drop.
            return std::future::pending::<Response>().await;
         }
         tracing::error!("drop outcome on a connection without a DropHandle");
         return body::status(StatusCode::INTERNAL_SERVER_ERROR);
      },
   };

   let cleaned_uri = strip_bagel_params(req.uri());
   *req.uri_mut() = cleaned_uri;

   crate::server::pipeline_evaluate::strip_bagel_cookies(&mut req, host);

   let mut resp = match final_response {
      Some(rule_resp) => {
         if let Some(pending) = rule_resp.extensions().get::<PendingRequestHeaders>() {
            for (name, value) in &pending.0 {
               req.headers_mut().insert(name.clone(), value.clone());
            }
         }
         let pending_response = rule_resp
            .extensions()
            .get::<PendingResponseHeaders>()
            .cloned();

         let mut resp = if let Some(marker) = rule_resp.extensions().get::<ProxyMarker>().cloned() {
            proxy_to_named(state, &marker, req).await
         } else if rule_resp.extensions().get::<PassMarker>().is_some() {
            match proxy::proxy_request(&state.runtime.http_client, backend, req).await {
               Ok(proxy_resp) | Err(proxy_resp) => proxy_resp,
            }
         } else {
            rule_resp
         };

         if let Some(pending) = pending_response {
            for (name, value) in &pending.0 {
               resp.headers_mut().insert(name.clone(), value.clone());
            }
         }
         resp
      },
      None => {
         match proxy::proxy_request(&state.runtime.http_client, backend, req).await {
            Ok(proxy_resp) | Err(proxy_resp) => proxy_resp,
         }
      },
   };

   if !challenge_state.injections.is_empty() {
      resp = inject_fragments(resp, &challenge_state.injections);
   }

   merge_vary(resp.headers_mut());

   if let Some(cookie) = challenge_state.seal_cookie(
      host,
      host_is_ip,
      &state.keys.signing_key,
      &state.keys.pkcs8_seed,
      client_ip,
   ) && let Ok(val) = HeaderValue::from_str(&cookie)
   {
      resp.headers_mut().append(header::SET_COOKIE, val);
   }

   resp
}

fn canonicalize_authority(
   uri: Option<&str>,
   header: Option<&str>,
) -> Result<CanonicalHost, String> {
   match (uri, header) {
      (Some(uri), Some(header)) => {
         let from_uri = CanonicalHost::parse(uri)?;
         let from_header = CanonicalHost::parse(header)?;
         if from_uri != from_header {
            return Err("URI authority and Host header disagree".into());
         }
         Ok(from_uri)
      },
      (Some(authority), None) | (None, Some(authority)) => CanonicalHost::parse(authority),
      (None, None) => Err("no usable authority".into()),
   }
}

/// Run bagel's signature traps over the request the way its own listener
/// did, matching the percent-decoded path but leaving the request untouched.
fn classify_request(
   classifier: &bagel_traps::Classifier,
   req: &Request,
   ip: IpAddr,
) -> TrapVerdict {
   use bagel_traps::classify::{
      TrapReason,
      Verdict,
      decode_path,
   };
   let user_agent = req
      .headers()
      .get(header::USER_AGENT)
      .and_then(|hv| hv.to_str().ok());
   match classifier.classify(req.uri().path(), user_agent, ip) {
      Verdict::Proxy | Verdict::Tarpit(TrapReason::Rate) => TrapVerdict::default(),
      Verdict::Tarpit(TrapReason::Path(_)) => {
         let decoded = decode_path(req.uri().path());
         TrapVerdict {
            reason:   Some("path"),
            category: Some(bagel_traps::category::categorize(&decoded).label()),
         }
      },
      Verdict::Tarpit(TrapReason::UserAgent(_)) => {
         TrapVerdict {
            reason:   Some("user_agent"),
            category: Some("scraper"),
         }
      },
      Verdict::Tarpit(TrapReason::Impersonator(_)) => {
         TrapVerdict {
            reason:   Some("impersonator"),
            category: Some("scraper"),
         }
      },
   }
}

/// Build a paced smear response, falling back to drop when slots are exhausted.
pub(super) fn smear_response(
   state: &StateInner,
   request_uri: &Uri,
   user_agent: &str,
) -> RuleOutcome {
   let Ok(permit) = Arc::clone(&state.runtime.smear_slots).try_acquire_owned() else {
      tracing::debug!("smear slots exhausted, degrading to drop");
      return RuleOutcome::Drop;
   };
   let decoded = bagel_traps::classify::decode_path(request_uri.path());
   let kind = bagel_traps::category::categorize(&decoded).label();
   let page = state.runtime.deceiver.page(&decoded, user_agent, kind);
   let smear = &state.config.smear;
   let schedule = Dribble {
      min_delay_ms: smear.min_delay_ms,
      max_delay_ms: smear.max_delay_ms,
      chunk_min:    smear.chunk_min,
      chunk_max:    smear.chunk_max,
   };
   RuleOutcome::Handled(crate::smear::response(
      page,
      schedule,
      smear.max_secs,
      permit,
   ))
}

static OFFENSE_DROP_WARNING: std::sync::Mutex<Option<std::time::Instant>> =
   std::sync::Mutex::new(None);

/// Hand an offense to the defense plane when a source is attached.
pub(super) fn emit_offense(
   state: &StateInner,
   client_ip: Option<IpAddr>,
   host: &str,
   rule: Option<&str>,
   detail: &str,
   kind: OffenseKind,
   group_key: Option<String>,
) {
   let Some(ip) = client_ip else {
      return;
   };
   let source = state.hooks.offenses.load();
   let Some(source) = source.as_ref() else {
      return;
   };
   let offense = bagel_runtime::Offense {
      address: ip,
      network: SourceNetwork::from_ip(ip).to_ip_network(),
      host: host.to_owned(),
      rule: rule.map(str::to_owned),
      detail: detail.to_owned(),
      kind,
      group_key,
   };
   if source.emit(&offense) {
      bmetrics::record_offense(offense.kind.label(), "sent");
   } else {
      bmetrics::record_offense(offense.kind.label(), "dropped");
      let mut last = OFFENSE_DROP_WARNING
         .lock()
         .unwrap_or_else(std::sync::PoisonError::into_inner);
      if last.is_none_or(|at| at.elapsed() >= std::time::Duration::from_secs(10)) {
         *last = Some(std::time::Instant::now());
         tracing::warn!(
            host,
            detail,
            "offense channel full, dropping records until the defense loop catches up"
         );
      }
   }
}

/// Append challenge fragments to a proxied HTML response.
const VARY_FIELDS: [&str; 5] = [
   "Cookie",
   "Accept",
   "Accept-Encoding",
   "Accept-Language",
   "User-Agent",
];

/// Add the fields bagel varies on to whatever the origin already declared.
fn merge_vary(headers: &mut HeaderMap) {
   let existing = headers
      .get_all(header::VARY)
      .iter()
      .filter_map(|value| value.to_str().ok())
      .flat_map(|value| value.split(','))
      .map(|field| field.trim().to_owned())
      .filter(|field| !field.is_empty())
      .collect::<Vec<String>>();

   if existing.iter().any(|field| field == "*") {
      return;
   }

   let mut merged = existing.clone();
   for field in VARY_FIELDS {
      if !existing.iter().any(|have| have.eq_ignore_ascii_case(field)) {
         merged.push(field.to_owned());
      }
   }

   if let Ok(value) = HeaderValue::from_str(&merged.join(", ")) {
      headers.insert(header::VARY, value);
   }
}

/// Compressed bodies are left alone and the injection retries on a later
/// response.
fn inject_fragments(resp: Response, fragments: &[String]) -> Response {
   let is_html = resp
      .headers()
      .get(header::CONTENT_TYPE)
      .and_then(|hv| hv.to_str().ok())
      .is_some_and(|ct| ct.starts_with("text/html"));
   let encoded = resp.headers().contains_key(header::CONTENT_ENCODING);

   if resp.status() != StatusCode::OK || !is_html || encoded {
      return resp;
   }

   let tail = Bytes::from(fragments.concat());
   let (mut parts, body) = resp.into_parts();
   let length = parts
      .headers
      .get(header::CONTENT_LENGTH)
      .and_then(|hv| hv.to_str().ok())
      .and_then(|text| text.parse::<u64>().ok());
   if let Some(len) = length {
      if let Some(total) = len.checked_add(tail.len() as u64) {
         parts
            .headers
            .insert(header::CONTENT_LENGTH, HeaderValue::from(total));
      } else {
         parts.headers.remove(header::CONTENT_LENGTH);
      }
   }

   Response::from_parts(
      parts,
      Body::new(Appended {
         inner: body,
         tail:  Some(tail),
      }),
   )
}

pin_project! {
   struct Appended {
      #[pin]
      inner: Body,
      tail: Option<Bytes>,
   }
}

impl http_body::Body for Appended {
   type Data = Bytes;
   type Error = BodyError;

   fn poll_frame(
      self: Pin<&mut Self>,
      cx: &mut Context<'_>,
   ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
      let this = self.project();
      match this.inner.poll_frame(cx) {
         Poll::Ready(None) => Poll::Ready(this.tail.take().map(|bytes| Ok(Frame::data(bytes)))),
         other => other,
      }
   }
}

/// Terminal result of policy evaluation for one request, before the response
/// is materialized.
enum Terminal {
   None,
   Handled(Response),
   Dropped { rule: Option<String> },
}

fn error_response(state: &StateInner, code: u16, title: &str, message: &str) -> RuleOutcome {
   let page = template::render_error(state.runtime.theme, code, title, message, None);
   RuleOutcome::Handled(body::html(
      StatusCode::from_u16(code).unwrap_or(StatusCode::FORBIDDEN),
      page,
   ))
}

pub(super) fn deny_response(state: &StateInner, code: u16) -> RuleOutcome {
   error_response(
      state,
      code,
      "Access Denied",
      "Your request has been denied.",
   )
}

pub(super) fn block_response(state: &StateInner, code: u16) -> RuleOutcome {
   error_response(state, code, "Blocked", "Your request has been blocked.")
}

/// Proxy to the backend a rule named, applying its rewritten path while
/// preserving the query unless the rewrite supplied one.
async fn proxy_to_named(state: &StateInner, marker: &ProxyMarker, mut req: Request) -> Response {
   let Some(backend) = state.runtime.backends.by_name(&marker.backend) else {
      tracing::error!(backend = marker.backend, "proxy rule backend missing");
      return body::text(StatusCode::BAD_GATEWAY, "bad gateway");
   };

   if let Some(ref path) = marker.rewritten_path {
      let pq = if path.contains('?') {
         path.clone()
      } else if let Some(query) = req.uri().query() {
         format!("{path}?{query}")
      } else {
         path.clone()
      };

      match pq.parse::<http::uri::PathAndQuery>() {
         Ok(parsed) => {
            let mut parts = req.uri().clone().into_parts();
            parts.path_and_query = Some(parsed);
            match Uri::from_parts(parts) {
               Ok(uri) => *req.uri_mut() = uri,
               Err(err) => {
                  tracing::error!(error = %err, path = pq, "invalid rewritten URI");
                  return body::text(StatusCode::BAD_GATEWAY, "bad gateway");
               },
            }
         },
         Err(err) => {
            tracing::error!(error = %err, path = pq, "invalid rewritten path");
            return body::text(StatusCode::BAD_GATEWAY, "bad gateway");
         },
      }
   }

   match proxy::proxy_request(&state.runtime.http_client, &backend, req).await {
      Ok(resp) | Err(resp) => resp,
   }
}

pub(super) fn pass_response() -> Response {
   let mut resp = Response::new(Body::empty());
   resp.extensions_mut().insert(PassMarker);
   resp
}
