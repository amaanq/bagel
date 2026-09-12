use bagel_runtime::OffenseKind;
use http::{
   HeaderMap,
   HeaderValue,
   StatusCode,
   Uri,
   header,
};
use rhai::Scope;

use crate::{
   body::{
      self,
      Body,
      Request,
      Response,
   },
   challenge::{
      RequestChallengeState,
      key::{
         bucket_expiry,
         derive_challenge_key,
      },
      token::{
         cookie_name as challenge_cookie_name,
         unix_timestamp,
      },
      types::{
         ChallengeClass,
         ChallengeContext,
         IssueResult,
      },
   },
   metrics as bmetrics,
   rule::{
      PassMarker,
      PendingRequestHeaders,
      PendingResponseHeaders,
      ProxyMarker,
      RuleOutcome,
      RuleState,
      action::{
         Action,
         ChallengeAction,
      },
      condition::ConditionContext,
   },
   server::{
      maze::tarpit_response,
      pipeline::{
         block_response,
         deny_response,
         emit_offense,
         pass_response,
         smear_response,
      },
   },
   state::StateInner,
   tag_fetcher,
   template,
};

pub(super) fn proxy_outcome(
   match_re: Option<&regex::Regex>,
   rewrite: &str,
   backend: &str,
   request_uri: &Uri,
) -> RuleOutcome {
   let rewritten_path = match_re.and_then(|re| {
      re.captures(request_uri.path()).map(|caps| {
         let mut expanded = String::new();
         caps.expand(rewrite, &mut expanded);
         expanded
      })
   });
   let mut resp = Response::new(Body::empty());
   resp.extensions_mut().insert(ProxyMarker {
      backend: backend.to_owned(),
      rewritten_path,
   });
   RuleOutcome::Handled(resp)
}

/// Apply an enforced scorecard candidate once the rule tree returned
/// Continue.
pub(super) async fn apply_candidate_action(action: &Action, eval: &mut Eval<'_>) -> RuleOutcome {
   match action {
      Action::Proxy {
         match_re,
         rewrite,
         backend,
      } => {
         bmetrics::record_action(eval.host, Action::PROXY);
         proxy_outcome(match_re.as_ref(), rewrite, backend, eval.request_uri)
      },
      Action::Challenge(ca) => evaluate_challenge_action("scorecard", ca, eval, false).await,
      Action::Tarpit { maze } => {
         bmetrics::record_action(eval.host, Action::TARPIT);
         RuleOutcome::Handled(
            tarpit_response(eval.state, maze, eval.host, eval.ctx.remote_ip).await,
         )
      },
      Action::Report { .. } => RuleOutcome::Continue,
      other => dispatch_sub_action(other, eval),
   }
}

pub(super) fn strip_bagel_cookies(req: &mut Request, host: &str) {
   let cname = challenge_cookie_name(host);
   let headers = req.headers_mut();

   if let Some(cookie_header) = headers.get(header::COOKIE).cloned()
      && let Ok(cookie_str) = cookie_header.to_str()
   {
      let cleaned: Vec<&str> = cookie_str
         .split(';')
         .map(str::trim)
         .filter(|cookie| {
            if let Some((name, _)) = cookie.split_once('=') {
               name.trim() != cname
            } else {
               true
            }
         })
         .collect();

      if cleaned.is_empty() {
         headers.remove(header::COOKIE);
      } else {
         let new_cookie = cleaned.join("; ");
         if let Ok(val) = HeaderValue::from_str(&new_cookie) {
            headers.insert(header::COOKIE, val);
         }
      }
   }
}

pub(super) struct Eval<'a> {
   pub state:           &'a StateInner,
   pub ctx:             &'a ConditionContext,
   pub scope:           &'a mut Scope<'static>,
   pub challenge_state: &'a mut RequestChallengeState,
   pub host:            &'a str,
   pub request_uri:     &'a Uri,
   pub user_agent:      &'a str,
   pub headers:         &'a HeaderMap,
}

async fn eval_children(
   children: &[RuleState],
   eval: &mut Eval<'_>,
   pending: Option<(&HeaderMap, &HeaderMap)>,
) -> RuleOutcome {
   for child in children {
      match Box::pin(evaluate_rule_recursive(child, eval)).await {
         RuleOutcome::Continue => {},
         RuleOutcome::Drop => return RuleOutcome::Drop,
         RuleOutcome::Handled(mut resp) => {
            if let Some((request_headers, response_headers)) = pending {
               let proxied = resp.extensions().get::<PassMarker>().is_some()
                  || resp.extensions().get::<ProxyMarker>().is_some();
               if proxied {
                  if resp.extensions().get::<PendingRequestHeaders>().is_none() {
                     resp
                        .extensions_mut()
                        .insert(PendingRequestHeaders(request_headers.clone()));
                  }
                  let mut pending_resp = resp
                     .extensions_mut()
                     .remove::<PendingResponseHeaders>()
                     .unwrap_or_else(|| PendingResponseHeaders(HeaderMap::new()));
                  for (name, value) in response_headers {
                     pending_resp.0.insert(name.clone(), value.clone());
                  }
                  resp.extensions_mut().insert(pending_resp);
               } else {
                  for (name, value) in response_headers {
                     resp.headers_mut().insert(name.clone(), value.clone());
                  }
               }
            }
            return RuleOutcome::Handled(resp);
         },
      }
   }
   RuleOutcome::Continue
}

/// Recursively evaluate a rule, handling challenge/check actions inline.
/// Async because challenge `issue()` may do DNS I/O.
pub(super) async fn evaluate_rule_recursive(rule: &RuleState, eval: &mut Eval<'_>) -> RuleOutcome {
   if let Some(ref ast) = rule.condition {
      match eval
         .state
         .runtime
         .rhai_engine
         .eval_ast_with_scope::<bool>(eval.scope, ast)
      {
         Ok(true) => {
            bmetrics::record_rule_hit(eval.host, &rule.name);
         },
         Ok(false) => {
            bmetrics::record_rule_miss(eval.host, &rule.name);
            return RuleOutcome::Continue;
         },
         Err(err) => {
            tracing::error!(rule = rule.name, error = %err, "rule condition error");
            return RuleOutcome::Continue;
         },
      }
   }

   match &rule.action {
      Action::None => eval_children(&rule.children, eval, None).await,
      Action::Pass => {
         tracing::debug!(rule = rule.name, action = Action::PASS, "rule hit");
         bmetrics::record_action(eval.host, Action::PASS);
         RuleOutcome::Handled(pass_response()).tagged(&rule.name, Action::PASS)
      },
      Action::Deny { code } => {
         tracing::debug!(rule = rule.name, action = Action::DENY, code, "rule hit");
         bmetrics::record_action(eval.host, Action::DENY);
         deny_response(eval.state, *code).tagged(&rule.name, Action::DENY)
      },
      Action::Block { code } => {
         tracing::debug!(rule = rule.name, action = Action::BLOCK, code, "rule hit");
         bmetrics::record_action(eval.host, Action::BLOCK);
         block_response(eval.state, *code).tagged(&rule.name, Action::BLOCK)
      },
      Action::Code(code) => {
         tracing::debug!(rule = rule.name, action = Action::CODE, code, "rule hit");
         bmetrics::record_action(eval.host, Action::CODE);
         RuleOutcome::Handled(body::status(
            StatusCode::from_u16(*code).unwrap_or(StatusCode::FORBIDDEN),
         ))
         .tagged(&rule.name, Action::CODE)
      },
      Action::Drop => {
         tracing::debug!(rule = rule.name, action = Action::DROP, "rule hit");
         bmetrics::record_action(eval.host, Action::DROP);
         RuleOutcome::Drop
      },
      Action::Tarpit { maze } => {
         tracing::debug!(rule = rule.name, action = Action::TARPIT, maze, "rule hit");
         bmetrics::record_action(eval.host, Action::TARPIT);
         let client_ip = eval.ctx.remote_ip;
         RuleOutcome::Handled(tarpit_response(eval.state, maze, eval.host, client_ip).await)
            .tagged(&rule.name, Action::TARPIT)
      },
      Action::Smear => {
         tracing::debug!(rule = rule.name, action = Action::SMEAR, "rule hit");
         bmetrics::record_action(eval.host, Action::SMEAR);
         smear_response(eval.state, eval.request_uri, eval.user_agent)
            .tagged(&rule.name, Action::SMEAR)
      },
      Action::Report { kind } => {
         tracing::debug!(rule = rule.name, action = Action::REPORT, kind, "rule hit");
         bmetrics::record_action(eval.host, Action::REPORT);
         emit_offense(
            eval.state,
            eval.ctx.remote_ip,
            eval.host,
            Some(&rule.name),
            &rule.name,
            OffenseKind::Report(kind.clone()),
            repository_key(eval.host, eval.request_uri.path()),
         );
         RuleOutcome::Continue
      },
      Action::Context {
         response_headers,
         request_headers,
      } => {
         tracing::debug!(rule = rule.name, action = Action::CONTEXT, "rule hit");
         bmetrics::record_action(eval.host, Action::CONTEXT);
         let child_ctx = eval.ctx.with_request_headers(request_headers);
         let mut child_scope = child_ctx.scope();
         let mut merged = eval.headers.clone();
         for (name, value) in request_headers {
            merged.insert(name.clone(), value.clone());
         }
         let mut child_eval = Eval {
            state:           eval.state,
            ctx:             &child_ctx,
            scope:           &mut child_scope,
            challenge_state: &mut *eval.challenge_state,
            host:            eval.host,
            request_uri:     eval.request_uri,
            user_agent:      eval.user_agent,
            headers:         &merged,
         };
         eval_children(
            &rule.children,
            &mut child_eval,
            Some((&merged, response_headers)),
         )
         .await
      },
      Action::Proxy {
         match_re,
         rewrite,
         backend,
      } => {
         tracing::debug!(
            rule = rule.name,
            action = Action::PROXY,
            backend,
            "rule hit"
         );
         bmetrics::record_action(eval.host, Action::PROXY);
         proxy_outcome(match_re.as_ref(), rewrite, backend, eval.request_uri)
            .tagged(&rule.name, Action::PROXY)
      },
      Action::Challenge(ca) | Action::Check(ca) => {
         let continue_after_issue = matches!(rule.action, Action::Check(_));
         evaluate_challenge_action(&rule.name, ca, eval, continue_after_issue)
            .await
            .tagged(&rule.name, rule.action.label())
      },
   }
}

fn repository_key(host: &str, path: &str) -> Option<String> {
   let mut segments = path.split('/').filter(|segment| !segment.is_empty());
   let first = segments.next()?;
   let (owner, repository) =
      if first == "api" && segments.next()? == "v1" && segments.next()? == "repos" {
         (segments.next()?, segments.next()?)
      } else {
         (first, segments.next()?)
      };
   let repository = repository.trim_end_matches(".git");
   (!repository.is_empty()).then(|| format!("{host}/{owner}/{repository}"))
}

async fn evaluate_challenge_action(
   rule_name: &str,
   ca: &ChallengeAction,
   eval: &mut Eval<'_>,
   continue_after_issue: bool,
) -> RuleOutcome {
   let now = unix_timestamp();
   let client_ip = eval.ctx.remote_ip;

   for challenge_name in &ca.challenges {
      let Some(reg) = eval.state.policy.challenges.get(challenge_name) else {
         tracing::warn!(challenge = challenge_name, "challenge not registered");
         continue;
      };

      let step = reg.duration.as_secs() as i64;
      let expiry = bucket_expiry(now, step);
      let challenge_key = derive_challenge_key(
         challenge_name,
         client_ip,
         expiry,
         &eval.state.keys.key_fingerprint,
      );
      let previous_key = derive_challenge_key(
         challenge_name,
         client_ip,
         expiry - step,
         &eval.state.keys.key_fingerprint,
      );

      if eval
         .challenge_state
         .is_challenge_passed(challenge_name, &challenge_key)
         || eval
            .challenge_state
            .is_challenge_passed(challenge_name, &previous_key)
      {
         tracing::debug!(
            rule = rule_name,
            challenge = challenge_name,
            "challenge already passed"
         );
         bmetrics::record_challenge_passed(eval.host, challenge_name);
         continue;
      }

      let (meta_tags, link_tags) = if reg.class == ChallengeClass::Blocking {
         let backend = eval.state.runtime.backends.select(eval.host);
         if let Some(ref backend) = backend {
            let tags = tag_fetcher::fetch_tags(
               eval.host,
               &eval.state.runtime.tag_cache,
               &eval.state.runtime.http_client,
               &backend.target,
            )
            .await;
            tag_fetcher::tags_to_template_values(&tags)
         } else {
            (Vec::new(), Vec::new())
         }
      } else {
         (Vec::new(), Vec::new())
      };

      let mut ctx = ChallengeContext::new(
         challenge_name,
         &challenge_key,
         eval.host,
         client_ip,
         eval.request_uri,
      );
      ctx.meta_tags = meta_tags;
      ctx.link_tags = link_tags;
      ctx.strings = &eval.state.config.strings;
      ctx.links = &eval.state.config.links;
      ctx.logo = eval.state.config.challenge_template_logo.as_deref();

      // Check mode injects a challenge fragment into the proxied response.
      if continue_after_issue && let Some(widget) = reg.runtime.embed_widget(&ctx) {
         eval.challenge_state.injections.push(template::render_embed(
            eval.state.runtime.theme,
            &eval.state.runtime.custom_theme,
            &widget,
         ));
         bmetrics::record_challenge_issued(eval.host, challenge_name);
         tracing::debug!(
            rule = rule_name,
            challenge = challenge_name,
            "challenge issued (background)"
         );
         continue;
      }

      let result = reg
         .runtime
         .issue(
            &ctx,
            eval.state.runtime.theme,
            &eval.state.runtime.custom_theme,
            ca.http_code,
         )
         .await;

      match result {
         IssueResult::Response(resp) => {
            // Only verify endpoints may seal a passed state.
            bmetrics::record_challenge_issued(eval.host, challenge_name);
            tracing::debug!(
               rule = rule_name,
               challenge = challenge_name,
               "challenge issued (response)"
            );

            if !continue_after_issue {
               return RuleOutcome::Handled(resp);
            }
         },
         IssueResult::Passed => {
            eval
               .challenge_state
               .issue_challenge(challenge_name, &challenge_key, reg.duration);
            bmetrics::record_challenge_passed(eval.host, challenge_name);
            tracing::debug!(
               rule = rule_name,
               challenge = challenge_name,
               "challenge passed (transparent)"
            );
         },
         IssueResult::Failed => {
            bmetrics::record_challenge_failed(eval.host, challenge_name);
            tracing::debug!(
               rule = rule_name,
               challenge = challenge_name,
               "challenge failed"
            );
            if !continue_after_issue {
               return dispatch_sub_action(&ca.fail_action, eval);
            }
         },
         IssueResult::Skip => {
            tracing::debug!(
               rule = rule_name,
               challenge = challenge_name,
               "challenge skipped"
            );
         },
      }
   }

   if continue_after_issue {
      RuleOutcome::Continue
   } else {
      dispatch_sub_action(&ca.pass_action, eval)
   }
}

fn dispatch_sub_action(action: &Action, eval: &Eval<'_>) -> RuleOutcome {
   match action {
      Action::Deny { code } => {
         bmetrics::record_action(eval.host, Action::DENY);
         deny_response(eval.state, *code)
      },
      Action::Block { code } => {
         bmetrics::record_action(eval.host, Action::BLOCK);
         block_response(eval.state, *code)
      },
      Action::Drop => {
         bmetrics::record_action(eval.host, Action::DROP);
         RuleOutcome::Drop
      },
      Action::Smear => {
         bmetrics::record_action(eval.host, Action::SMEAR);
         smear_response(eval.state, eval.request_uri, eval.user_agent)
      },
      _ => {
         bmetrics::record_action(eval.host, Action::PASS);
         RuleOutcome::Handled(pass_response())
      },
   }
}
