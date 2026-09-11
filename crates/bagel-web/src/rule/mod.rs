pub mod action;
pub mod condition;
pub mod scoring;

use std::collections::HashMap;

use action::Action;
use rhai::{
   AST,
   Engine,
};

use crate::{
   body::Response,
   config::policy::RuleConfig,
   error,
};

/// Compiled rule state, ready for per-request evaluation.
#[derive(Clone)]
pub struct RuleState {
   pub name:      String,
   pub condition: Option<AST>,
   pub action:    Action,
   pub children:  Vec<Self>,
}

/// Outcome of evaluating a single rule.
pub enum RuleOutcome {
   Continue,
   /// A response has been produced, so rule processing stops.
   Handled(Response),
   /// Reset the connection without writing a response.
   Drop,
}

impl RuleOutcome {
   /// Attribute a handled response to a rule, keeping the tag an inner rule
   /// already applied so the trace names the rule that decided.
   #[must_use]
   pub fn tagged(self, rule: &str, action: &'static str) -> Self {
      match self {
         Self::Handled(mut resp) => {
            if resp.extensions().get::<TerminalRuleInfo>().is_none() {
               resp.extensions_mut().insert(TerminalRuleInfo {
                  rule: rule.to_owned(),
                  action,
               });
            }
            Self::Handled(resp)
         },
         other => other,
      }
   }
}

impl RuleState {
   pub fn build_rules(
      configs: &[RuleConfig],
      engine: &Engine,
      named_conditions: &HashMap<String, String>,
      default_http_code: u16,
      parent_name: &str,
   ) -> error::Result<Vec<Self>> {
      let mut rules = Vec::new();

      for cfg in configs {
         let full_name = if parent_name.is_empty() {
            cfg.name.clone()
         } else {
            format!("{}/{}", parent_name, cfg.name)
         };

         let condition = if let Some(ref expr) = cfg.condition {
            let expanded = condition::expand_condition_macros(expr.as_ref(), named_conditions);
            match engine.compile_expression(&expanded) {
               Ok(ast) => Some(ast),
               Err(err) => {
                  tracing::error!(
                      rule = full_name,
                      expr = expanded,
                      error = %err,
                      "failed to compile rule condition"
                  );
                  return Err(error::Error::Config(format!(
                     "rule '{full_name}' condition compile error: {err}"
                  )));
               },
            }
         } else {
            None
         };

         let action = Action::parse(
            &cfg.action,
            &cfg.settings,
            &cfg.challenges,
            default_http_code,
         )
         .map_err(|err| error::Error::Config(format!("rule '{full_name}': {err}")))?;

         let children = Self::build_rules(
            &cfg.children,
            engine,
            named_conditions,
            default_http_code,
            &full_name,
         )?;

         rules.push(Self {
            name: full_name,
            condition,
            action,
            children,
         });
      }

      Ok(rules)
   }
}

/// Extension marker indicating the rule outcome is "pass to backend".
#[derive(Clone, Copy)]
pub struct PassMarker;

/// Extension marker indicating the rule outcome is "proxy to a named backend",
/// with the path already rewritten when the rule's match applied.
#[derive(Clone)]
pub struct ProxyMarker {
   pub backend:        String,
   pub rewritten_path: Option<String>,
}

/// Extension recording which rule produced a handled response and with what
/// action kind, for the decision trace.
#[derive(Clone)]
pub struct TerminalRuleInfo {
   pub rule:   String,
   pub action: &'static str,
}

/// Request headers accumulated from enclosing `context` rules, applied to the
/// upstream request when the terminal outcome inside the subtree proxies.
#[derive(Clone)]
pub struct PendingRequestHeaders(pub http::HeaderMap);

/// Response headers from enclosing `context` rules, applied once the upstream
/// response for a marker outcome exists.
#[derive(Clone)]
pub struct PendingResponseHeaders(pub http::HeaderMap);
