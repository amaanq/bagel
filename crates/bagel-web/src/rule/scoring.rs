use std::collections::{
   HashMap,
   HashSet,
};

use rhai::{
   AST,
   Engine,
   Scope,
};

use super::{
   action::Action,
   condition::expand_condition_macros,
};
use crate::{
   config::policy::ScoringConfig,
   error::{
      Error,
      Result,
   },
   net::rate,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScoreMode {
   Observe,
   Enforce,
}

impl ScoreMode {
   #[must_use]
   pub const fn as_str(self) -> &'static str {
      match self {
         Self::Observe => "observe",
         Self::Enforce => "enforce",
      }
   }
}

#[derive(Clone)]
pub struct SignalState {
   pub name:      String,
   pub condition: AST,
   pub weight:    u32,
}

#[derive(Clone)]
pub struct ThresholdState {
   pub value:  u32,
   pub action: Action,
   pub kind:   &'static str,
}

#[derive(Clone)]
pub struct ScorecardState {
   pub name:       String,
   pub condition:  Option<AST>,
   pub mode:       ScoreMode,
   pub signals:    Vec<SignalState>,
   /// Sorted ascending by value, so the candidate is the last one not
   /// exceeding the score.
   pub thresholds: Vec<ThresholdState>,
}

#[derive(Clone)]
pub struct ScoringState {
   pub rate_capacity: usize,
   pub scorecards:    Vec<ScorecardState>,
}

/// Result of evaluating the first matching scorecard for one request.
pub struct ScoreResult<'a> {
   pub scorecard: &'a ScorecardState,
   pub score:     u32,
   pub matched:   Vec<&'a str>,
   pub errors:    Vec<&'a str>,
   pub candidate: Option<&'a ThresholdState>,
}

const FORBIDDEN_THRESHOLD_ACTIONS: [&str; 4] = ["none", "context", "check", "pass"];

impl ScoringState {
   pub fn build(
      config: &ScoringConfig,
      engine: &Engine,
      named_conditions: &HashMap<String, String>,
      default_http_code: u16,
   ) -> Result<Self> {
      let rate_capacity = config.rate_capacity.unwrap_or(rate::DEFAULT_CAPACITY);
      if !(rate::MIN_CAPACITY..=rate::MAX_CAPACITY).contains(&rate_capacity) {
         return Err(Error::Config(format!(
            "scoring rate-capacity {rate_capacity} is outside {}..={}",
            rate::MIN_CAPACITY,
            rate::MAX_CAPACITY
         )));
      }

      let mut scorecards = Vec::new();
      let mut card_names = HashSet::new();
      let mut unconditional: Option<&str> = None;

      for card in &config.scorecards {
         if !card_names.insert(card.name.as_str()) {
            return Err(Error::Config(format!(
               "duplicate scorecard '{}'",
               card.name
            )));
         }
         if let Some(first) = unconditional {
            return Err(Error::Config(format!(
               "scorecard '{}' is unreachable after unconditional scorecard '{first}'",
               card.name
            )));
         }

         let mode = match card.mode.as_deref() {
            None | Some("observe") => ScoreMode::Observe,
            Some("enforce") => ScoreMode::Enforce,
            Some(other) => {
               return Err(Error::Config(format!(
                  "scorecard '{}': unknown mode '{other}'",
                  card.name
               )));
            },
         };

         let condition = card
            .condition
            .as_ref()
            .map(|expr| compile(engine, named_conditions, expr.as_ref()))
            .transpose()
            .map_err(|err| Error::Config(format!("scorecard '{}': {err}", card.name)))?;
         if condition.is_none() {
            unconditional = Some(card.name.as_str());
         }

         let mut signals = Vec::new();
         let mut signal_names = HashSet::new();
         for signal in &card.signals {
            if !signal_names.insert(signal.name.as_str()) {
               return Err(Error::Config(format!(
                  "scorecard '{}': duplicate signal '{}'",
                  card.name, signal.name
               )));
            }
            if signal.weight == 0 {
               return Err(Error::Config(format!(
                  "scorecard '{}': signal '{}' has zero weight",
                  card.name, signal.name
               )));
            }
            let compiled =
               compile(engine, named_conditions, signal.condition.as_ref()).map_err(|err| {
                  Error::Config(format!(
                     "scorecard '{}': signal '{}': {err}",
                     card.name, signal.name
                  ))
               })?;
            signals.push(SignalState {
               name:      signal.name.clone(),
               condition: compiled,
               weight:    signal.weight,
            });
         }

         let mut thresholds = Vec::new();
         let mut values = HashSet::new();
         for threshold in &card.thresholds {
            if threshold.value == 0 {
               return Err(Error::Config(format!(
                  "scorecard '{}': threshold values must be positive",
                  card.name
               )));
            }
            if !values.insert(threshold.value) {
               return Err(Error::Config(format!(
                  "scorecard '{}': duplicate threshold value {}",
                  card.name, threshold.value
               )));
            }
            let kind = threshold.action.to_lowercase();
            if FORBIDDEN_THRESHOLD_ACTIONS.contains(&kind.as_str()) {
               return Err(Error::Config(format!(
                  "scorecard '{}': threshold {} may not use action '{kind}'",
                  card.name, threshold.value
               )));
            }
            let action = Action::parse(
               &threshold.action,
               &threshold.settings,
               &threshold.challenges,
               default_http_code,
            )
            .map_err(|err| {
               Error::Config(format!(
                  "scorecard '{}': threshold {}: {err}",
                  card.name, threshold.value
               ))
            })?;
            if matches!(action, Action::Challenge(_)) && threshold.challenges.is_empty() {
               return Err(Error::Config(format!(
                  "scorecard '{}': challenge threshold {} has no challenges",
                  card.name, threshold.value
               )));
            }
            thresholds.push(ThresholdState {
               value: threshold.value,
               action,
               kind: action_kind(&kind),
            });
         }
         thresholds.sort_by_key(|threshold| threshold.value);

         scorecards.push(ScorecardState {
            name: card.name.clone(),
            condition,
            mode,
            signals,
            thresholds,
         });
      }

      Ok(Self {
         rate_capacity,
         scorecards,
      })
   }

   /// Select and evaluate the first matching scorecard.
   #[must_use]
   pub fn evaluate(
      &self,
      engine: &Engine,
      script_scope: &mut Scope<'static>,
   ) -> Option<ScoreResult<'_>> {
      let card = self.scorecards.iter().find(|card| {
         card.condition.as_ref().is_none_or(|ast| {
            match engine.eval_ast_with_scope::<bool>(script_scope, ast) {
               Ok(matched) => matched,
               Err(err) => {
                  tracing::error!(scorecard = card.name, error = %err, "scorecard condition error");
                  false
               },
            }
         })
      })?;

      let mut total_score = 0_u32;
      let mut matched = Vec::new();
      let mut errors = Vec::new();

      for signal in &card.signals {
         match engine.eval_ast_with_scope::<bool>(script_scope, &signal.condition) {
            Ok(true) => {
               total_score = total_score.saturating_add(signal.weight);
               matched.push(signal.name.as_str());
            },
            Ok(false) => {},
            Err(err) => {
               tracing::error!(
                  scorecard = card.name,
                  signal = signal.name,
                  error = %err,
                  "signal expression error"
               );
               errors.push(signal.name.as_str());
            },
         }
      }

      let candidate = card
         .thresholds
         .iter()
         .rev()
         .find(|threshold| threshold.value <= total_score);

      Some(ScoreResult {
         scorecard: card,
         score: total_score,
         matched,
         errors,
         candidate,
      })
   }
}

fn action_kind(action: &str) -> &'static str {
   match action {
      "challenge" => "challenge",
      "deny" => "deny",
      "block" => "block",
      "code" => "code",
      "drop" => "drop",
      "proxy" => "proxy",
      "tarpit" => "tarpit",
      "smear" => "smear",
      _ => "unknown",
   }
}

fn compile(
   engine: &Engine,
   named_conditions: &HashMap<String, String>,
   expr: &str,
) -> std::result::Result<AST, String> {
   let expanded = expand_condition_macros(expr, named_conditions);
   engine
      .compile_expression(&expanded)
      .map_err(|err| format!("condition compile error: {err}"))
}
