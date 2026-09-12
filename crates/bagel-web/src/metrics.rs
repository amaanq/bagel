use metrics::{
   counter,
   describe_counter,
   describe_histogram,
   histogram,
};

/// Histogram buckets for `bagel_scoring_score`.
pub const SCORE_BUCKETS: [f64; 11] = [
   0.0_f64, 10.0_f64, 20.0_f64, 40.0_f64, 60.0_f64, 80.0_f64, 100.0_f64, 150.0_f64, 200.0_f64,
   300.0_f64, 500.0_f64,
];

pub fn init_metrics() {
   describe_counter!("bagel_rule_results", "Rule evaluation results");
   describe_counter!("bagel_action_results", "Action execution results");
   describe_counter!(
      "bagel_challenge_results",
      "Challenge issuance/verification results"
   );
   describe_counter!("bagel_scoring_signal_total", "Matched scoring signals");
   describe_counter!(
      "bagel_scoring_signal_error_total",
      "Scoring signal expression errors"
   );
   describe_counter!(
      "bagel_scoring_decision_total",
      "Scoring decisions by scorecard, mode, candidate status, and action kind"
   );
   describe_histogram!("bagel_scoring_score", "Numeric score per scored request");
   describe_counter!(
      "bagel_poison_requests_total",
      "Maze requests by maze and token classification"
   );
   describe_counter!(
      "bagel_maze_renderer_requests_total",
      "Maze renderer invocations by renderer kind and result"
   );
   describe_counter!(
      "bagel_offenses_total",
      "Verdicts handed to the defense plane by kind and outcome"
   );
}

pub fn record_rule_hit(site: &str, rule_name: &str) {
   counter!("bagel_rule_results", "site" => site.to_owned(), "rule" => rule_name.to_owned(), "result" => "hit").increment(1);
}

pub fn record_rule_miss(site: &str, rule_name: &str) {
   counter!("bagel_rule_results", "site" => site.to_owned(), "rule" => rule_name.to_owned(), "result" => "miss").increment(1);
}

pub fn record_action(site: &str, action: &str) {
   counter!("bagel_action_results", "site" => site.to_owned(), "action" => action.to_owned())
      .increment(1);
}

pub fn record_challenge_issued(site: &str, challenge: &str) {
   counter!("bagel_challenge_results", "site" => site.to_owned(), "challenge" => challenge.to_owned(), "action" => "issued")
      .increment(1);
}

pub fn record_challenge_passed(site: &str, challenge: &str) {
   counter!("bagel_challenge_results", "site" => site.to_owned(), "challenge" => challenge.to_owned(), "action" => "passed")
      .increment(1);
}

pub fn record_challenge_failed(site: &str, challenge: &str) {
   counter!("bagel_challenge_results", "site" => site.to_owned(), "challenge" => challenge.to_owned(), "action" => "failed")
      .increment(1);
}

pub fn record_signal_match(site: &str, scorecard: &str, signal: &str) {
   counter!("bagel_scoring_signal_total", "site" => site.to_owned(), "scorecard" => scorecard.to_owned(), "signal" => signal.to_owned()).increment(1);
}

pub fn record_signal_error(site: &str, scorecard: &str, signal: &str) {
   counter!("bagel_scoring_signal_error_total", "site" => site.to_owned(), "scorecard" => scorecard.to_owned(), "signal" => signal.to_owned()).increment(1);
}

pub fn record_scoring_decision(
   site: &str,
   scorecard: &str,
   mode: &'static str,
   status: &'static str,
   action: &'static str,
) {
   counter!(
      "bagel_scoring_decision_total",
      "site" => site.to_owned(),
      "scorecard" => scorecard.to_owned(),
      "mode" => mode,
      "status" => status,
      "action" => action
   )
   .increment(1);
}

pub fn record_score(site: &str, scorecard: &str, score: u32) {
   histogram!("bagel_scoring_score", "site" => site.to_owned(), "scorecard" => scorecard.to_owned()).record(f64::from(score));
}

pub fn record_poison_request(site: &str, maze: &str, classification: &'static str) {
   counter!("bagel_poison_requests_total", "site" => site.to_owned(), "maze" => maze.to_owned(), "classification" => classification).increment(1);
}

pub fn record_offense(site: &str, kind: &str, result: &'static str) {
   counter!("bagel_offenses_total", "site" => site.to_owned(), "kind" => kind.to_owned(), "result" => result).increment(1);
}

pub fn record_maze_render(site: &str, renderer: &'static str, result: &'static str) {
   counter!("bagel_maze_renderer_requests_total", "site" => site.to_owned(), "renderer" => renderer, "result" => result)
      .increment(1);
}
