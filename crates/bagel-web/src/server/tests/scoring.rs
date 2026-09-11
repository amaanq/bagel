use super::fixtures::*;

#[tokio::test]
async fn first_matching_scorecard_wins() {
   let shared = scoring_shared(r#"scoring { scorecard "a" condition="path.starts_with(\"/a\")" mode="enforce" { signal "always" condition="true" weight=100; threshold 50 action="deny" http-code=451 } scorecard "b" condition="true" mode="enforce" { signal "always" condition="true" weight=100; threshold 50 action="deny" } }"#).await;
   let (status, _) = send(&shared, "/a").await;
   assert_eq!(status, StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
   let (status, _) = send(&shared, "/b").await;
   assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn signal_errors_contribute_zero() {
   let shared = scoring_shared(r#"scoring { scorecard "default" mode="enforce" { signal "works" condition="true" weight=55; signal "broken" condition="undefined_variable > 1" weight=100; threshold 50 action="deny"; threshold 100 action="deny" http-code=451 } }"#).await;
   let (status, _) = send(&shared, "/").await;
   assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn highest_eligible_threshold_wins() {
   let shared = scoring_shared(r#"scoring { scorecard "default" mode="enforce" { signal "always" condition="true" weight=100; threshold 50 action="deny"; threshold 90 action="deny" http-code=451; threshold 200 action="deny" http-code=402 } }"#).await;
   let (status, _) = send(&shared, "/").await;
   assert_eq!(status, StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
}

#[tokio::test]
async fn observe_mode_never_applies_the_candidate() {
   let shared = scoring_shared(r#"scoring { scorecard "default" mode="observe" { signal "always" condition="true" weight=100; threshold 50 action="deny" } }"#).await;
   let (status, body) = send(&shared, "/").await;
   assert_eq!(status, StatusCode::OK);
   assert_eq!(body, "main / -");
}

#[tokio::test]
async fn terminal_pass_rule_suppresses_enforcement() {
   let shared = scoring_shared(r#"scoring { scorecard "default" mode="enforce" { signal "always" condition="true" weight=100; threshold 50 action="deny" } } rules { rule "allow" condition="path.starts_with(\"/allowed\")" action="pass" }"#).await;
   let (status, _) = send(&shared, "/allowed").await;
   assert_eq!(status, StatusCode::OK);
   let (status, _) = send(&shared, "/other").await;
   assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rate_signals_drive_enforcement() {
   let shared = scoring_shared(r#"scoring { scorecard "default" mode="enforce" { signal "burst" condition="rate[\"available\"] && rate[\"10s\"] > 2" weight=100; threshold 50 action="deny" } }"#).await;
   let (status, _) = send(&shared, "/").await;
   assert_eq!(status, StatusCode::OK);
   let (status, _) = send(&shared, "/").await;
   assert_eq!(status, StatusCode::OK);
   let (status, _) = send(&shared, "/").await;
   assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn context_request_headers_reach_children() {
   let shared = context_shared(r#"rule "ctx" action="context" { request-headers { x-test "1" }; rule "child" condition="headers[\"x-test\"] == \"1\"" action="deny" }"#).await;
   let (status, _) = send(&shared, "/").await;
   assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn context_mutations_do_not_leak_into_siblings() {
   let shared = context_shared(r#"rule "ctx" action="context" { request-headers { x-test "1" } } rule "sib" condition="headers[\"x-test\"] == \"1\"" action="deny""#).await;
   let (status, body) = send(&shared, "/").await;
   assert_eq!(status, StatusCode::OK);
   assert_eq!(body, "main / -");
}

#[tokio::test]
async fn context_response_headers_modify_child_responses() {
   let shared = context_shared(r#"rule "ctx" action="context" { response-headers { x-resp "yes" }; rule "child" condition="true" action="deny" }"#).await;
   let resp = send_raw(&shared, "/").await;
   assert_eq!(resp.status(), StatusCode::FORBIDDEN);
   assert_eq!(resp.headers().get("x-resp").unwrap(), "yes");
}
