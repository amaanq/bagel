use super::fixtures::*;

#[tokio::test]
async fn scorecard_after_unconditional_is_rejected() {
   let err = policy_err(r#"scoring { scorecard "a" mode="enforce" { signal "always" condition="true" weight=100; threshold 50 action="deny" } scorecard "b" condition="true" { signal "always" condition="true" weight=100; threshold 50 action="deny" } }"#).await;
   assert!(err.contains("unreachable"), "{err}");
}

#[tokio::test]
async fn representative_config_rejections() {
   let err =
      policy_err(r#"rules { rule "r" action="proxy" backend="*" match="([" rewrite="/x" }"#).await;
   assert!(err.contains("invalid proxy match regex"), "{err}");

   let err = policy_err(r#"rules { rule "r" action="proxy" backend="missing" }"#).await;
   assert!(err.contains("unknown backend 'missing'"), "{err}");

   let err = top_level_err("smear { chunk-min 0 }").await;
   assert!(err.contains("smear: chunk-min"), "{err}");
}
