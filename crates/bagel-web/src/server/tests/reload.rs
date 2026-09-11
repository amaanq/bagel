use std::time::Duration;

use super::fixtures::*;
use crate::{
   config::policy::RendererConfig,
   maze::renderer::Backend,
};

#[tokio::test]
async fn proxy_trust_follows_the_reloaded_configuration() {
   let shared = proxy_protocol_deny_app("127.0.0.0/8").await;
   let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
   assert!(trusts_proxy_peer(&shared, peer));

   let mut config = shared.load().config.clone();
   config.trusted_proxies = Some(vec!["192.0.2.0/24".to_owned()]);
   reload_shared(config, &shared).await;
   assert!(!trusts_proxy_peer(&shared, peer));

   let mut config = shared.load().config.clone();
   config.trusted_proxies = Some(vec!["127.0.0.0/8".to_owned()]);
   reload_shared(config, &shared).await;
   assert!(trusts_proxy_peer(&shared, peer));

   let mut config = shared.load().config.clone();
   config.bind.proxy_protocol = false;
   reload_shared(config, &shared).await;
   assert!(!trusts_proxy_peer(&shared, peer));
}

#[tokio::test]
async fn reload_preserves_runtime_state_and_keys() {
   let shared = maze_shared().await;
   let old = shared.load_full();
   let source = SourceNetwork::from_ip(IP_A);
   old.runtime
      .poison
      .set([7; 32], "default", Duration::from_hours(1));
   assert_eq!(
      old.runtime
         .rate_tracker
         .record("example.test", source)
         .last_60s,
      1
   );

   reload_shared(old.config.clone(), &shared).await;
   let current = shared.load_full();
   assert!(!Arc::ptr_eq(&old, &current));
   assert!(Arc::ptr_eq(&old.runtime.poison, &current.runtime.poison));
   assert!(Arc::ptr_eq(
      &old.runtime.rate_tracker,
      &current.runtime.rate_tracker
   ));
   assert!(Arc::ptr_eq(
      &old.runtime.deceiver,
      &current.runtime.deceiver
   ));
   assert!(Arc::ptr_eq(&old.hooks, &current.hooks));
   assert_eq!(old.keys.pkcs8_seed, current.keys.pkcs8_seed);
   assert_eq!(old.keys.poison_master, current.keys.poison_master);
   assert!(current.runtime.poison.contains(&[7; 32]));
   assert_eq!(
      current
         .runtime
         .rate_tracker
         .record("example.test", source)
         .last_60s,
      2
   );
}

#[tokio::test]
async fn rejected_reload_preserves_poison_until_a_valid_ttl_change() {
   let shared = maze_shared().await;
   let old = shared.load_full();
   old.runtime
      .poison
      .set([7; 32], "default", Duration::from_hours(1));

   let mut config = old.config.clone();
   config.policy.mazes[0].memory_ttl = Duration::from_hours(2);
   let mut invalid = config.clone();
   invalid.trusted_proxies = Some(vec!["invalid-cidr".to_owned()]);
   reload_shared(invalid, &shared).await;
   assert!(Arc::ptr_eq(&old, &shared.load_full()));
   assert!(old.runtime.poison.contains(&[7; 32]));

   reload_shared(config, &shared).await;
   assert!(!Arc::ptr_eq(&old, &shared.load_full()));
   assert!(!shared.load().runtime.poison.contains(&[7; 32]));
}

#[tokio::test]
async fn renderer_reuse_tracks_its_deception_configuration() {
   let shared = maze_shared().await;
   let mut config = shared.load().config.clone();
   config.policy.renderers = vec![
      RendererConfig {
         name: "local".to_owned(),
         kind: "markov".to_owned(),
         ..RendererConfig::default()
      },
      RendererConfig {
         name: "remote".to_owned(),
         kind: "iocaine".to_owned(),
         endpoint: "http://127.0.0.1:9/render".to_owned(),
         ..RendererConfig::default()
      },
   ];
   reload_shared(config, &shared).await;
   let old = shared.load_full();

   reload_shared(old.config.clone(), &shared).await;
   let unchanged = shared.load_full();
   for name in ["local", "remote"] {
      assert!(Arc::ptr_eq(
         &old.runtime.renderers[name],
         &unchanged.runtime.renderers[name]
      ));
   }

   let mut config = unchanged.config.clone();
   config.deception.server = "reload-test".to_owned();
   reload_shared(config, &shared).await;
   let current = shared.load_full();
   assert!(!Arc::ptr_eq(
      &old.runtime.deceiver,
      &current.runtime.deceiver
   ));
   assert!(!Arc::ptr_eq(
      &old.runtime.renderers["local"],
      &current.runtime.renderers["local"]
   ));
   assert!(Arc::ptr_eq(
      &old.runtime.renderers["remote"],
      &current.runtime.renderers["remote"]
   ));
   assert!(matches!(
      &current.runtime.renderers["local"].backend,
      Backend::Markov(deceiver) if Arc::ptr_eq(deceiver, &current.runtime.deceiver)
   ));
}
