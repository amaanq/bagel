use std::{
   collections::BTreeMap,
   sync::{
      Arc,
      atomic::{
         AtomicUsize,
         Ordering,
      },
   },
   time::Duration,
};

use bagel_config::{
   Action,
   Config,
   EnforcementMode,
   Policy,
   Source,
};
use tokio_util::sync::CancellationToken;

use crate::defense::{
   Defense,
   RECORD_BATCH,
   RECORD_QUEUE,
   now,
};

#[cfg(test)]
static NEXT_DATABASE: AtomicUsize = AtomicUsize::new(0);

#[tokio::test]
async fn shutdown_drains_accepted_records_and_closes_the_source() {
   for queued in [0, 1, RECORD_BATCH + 1, RECORD_QUEUE] {
      let config = Config {
         database_path: ":memory:".into(),
         nft_path: "true".into(),
         sources: BTreeMap::from([("web".into(), Source::Web)]),
         policies: BTreeMap::from([("web".into(), Policy {
            source:          "web".into(),
            detector:        bagel_config::Detector::Json {
               equals:            BTreeMap::new(),
               address_pointer:   "/address".into(),
               timestamp_pointer: None,
               group_key_pointer: None,
               timestamp_format:  None,
            },
            ignore_networks: Vec::new(),
            max_attempts:    u32::MAX,
            findtime_secs:   600,
            ban:             bagel_config::BanSchedule::default(),
            action:          Action::Observe,
         })]),
         enforcement: bagel_config::Enforcement {
            mode: EnforcementMode::Observe,
            ..bagel_config::Enforcement::default()
         },
         ..Config::default()
      };
      let defense = Defense::open(Arc::new(config)).unwrap();
      defense.initialize().await.unwrap();
      let source = defense.web_source("web").unwrap();
      let offense = crate::offense::Offense {
         address:   "192.0.2.7".parse().unwrap(),
         network:   "192.0.2.7/32".parse().unwrap(),
         host:      "example.test".into(),
         rule:      None,
         detail:    "test".into(),
         kind:      crate::offense::OffenseKind::Score { score: 1 },
         group_key: None,
      };
      for _ in 0..queued {
         assert!(source.emit(&offense));
      }

      let shutdown = CancellationToken::new();
      shutdown.cancel();
      tokio::time::timeout(Duration::from_secs(5), Arc::clone(&defense).run(shutdown))
         .await
         .unwrap()
         .unwrap();

      assert!(!source.emit(&offense));
      assert!(!defense.is_ready());
      assert_eq!(
         defense
            .store_ref()
            .lock()
            .last_listener_sequence("web")
            .unwrap(),
         queued as u64
      );
      assert_eq!(
         defense
            .store_ref()
            .lock()
            .prune_offenses(now() + 1)
            .unwrap(),
         queued
      );
   }
}

#[tokio::test]
async fn maintenance_continues_without_streaming_sources() {
   let path = std::env::temp_dir().join(format!(
      "bagel-defense-{}-{}.sqlite3",
      std::process::id(),
      NEXT_DATABASE.fetch_add(1, Ordering::Relaxed)
   ));
   let config = Config {
      database_path: path.clone(),
      nft_path: "true".into(),
      enforcement: bagel_config::Enforcement {
         mode: EnforcementMode::Observe,
         reconcile_interval_secs: 1,
         ..bagel_config::Enforcement::default()
      },
      ..Config::default()
   };
   let defense = Defense::open(Arc::new(config)).unwrap();
   defense.initialize().await.unwrap();
   defense.manual_block("198.51.100.4", Some(2)).await.unwrap();
   assert_eq!(defense.bans().await.unwrap().len(), 1);

   let shutdown = CancellationToken::new();
   let task = tokio::spawn(Arc::clone(&defense).run(shutdown.clone()));
   tokio::time::timeout(Duration::from_secs(5), async {
      loop {
         if defense.bans().await.unwrap().is_empty() {
            break;
         }
         tokio::time::sleep(Duration::from_millis(100)).await;
      }
   })
   .await
   .unwrap();
   shutdown.cancel();
   task.await.unwrap().unwrap();

   let _ = std::fs::remove_file(path);
}
