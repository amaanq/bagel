//! In-process offense records from the HTTP data plane.

use std::{
   net::IpAddr,
   sync::atomic::{
      AtomicU64,
      Ordering,
   },
   time::{
      SystemTime,
      UNIX_EPOCH,
   },
};

use ipnetwork::IpNetwork;
use tokio::sync::mpsc;

use crate::source::{
   Checkpoint,
   SourceRecord,
};

/// Why the web plane considers a request hostile.
#[derive(Clone, PartialEq, Eq)]
pub enum OffenseKind {
   Drop,
   Smear,
   Tarpit,
   PoisonReturn,
   Score { score: u32 },
   Report(String),
}

impl OffenseKind {
   /// Stable label used as the `kind` field of the record payload.
   #[must_use]
   pub const fn label(&self) -> &str {
      match self {
         Self::Drop => "drop",
         Self::Smear => "smear",
         Self::Tarpit => "tarpit",
         Self::PoisonReturn => "poison_return",
         Self::Score { .. } => "score",
         Self::Report(kind) => kind.as_str(),
      }
   }
}

/// One hostile request as seen by the web plane.
#[derive(Clone, PartialEq, Eq)]
pub struct Offense {
   pub address:   IpAddr,
   pub network:   IpNetwork,
   pub host:      String,
   pub rule:      Option<String>,
   pub detail:    String,
   pub kind:      OffenseKind,
   pub group_key: Option<String>,
}

/// A sequence-numbered in-memory source. Records carry a JSON payload so a
/// `json` detector can match on `/kind` and read the address from `/address`.
pub struct WebOffenseSource {
   name:     String,
   sender:   mpsc::Sender<SourceRecord>,
   sequence: AtomicU64,
}

impl WebOffenseSource {
   /// `last_sequence` is the last checkpoint the store holds for this source,
   /// so numbering resumes without colliding after a restart.
   pub fn new<Name: Into<String>>(
      name: Name,
      sender: mpsc::Sender<SourceRecord>,
      last_sequence: u64,
   ) -> Self {
      Self {
         name: name.into(),
         sender,
         sequence: AtomicU64::new(last_sequence),
      }
   }

   #[must_use]
   pub fn name(&self) -> &str {
      &self.name
   }

   /// Queue one offense without waiting. Returns false when the defense loop
   /// is not keeping up or has gone away, and the record is dropped rather
   /// than stalling the request path.
   pub fn emit(&self, offense: &Offense) -> bool {
      let sequence = self
         .sequence
         .fetch_add(1, Ordering::Relaxed)
         .saturating_add(1);
      let score = match &offense.kind {
         OffenseKind::Score { score } => Some(*score),
         _ => None,
      };
      let payload = serde_json::json!({
          "kind": offense.kind.label(),
          "address": offense.address,
          "network": offense.network.to_string(),
          "host": offense.host,
          "rule": offense.rule,
          "detail": offense.detail,
          "score": score,
          "group_key": offense.group_key,
      });
      let record = SourceRecord {
         source:      self.name.clone(),
         id:          format!("listener:{}:{sequence}", self.name),
         payload:     payload.to_string(),
         correlation: None,
         observed_at: now(),
         checkpoint:  Checkpoint::Listener { sequence },
         oversized:   false,
      };
      self.sender.try_send(record).is_ok()
   }
}

fn now() -> u64 {
   SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map(|duration| duration.as_secs())
      .unwrap_or_default()
}

#[cfg(test)]
mod tests {
   use super::*;

   fn offense(kind: OffenseKind) -> Offense {
      Offense {
         address: "203.0.113.7".parse().unwrap(),
         network: "203.0.113.0/24".parse().unwrap(),
         host: "example.test".into(),
         rule: Some("probe".into()),
         detail: "smear".into(),
         kind,
         group_key: None,
      }
   }

   #[test]
   fn records_carry_json_and_resume_sequences() {
      let (sender, mut receiver) = mpsc::channel(4);
      let source = WebOffenseSource::new("bagel-web", sender, 41);
      assert!(source.emit(&offense(OffenseKind::Smear)));
      assert!(source.emit(&offense(OffenseKind::Score { score: 120 })));

      let first = receiver.try_recv().unwrap();
      assert_eq!(first.source, "bagel-web");
      assert_eq!(first.id, "listener:bagel-web:42");
      assert_eq!(first.checkpoint, Checkpoint::Listener { sequence: 42 });
      assert!(!first.oversized);
      let payload: serde_json::Value = serde_json::from_str(&first.payload).unwrap();
      assert_eq!(payload["kind"], "smear");
      assert_eq!(payload["address"], "203.0.113.7");
      assert_eq!(payload["network"], "203.0.113.0/24");
      assert_eq!(payload["host"], "example.test");
      assert_eq!(payload["rule"], "probe");
      assert!(payload["score"].is_null());

      let second = receiver.try_recv().unwrap();
      assert_eq!(second.checkpoint, Checkpoint::Listener { sequence: 43 });
      let payload: serde_json::Value = serde_json::from_str(&second.payload).unwrap();
      assert_eq!(payload["kind"], "score");
      assert_eq!(payload["score"], 120);
   }

   #[test]
   fn full_or_closed_channels_drop_the_record() {
      let (sender, receiver) = mpsc::channel(1);
      let source = WebOffenseSource::new("bagel-web", sender, 0);
      assert!(source.emit(&offense(OffenseKind::Drop)));
      assert!(!source.emit(&offense(OffenseKind::Drop)));
      drop(receiver);
      assert!(!source.emit(&offense(OffenseKind::Drop)));
   }
}
