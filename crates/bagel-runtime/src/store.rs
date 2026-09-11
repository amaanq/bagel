//! Durable source progress, offense windows, and enforcement leases.

use std::path::Path;

use bagel_config::{
   Action,
   BanSchedule,
};
use bagel_core::{
   Error,
   Result,
};
use ipnetwork::IpNetwork;
use rand::RngExt;
use rusqlite::{
   Connection,
   OptionalExtension,
   ToSql,
   Transaction,
   params,
};

use crate::source::Checkpoint;

const SCHEMA_VERSION: i64 = 2;
const MANUAL_POLICY: &str = "__manual__";

macro_rules! offense_window {
   () => {
      "policy = ?1 AND network = ?2 AND consumed = 0 AND observed_at >= ?3 AND observed_at <= ?4 \
       AND (?5 IS NULL OR attempt_key = ?5)"
   };
}

const COUNT_GROUPED_ATTEMPTS: &str =
   concat!("SELECT COUNT(*) FROM offenses WHERE ", offense_window!());

const COUNT_DISTINCT_ATTEMPTS: &str = concat!(
   "SELECT COUNT(DISTINCT attempt_key) + COUNT(*) - COUNT(attempt_key) FROM offenses WHERE ",
   offense_window!()
);

const CONSUME_ATTEMPTS: &str =
   concat!("UPDATE offenses SET consumed = 1 WHERE ", offense_window!());

#[derive(Clone)]
pub struct Lease {
   pub id:               i64,
   pub network:          IpNetwork,
   pub policy:           String,
   pub action:           Action,
   pub created_at:       u64,
   pub expires_at:       Option<u64>,
   pub escalation_count: u64,
   pub manual:           bool,
   pub apply_state:      String,
   pub last_error:       Option<String>,
}

pub struct OffenseInput<'a> {
   pub policy:                 &'a str,
   pub network:                IpNetwork,
   pub max_attempts:           u32,
   pub findtime_secs:          u64,
   pub history_retention_secs: u64,
   pub ban:                    &'a BanSchedule,
   pub action:                 &'a Action,
   pub observed_at:            Option<u64>,
   pub attempt_key:            Option<&'a str>,
   pub group_key:              Option<&'a str>,
}

pub struct EventInput<'a> {
   pub source:      &'a str,
   pub event_id:    &'a str,
   pub checkpoint:  &'a Checkpoint,
   pub observed_at: u64,
   pub offenses:    &'a [OffenseInput<'a>],
}

#[derive(Default)]
pub struct EventOutcome {
   pub duplicate: bool,
   pub leases:    Vec<Lease>,
}

#[derive(Clone, Eq, PartialEq)]
pub enum ApplyOutcome {
   Applied,
   Observed,
   Failed(String),
}

pub struct Store {
   connection: Connection,
}

impl Store {
   pub fn open(path: &Path) -> Result<Self> {
      let connection = Connection::open(path).map_err(db_error)?;
      connection
         .pragma_update(None, "journal_mode", "WAL")
         .map_err(db_error)?;
      connection
         .pragma_update(None, "synchronous", "FULL")
         .map_err(db_error)?;
      connection
         .pragma_update(None, "foreign_keys", "ON")
         .map_err(db_error)?;
      connection
         .busy_timeout(std::time::Duration::from_secs(5))
         .map_err(db_error)?;

      let version: i64 = connection
         .pragma_query_value(None, "user_version", |row| row.get(0))
         .map_err(db_error)?;
      match version {
         0 => create_schema(&connection)?,
         SCHEMA_VERSION => {},
         other => {
            return Err(Error::Config(format!(
               "unsupported defense database schema version {other}; expected {SCHEMA_VERSION}"
            )));
         },
      }
      Ok(Self { connection })
   }

   /// The highest `listener:{source}:N` event sequence stored for `source`,
   /// or zero. In-process sources resume from this so a restart never reuses
   /// an id the store already holds.
   pub fn last_listener_sequence(&self, source: &str) -> Result<u64> {
      let prefix = format!("listener:{source}:");
      let mut statement = self
         .connection
         .prepare("SELECT event_id FROM events WHERE source = ?1 AND event_id LIKE ?2")
         .map_err(db_error)?;
      let rows = statement
         .query_map(rusqlite::params![source, format!("{prefix}%")], |row| {
            row.get::<_, String>(0)
         })
         .map_err(db_error)?;
      let mut newest = 0;
      for row in rows {
         let id = row.map_err(db_error)?;
         if let Some(sequence) = id
            .strip_prefix(&prefix)
            .and_then(|rest| rest.parse::<u64>().ok())
         {
            newest = newest.max(sequence);
         }
      }
      Ok(newest)
   }

   pub fn checkpoint(&self, source: &str) -> Result<Option<Checkpoint>> {
      let data = self
         .connection
         .query_row(
            "SELECT data FROM checkpoints WHERE source = ?1",
            [source],
            |row| row.get::<_, String>(0),
         )
         .optional()
         .map_err(db_error)?;
      data
         .map(|data| serde_json::from_str(&data).map_err(json_error))
         .transpose()
   }

   /// Persist a record and all policy matches in one transaction. A source
   /// checkpoint can therefore never advance past an uncommitted offense.
   pub fn process_event(&mut self, input: &EventInput<'_>) -> Result<EventOutcome> {
      let transaction = self.connection.transaction().map_err(db_error)?;
      let outcome = Self::apply_event(&transaction, input)?;
      transaction.commit().map_err(db_error)?;
      Ok(outcome)
   }

   /// Apply several events in one transaction, in order. Outcomes are returned
   /// in the same order. One failing event rolls the whole batch back.
   pub fn process_events(&mut self, inputs: &[EventInput<'_>]) -> Result<Vec<EventOutcome>> {
      let transaction = self.connection.transaction().map_err(db_error)?;
      let mut outcomes = Vec::with_capacity(inputs.len());
      for input in inputs {
         if input.offenses.is_empty() {
            upsert_checkpoint(
               &transaction,
               input.source,
               input.event_id,
               input.checkpoint,
               input.observed_at,
            )?;
            outcomes.push(EventOutcome::default());
            continue;
         }
         outcomes.push(Self::apply_event(&transaction, input)?);
      }
      transaction.commit().map_err(db_error)?;
      Ok(outcomes)
   }

   fn apply_event(transaction: &Transaction<'_>, input: &EventInput<'_>) -> Result<EventOutcome> {
      let observed_at = sql_time(input.observed_at)?;
      let inserted = transaction
         .execute(
            "INSERT OR IGNORE INTO events(source, event_id, observed_at) VALUES (?1, ?2, ?3)",
            params![input.source, input.event_id, observed_at],
         )
         .map_err(db_error)?;
      if inserted == 0 {
         return Ok(EventOutcome {
            duplicate: true,
            leases:    Vec::new(),
         });
      }

      let mut leases = Vec::new();
      for offense in input.offenses {
         let observed_at = offense.observed_at.unwrap_or(input.observed_at);
         let offense_observed_at = sql_time(observed_at)?;
         let network = offense.network.to_string();
         transaction
            .execute(
               "INSERT INTO offenses( source, event_id, policy, network, observed_at, \
                attempt_key, consumed ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
               params![
                  input.source,
                  input.event_id,
                  offense.policy,
                  network,
                  offense_observed_at,
                  offense.group_key.or(offense.attempt_key),
               ],
            )
            .map_err(db_error)?;

         if has_active_lease(transaction, offense.policy, offense.network, observed_at)? {
            transaction
               .execute(
                  "UPDATE offenses SET consumed = 1 WHERE source = ?1 AND event_id = ?2 AND \
                   policy = ?3",
                  params![input.source, input.event_id, offense.policy],
               )
               .map_err(db_error)?;
            continue;
         }

         let window_start = sql_time(observed_at.saturating_sub(offense.findtime_secs))?;
         let window: [&dyn ToSql; 5] = [
            &offense.policy,
            &network,
            &window_start,
            &offense_observed_at,
            &offense.group_key,
         ];
         let count_sql = if offense.group_key.is_some() {
            COUNT_GROUPED_ATTEMPTS
         } else {
            COUNT_DISTINCT_ATTEMPTS
         };
         let attempts = transaction
            .query_row(count_sql, window.as_slice(), |row| row.get::<_, i64>(0))
            .map_err(db_error)
            .and_then(rust_time)?;
         if attempts < u64::from(offense.max_attempts) {
            continue;
         }

         let escalation_count = escalation_count(
            transaction,
            offense.policy,
            offense.network,
            offense.ban.overall,
            observed_at.saturating_sub(offense.history_retention_secs),
         )?;
         let duration = ban_duration(offense.ban, escalation_count);
         let expires_at =
            duration.map(|duration| observed_at.saturating_add(duration).min(i64::MAX as u64));
         let id = insert_lease(transaction, &NewLease {
            network: offense.network,
            policy: offense.policy,
            action: offense.action,
            created_at: observed_at,
            expires_at,
            escalation_count,
            manual: false,
         })?;
         transaction
            .execute(CONSUME_ATTEMPTS, window.as_slice())
            .map_err(db_error)?;
         leases.push(Lease {
            id,
            network: offense.network,
            policy: offense.policy.to_owned(),
            action: offense.action.clone(),
            created_at: observed_at,
            expires_at,
            escalation_count,
            manual: false,
            apply_state: "pending".into(),
            last_error: None,
         });
      }

      upsert_checkpoint(
         transaction,
         input.source,
         input.event_id,
         input.checkpoint,
         input.observed_at,
      )?;
      Ok(EventOutcome {
         duplicate: false,
         leases,
      })
   }

   pub fn active_leases(&self, now: u64) -> Result<Vec<Lease>> {
      let mut statement = self
         .connection
         .prepare(
            "SELECT id, network, policy, action, created_at, expires_at, escalation_count, \
             manual, apply_state, apply_error FROM leases WHERE revoked_at IS NULL AND expired_at \
             IS NULL AND (expires_at IS NULL OR expires_at > ?1) ORDER BY id",
         )
         .map_err(db_error)?;
      let rows = statement
         .query_map([sql_time(now)?], lease_from_row)
         .map_err(db_error)?;
      rows
         .map(|row| row.map_err(db_error).and_then(decode_lease))
         .collect()
   }

   pub fn expire(&mut self, now: u64) -> Result<usize> {
      self
         .connection
         .execute(
            "UPDATE leases SET expired_at = ?1 WHERE revoked_at IS NULL AND expired_at IS NULL \
             AND expires_at IS NOT NULL AND expires_at <= ?1",
            [sql_time(now)?],
         )
         .map_err(db_error)
   }

   /// Bound rolling-window history without touching durable lease history.
   pub fn prune_offenses(&mut self, before: u64) -> Result<usize> {
      let transaction = self.connection.transaction().map_err(db_error)?;
      let removed = transaction
         .execute("DELETE FROM offenses WHERE observed_at < ?1", [sql_time(
            before,
         )?])
         .map_err(db_error)?;
      transaction
         .execute(
            "DELETE FROM events WHERE NOT EXISTS ( SELECT 1 FROM offenses WHERE offenses.source = \
             events.source AND offenses.event_id = events.event_id )",
            [],
         )
         .map_err(db_error)?;
      transaction.commit().map_err(db_error)?;
      Ok(removed)
   }

   /// Remove inactive lease history after its escalation-retention window.
   pub fn prune_leases(&mut self, before: u64, now: u64) -> Result<usize> {
      self
         .connection
         .execute(
            "DELETE FROM leases WHERE created_at < ?1 AND (revoked_at IS NOT NULL OR expired_at \
             IS NOT NULL OR (expires_at IS NOT NULL AND expires_at <= ?2))",
            params![sql_time(before)?, sql_time(now)?],
         )
         .map_err(db_error)
   }

   /// Mark the desired set as not yet verified before an nftables reconcile.
   pub fn begin_reconcile(&mut self, now: u64) -> Result<usize> {
      self
         .connection
         .execute(
            "UPDATE leases SET apply_state = 'pending', apply_error = NULL WHERE revoked_at IS \
             NULL AND expired_at IS NULL AND (expires_at IS NULL OR expires_at > ?1)",
            [sql_time(now)?],
         )
         .map_err(db_error)
   }

   pub fn manual_block(
      &mut self,
      network: IpNetwork,
      action: &Action,
      now: u64,
      duration_secs: Option<u64>,
   ) -> Result<Lease> {
      let transaction = self.connection.transaction().map_err(db_error)?;
      transaction
         .execute(
            "UPDATE leases SET revoked_at = ?1 WHERE manual = 1 AND network = ?2 AND revoked_at \
             IS NULL AND expired_at IS NULL",
            params![sql_time(now)?, network.to_string()],
         )
         .map_err(db_error)?;
      let expires_at = duration_secs.map(|duration| now.saturating_add(duration));
      let id = insert_lease(&transaction, &NewLease {
         network,
         policy: MANUAL_POLICY,
         action,
         created_at: now,
         expires_at,
         escalation_count: 0,
         manual: true,
      })?;
      let lease = Lease {
         id,
         network,
         policy: MANUAL_POLICY.to_owned(),
         action: action.clone(),
         created_at: now,
         expires_at,
         escalation_count: 0,
         manual: true,
         apply_state: "pending".into(),
         last_error: None,
      };
      transaction.commit().map_err(db_error)?;
      Ok(lease)
   }

   pub fn manual_unblock(&mut self, network: IpNetwork, now: u64) -> Result<usize> {
      self
         .connection
         .execute(
            "UPDATE leases SET revoked_at = ?1 WHERE network = ?2 AND revoked_at IS NULL AND \
             expired_at IS NULL AND (expires_at IS NULL OR expires_at > ?1)",
            params![sql_time(now)?, network.to_string()],
         )
         .map_err(db_error)
   }

   /// Persist one reconciliation outcome atomically for every desired lease.
   pub fn mark_apply_results(&mut self, outcomes: &[(i64, ApplyOutcome)]) -> Result<()> {
      let transaction = self.connection.transaction().map_err(db_error)?;
      for (lease_id, outcome) in outcomes {
         let (state, error) = match outcome {
            ApplyOutcome::Applied => ("applied", None),
            ApplyOutcome::Observed => ("observed", None),
            ApplyOutcome::Failed(error) => ("failed", Some(error.as_str())),
         };
         let changed = transaction
            .execute(
               "UPDATE leases SET apply_state = ?1, apply_error = ?2 WHERE id = ?3",
               params![state, error, lease_id],
            )
            .map_err(db_error)?;
         if changed == 0 {
            return Err(Error::Config(format!("unknown defense lease {lease_id}")));
         }
      }
      transaction.commit().map_err(db_error)
   }
}

fn create_schema(connection: &Connection) -> Result<()> {
   let transaction = connection.unchecked_transaction().map_err(db_error)?;
   transaction
      .execute_batch(
         "CREATE TABLE checkpoints (
                 source TEXT PRIMARY KEY,
                 event_id TEXT NOT NULL,
                 data TEXT NOT NULL,
                 updated_at INTEGER NOT NULL
             ) STRICT;
             CREATE TABLE events (
                 source TEXT NOT NULL,
                 event_id TEXT NOT NULL,
                 observed_at INTEGER NOT NULL,
                 PRIMARY KEY(source, event_id)
             ) STRICT;
             CREATE TABLE offenses (
                 source TEXT NOT NULL,
                 event_id TEXT NOT NULL,
                 policy TEXT NOT NULL,
                 network TEXT NOT NULL,
                 observed_at INTEGER NOT NULL,
                 attempt_key TEXT,
                 consumed INTEGER NOT NULL CHECK(consumed IN (0, 1)),
                 PRIMARY KEY(source, event_id, policy),
                 FOREIGN KEY(source, event_id) REFERENCES events(source, event_id)
             ) STRICT;
             CREATE INDEX offenses_window
                 ON offenses(policy, network, consumed, observed_at);
             CREATE TABLE leases (
                 id INTEGER PRIMARY KEY,
                 network TEXT NOT NULL,
                 policy TEXT NOT NULL,
                 action TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 expires_at INTEGER,
                 escalation_count INTEGER NOT NULL,
                 manual INTEGER NOT NULL CHECK(manual IN (0, 1)),
                 revoked_at INTEGER,
                 expired_at INTEGER,
                 apply_state TEXT NOT NULL CHECK(apply_state IN ('pending', 'applied', 'observed', \
          'failed')),
                 apply_error TEXT
             ) STRICT;
             CREATE INDEX leases_active
                 ON leases(network, policy, revoked_at, expired_at, expires_at);",
      )
      .map_err(db_error)?;
   transaction
      .pragma_update(None, "user_version", SCHEMA_VERSION)
      .map_err(db_error)?;
   transaction.commit().map_err(db_error)
}

struct NewLease<'a> {
   network:          IpNetwork,
   policy:           &'a str,
   action:           &'a Action,
   created_at:       u64,
   expires_at:       Option<u64>,
   escalation_count: u64,
   manual:           bool,
}

fn insert_lease(transaction: &Transaction<'_>, lease: &NewLease<'_>) -> Result<i64> {
   let serialized = serde_json::to_string(lease.action).map_err(json_error)?;
   transaction
      .execute(
         "INSERT INTO leases( network, policy, action, created_at, expires_at, escalation_count, \
          manual, apply_state ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending')",
         params![
            lease.network.to_string(),
            lease.policy,
            serialized,
            sql_time(lease.created_at)?,
            lease.expires_at.map(sql_time).transpose()?,
            sql_time(lease.escalation_count)?,
            i64::from(lease.manual),
         ],
      )
      .map_err(db_error)?;
   Ok(transaction.last_insert_rowid())
}

fn upsert_checkpoint(
   transaction: &Transaction<'_>,
   source: &str,
   event_id: &str,
   checkpoint: &Checkpoint,
   observed_at: u64,
) -> Result<()> {
   let data = serde_json::to_string(checkpoint).map_err(json_error)?;
   transaction
      .execute(
         "INSERT INTO checkpoints(source, event_id, data, updated_at) VALUES (?1, ?2, ?3, ?4) ON \
          CONFLICT(source) DO UPDATE SET event_id = excluded.event_id, data = excluded.data, \
          updated_at = excluded.updated_at",
         params![source, event_id, data, sql_time(observed_at)?],
      )
      .map_err(db_error)?;
   Ok(())
}

fn has_active_lease(
   transaction: &Transaction<'_>,
   policy: &str,
   network: IpNetwork,
   now: u64,
) -> Result<bool> {
   transaction
      .query_row(
         "SELECT EXISTS( SELECT 1 FROM leases WHERE policy = ?1 AND network = ?2 AND revoked_at \
          IS NULL AND expired_at IS NULL AND (expires_at IS NULL OR expires_at > ?3) )",
         params![policy, network.to_string(), sql_time(now)?],
         |row| row.get(0),
      )
      .map_err(db_error)
}

fn escalation_count(
   transaction: &Transaction<'_>,
   policy: &str,
   network: IpNetwork,
   overall: bool,
   history_start: u64,
) -> Result<u64> {
   let count = if overall {
      transaction.query_row(
         "SELECT COUNT(*) FROM leases WHERE network = ?1 AND manual = 0 AND created_at >= ?2",
         params![network.to_string(), sql_time(history_start)?],
         |row| row.get::<_, i64>(0),
      )
   } else {
      transaction.query_row(
         "SELECT COUNT(*) FROM leases WHERE network = ?1 AND policy = ?2 AND manual = 0 AND \
          created_at >= ?3",
         params![network.to_string(), policy, sql_time(history_start)?],
         |row| row.get::<_, i64>(0),
      )
   }
   .map_err(db_error)?;
   rust_time(count)
}

fn ban_duration(schedule: &BanSchedule, count: u64) -> Option<u64> {
   let base = schedule.duration_secs?;
   let duration = if schedule.multipliers.is_empty() {
      base
         .saturating_mul(schedule.factor)
         .saturating_mul(2_u64.saturating_pow(count.min(u64::from(u32::MAX)) as u32))
   } else {
      let index = usize::try_from(count)
         .unwrap_or(usize::MAX)
         .min(schedule.multipliers.len() - 1);
      base
         .saturating_mul(schedule.factor)
         .saturating_mul(schedule.multipliers[index])
   };
   let jitter = if schedule.jitter_secs == 0 {
      0
   } else {
      rand::rng().random_range(0..=schedule.jitter_secs)
   };
   Some(
      duration
         .saturating_add(jitter)
         .min(schedule.max_duration_secs),
   )
}

struct EncodedLease {
   id:               i64,
   network:          String,
   policy:           String,
   action:           String,
   created_at:       i64,
   expires_at:       Option<i64>,
   escalation_count: i64,
   manual:           bool,
   apply_state:      String,
   last_error:       Option<String>,
}

fn lease_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EncodedLease> {
   Ok(EncodedLease {
      id:               row.get(0)?,
      network:          row.get(1)?,
      policy:           row.get(2)?,
      action:           row.get(3)?,
      created_at:       row.get(4)?,
      expires_at:       row.get(5)?,
      escalation_count: row.get(6)?,
      manual:           row.get(7)?,
      apply_state:      row.get(8)?,
      last_error:       row.get(9)?,
   })
}

fn decode_lease(lease: EncodedLease) -> Result<Lease> {
   Ok(Lease {
      id:               lease.id,
      network:          lease
         .network
         .parse()
         .map_err(|error| Error::Network(format!("{}: {error}", lease.network)))?,
      policy:           lease.policy,
      action:           serde_json::from_str(&lease.action).map_err(json_error)?,
      created_at:       rust_time(lease.created_at)?,
      expires_at:       lease.expires_at.map(rust_time).transpose()?,
      escalation_count: rust_time(lease.escalation_count)?,
      manual:           lease.manual,
      apply_state:      lease.apply_state,
      last_error:       lease.last_error,
   })
}

fn sql_time(value: u64) -> Result<i64> {
   i64::try_from(value)
      .map_err(|_| Error::Config(format!("timestamp {value} exceeds SQLite range")))
}

fn rust_time(value: i64) -> Result<u64> {
   u64::try_from(value)
      .map_err(|_| Error::Config(format!("negative timestamp in defense database: {value}")))
}

fn db_error(error: rusqlite::Error) -> Error {
   Error::Io(std::io::Error::other(error))
}

#[expect(
   clippy::needless_pass_by_value,
   reason = "map_err needs it passed by value"
)]
fn json_error(error: serde_json::Error) -> Error {
   Error::Config(format!("invalid defense database JSON: {error}"))
}
