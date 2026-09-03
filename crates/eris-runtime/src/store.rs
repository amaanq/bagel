//! Durable source progress, offense windows, and enforcement leases.

use crate::source::Checkpoint;
use eris_config::{Action, BanSchedule};
use eris_core::{Error, Result};
use ipnetwork::IpNetwork;
use rand::RngExt;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use std::path::Path;

const SCHEMA_VERSION: i64 = 2;
const MANUAL_POLICY: &str = "__manual__";

#[derive(Clone, Debug)]
pub struct Lease {
    pub id: i64,
    pub network: IpNetwork,
    pub policy: String,
    pub action: Action,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub escalation_count: u64,
    pub manual: bool,
    pub apply_state: String,
    pub last_error: Option<String>,
}

pub struct OffenseInput<'a> {
    pub policy: &'a str,
    pub network: IpNetwork,
    pub max_attempts: u32,
    pub findtime_secs: u64,
    pub history_retention_secs: u64,
    pub ban: &'a BanSchedule,
    pub action: &'a Action,
    pub observed_at: Option<u64>,
    pub attempt_key: Option<&'a str>,
}

pub struct EventInput<'a> {
    pub source: &'a str,
    pub event_id: &'a str,
    pub checkpoint: &'a Checkpoint,
    pub observed_at: u64,
    pub offenses: &'a [OffenseInput<'a>],
}

#[derive(Debug, Default)]
pub struct EventOutcome {
    pub duplicate: bool,
    pub leases: Vec<Lease>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
            1 => migrate_schema_1_to_2(&connection)?,
            SCHEMA_VERSION => {}
            other => {
                return Err(Error::Config(format!(
                    "unsupported defense database schema version {other}; expected {SCHEMA_VERSION}"
                )));
            }
        }
        Ok(Self { connection })
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
        data.map(|data| serde_json::from_str(&data).map_err(json_error))
            .transpose()
    }

    /// Persist a record and all policy matches in one transaction. A source
    /// checkpoint can therefore never advance past an uncommitted offense.
    pub fn process_event(&mut self, input: EventInput<'_>) -> Result<EventOutcome> {
        let observed_at = sql_time(input.observed_at)?;
        let transaction = self.connection.transaction().map_err(db_error)?;
        let inserted = transaction
            .execute(
                "INSERT OR IGNORE INTO events(source, event_id, observed_at) VALUES (?1, ?2, ?3)",
                params![input.source, input.event_id, observed_at],
            )
            .map_err(db_error)?;
        if inserted == 0 {
            transaction.commit().map_err(db_error)?;
            return Ok(EventOutcome {
                duplicate: true,
                leases: Vec::new(),
            });
        }

        let mut leases = Vec::new();
        for offense in input.offenses {
            let observed_at = offense.observed_at.unwrap_or(input.observed_at);
            let offense_observed_at = sql_time(observed_at)?;
            transaction
                .execute(
                    "INSERT INTO offenses( \
                         source, event_id, policy, network, observed_at, attempt_key, consumed \
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
                    params![
                        input.source,
                        input.event_id,
                        offense.policy,
                        offense.network.to_string(),
                        offense_observed_at,
                        offense.attempt_key,
                    ],
                )
                .map_err(db_error)?;

            if has_active_lease(&transaction, offense.policy, offense.network, observed_at)? {
                transaction
                    .execute(
                        "UPDATE offenses SET consumed = 1 \
                         WHERE source = ?1 AND event_id = ?2 AND policy = ?3",
                        params![input.source, input.event_id, offense.policy],
                    )
                    .map_err(db_error)?;
                continue;
            }

            let window_start = observed_at.saturating_sub(offense.findtime_secs);
            let attempt_query = if offense.attempt_key.is_some() {
                "SELECT COUNT(DISTINCT COALESCE(attempt_key, source || ':' || event_id)) \
                     FROM offenses \
                     WHERE policy = ?1 AND network = ?2 AND consumed = 0 \
                       AND observed_at >= ?3 AND observed_at <= ?4"
            } else {
                "SELECT COUNT(*) FROM offenses \
                     WHERE policy = ?1 AND network = ?2 AND consumed = 0 \
                       AND observed_at >= ?3 AND observed_at <= ?4"
            };
            let attempts = transaction
                .query_row(
                    attempt_query,
                    params![
                        offense.policy,
                        offense.network.to_string(),
                        sql_time(window_start)?,
                        offense_observed_at,
                    ],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(db_error)
                .and_then(rust_time)?;
            if attempts < u64::from(offense.max_attempts) {
                continue;
            }

            let escalation_count = escalation_count(
                &transaction,
                offense.policy,
                offense.network,
                offense.ban.overall,
                observed_at.saturating_sub(offense.history_retention_secs),
            )?;
            let duration = ban_duration(offense.ban, escalation_count);
            let expires_at = duration.map(|duration| observed_at.saturating_add(duration));
            let action = serde_json::to_string(offense.action).map_err(json_error)?;
            transaction
                .execute(
                    "INSERT INTO leases( \
                         network, policy, action, created_at, expires_at, escalation_count, manual, apply_state \
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 'pending')",
                    params![
                        offense.network.to_string(),
                        offense.policy,
                        action,
                        offense_observed_at,
                        expires_at.map(sql_time).transpose()?,
                        sql_time(escalation_count)?,
                    ],
                )
                .map_err(db_error)?;
            let id = transaction.last_insert_rowid();
            transaction
                .execute(
                    "UPDATE offenses SET consumed = 1 \
                     WHERE policy = ?1 AND network = ?2 AND consumed = 0 \
                       AND observed_at >= ?3 AND observed_at <= ?4",
                    params![
                        offense.policy,
                        offense.network.to_string(),
                        sql_time(window_start)?,
                        offense_observed_at,
                    ],
                )
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
            &transaction,
            input.source,
            input.event_id,
            input.checkpoint,
            input.observed_at,
        )?;
        transaction.commit().map_err(db_error)?;
        Ok(EventOutcome {
            duplicate: false,
            leases,
        })
    }

    /// Persist progress for a source record that produced no policy matches.
    pub fn persist_checkpoint(
        &mut self,
        source: &str,
        event_id: &str,
        checkpoint: &Checkpoint,
        observed_at: u64,
    ) -> Result<bool> {
        let transaction = self.connection.transaction().map_err(db_error)?;
        upsert_checkpoint(&transaction, source, event_id, checkpoint, observed_at)?;
        transaction.commit().map_err(db_error)?;
        Ok(true)
    }

    pub fn active_leases(&self, now: u64) -> Result<Vec<Lease>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, network, policy, action, created_at, expires_at, escalation_count, manual, \
                        apply_state, apply_error \
                 FROM leases \
                 WHERE revoked_at IS NULL AND expired_at IS NULL \
                   AND (expires_at IS NULL OR expires_at > ?1) \
                 ORDER BY id",
            )
            .map_err(db_error)?;
        let rows = statement
            .query_map([sql_time(now)?], lease_from_row)
            .map_err(db_error)?;
        rows.map(|row| row.map_err(db_error).and_then(decode_lease))
            .collect()
    }

    pub fn expire(&mut self, now: u64) -> Result<usize> {
        self.connection
            .execute(
                "UPDATE leases SET expired_at = ?1 \
                 WHERE revoked_at IS NULL AND expired_at IS NULL \
                   AND expires_at IS NOT NULL AND expires_at <= ?1",
                [sql_time(now)?],
            )
            .map_err(db_error)
    }

    /// Bound rolling-window history without touching durable lease history.
    pub fn prune_offenses(&mut self, before: u64) -> Result<usize> {
        let transaction = self.connection.transaction().map_err(db_error)?;
        let removed = transaction
            .execute(
                "DELETE FROM offenses WHERE observed_at < ?1",
                [sql_time(before)?],
            )
            .map_err(db_error)?;
        transaction
            .execute(
                "DELETE FROM events WHERE NOT EXISTS ( \
                     SELECT 1 FROM offenses \
                     WHERE offenses.source = events.source \
                       AND offenses.event_id = events.event_id \
                 )",
                [],
            )
            .map_err(db_error)?;
        transaction.commit().map_err(db_error)?;
        Ok(removed)
    }

    /// Remove inactive lease history after its escalation-retention window.
    pub fn prune_leases(&mut self, before: u64, now: u64) -> Result<usize> {
        self.connection
            .execute(
                "DELETE FROM leases WHERE created_at < ?1 \
                 AND (revoked_at IS NOT NULL OR expired_at IS NOT NULL \
                      OR (expires_at IS NOT NULL AND expires_at <= ?2))",
                params![sql_time(before)?, sql_time(now)?],
            )
            .map_err(db_error)
    }

    /// Mark the desired set as not yet verified before an nftables reconcile.
    pub fn begin_reconcile(&mut self, now: u64) -> Result<usize> {
        self.connection
            .execute(
                "UPDATE leases SET apply_state = 'pending', apply_error = NULL \
                 WHERE revoked_at IS NULL AND expired_at IS NULL \
                   AND (expires_at IS NULL OR expires_at > ?1)",
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
                "UPDATE leases SET revoked_at = ?1 \
                 WHERE manual = 1 AND network = ?2 AND revoked_at IS NULL AND expired_at IS NULL",
                params![sql_time(now)?, network.to_string()],
            )
            .map_err(db_error)?;
        let expires_at = duration_secs.map(|duration| now.saturating_add(duration));
        let serialized = serde_json::to_string(action).map_err(json_error)?;
        transaction
            .execute(
                "INSERT INTO leases( \
                     network, policy, action, created_at, expires_at, escalation_count, manual, apply_state \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 0, 1, 'pending')",
                params![
                    network.to_string(),
                    MANUAL_POLICY,
                    serialized,
                    sql_time(now)?,
                    expires_at.map(sql_time).transpose()?,
                ],
            )
            .map_err(db_error)?;
        let lease = Lease {
            id: transaction.last_insert_rowid(),
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
        self.connection
            .execute(
                "UPDATE leases SET revoked_at = ?1 \
                 WHERE network = ?2 AND revoked_at IS NULL AND expired_at IS NULL \
                   AND (expires_at IS NULL OR expires_at > ?1)",
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
                 apply_state TEXT NOT NULL CHECK(apply_state IN ('pending', 'applied', 'observed', 'failed')),
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

fn migrate_schema_1_to_2(connection: &Connection) -> Result<()> {
    let transaction = connection.unchecked_transaction().map_err(db_error)?;
    transaction
        .execute("ALTER TABLE offenses ADD COLUMN attempt_key TEXT", [])
        .map_err(db_error)?;
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(db_error)?;
    transaction.commit().map_err(db_error)
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
            "INSERT INTO checkpoints(source, event_id, data, updated_at) VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(source) DO UPDATE SET \
                 event_id = excluded.event_id, data = excluded.data, updated_at = excluded.updated_at",
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
            "SELECT EXISTS( \
                 SELECT 1 FROM leases \
                 WHERE policy = ?1 AND network = ?2 AND revoked_at IS NULL AND expired_at IS NULL \
                   AND (expires_at IS NULL OR expires_at > ?3) \
             )",
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
            "SELECT COUNT(*) FROM leases \
             WHERE network = ?1 AND manual = 0 AND created_at >= ?2",
            params![network.to_string(), sql_time(history_start)?],
            |row| row.get::<_, i64>(0),
        )
    } else {
        transaction.query_row(
            "SELECT COUNT(*) FROM leases \
             WHERE network = ?1 AND policy = ?2 AND manual = 0 AND created_at >= ?3",
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
        base.saturating_mul(schedule.factor)
            .saturating_mul(2_u64.saturating_pow(count.min(u64::from(u32::MAX)) as u32))
    } else {
        let index = usize::try_from(count)
            .unwrap_or(usize::MAX)
            .min(schedule.multipliers.len() - 1);
        base.saturating_mul(schedule.factor)
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
    id: i64,
    network: String,
    policy: String,
    action: String,
    created_at: i64,
    expires_at: Option<i64>,
    escalation_count: i64,
    manual: bool,
    apply_state: String,
    last_error: Option<String>,
}

fn lease_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EncodedLease> {
    Ok(EncodedLease {
        id: row.get(0)?,
        network: row.get(1)?,
        policy: row.get(2)?,
        action: row.get(3)?,
        created_at: row.get(4)?,
        expires_at: row.get(5)?,
        escalation_count: row.get(6)?,
        manual: row.get(7)?,
        apply_state: row.get(8)?,
        last_error: row.get(9)?,
    })
}

fn decode_lease(lease: EncodedLease) -> Result<Lease> {
    Ok(Lease {
        id: lease.id,
        network: lease
            .network
            .parse()
            .map_err(|error| Error::Network(format!("{}: {error}", lease.network)))?,
        policy: lease.policy,
        action: serde_json::from_str(&lease.action).map_err(json_error)?,
        created_at: rust_time(lease.created_at)?,
        expires_at: lease.expires_at.map(rust_time).transpose()?,
        escalation_count: rust_time(lease.escalation_count)?,
        manual: lease.manual,
        apply_state: lease.apply_state,
        last_error: lease.last_error,
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

fn json_error(error: serde_json::Error) -> Error {
    Error::Config(format!("invalid defense database JSON: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::Checkpoint;
    use eris_config::{Action, TransportProtocol};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);

    fn database_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "eris-store-{name}-{}-{}.sqlite3",
            std::process::id(),
            NEXT_DATABASE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn checkpoint(offset: u64) -> Checkpoint {
        Checkpoint::File {
            device: 1,
            inode: 2,
            offset,
            generation: 0,
            tail: Vec::new(),
        }
    }

    fn schedule(duration_secs: Option<u64>) -> BanSchedule {
        BanSchedule {
            duration_secs,
            factor: 2,
            multipliers: vec![3, 5],
            jitter_secs: 0,
            max_duration_secs: 1_000,
            overall: false,
        }
    }

    fn action() -> Action {
        Action::Drop {
            protocol: TransportProtocol::Tcp,
            ports: vec![22],
        }
    }

    fn offense<'a>(
        policy: &'a str,
        network: IpNetwork,
        max_attempts: u32,
        findtime_secs: u64,
        ban: &'a BanSchedule,
        action: &'a Action,
    ) -> OffenseInput<'a> {
        OffenseInput {
            policy,
            network,
            max_attempts,
            findtime_secs,
            history_retention_secs: 86_400,
            ban,
            action,
            observed_at: None,
            attempt_key: None,
        }
    }

    fn process(
        store: &mut Store,
        id: &str,
        time: u64,
        checkpoint: &Checkpoint,
        offenses: &[OffenseInput<'_>],
    ) -> EventOutcome {
        store
            .process_event(EventInput {
                source: "test",
                event_id: id,
                checkpoint,
                observed_at: time,
                offenses,
            })
            .unwrap()
    }

    #[test]
    fn deduplicates_events_without_regressing_checkpoint() {
        let path = database_path("dedup");
        let mut store = Store::open(&path).unwrap();
        let ban = schedule(Some(10));
        let action = action();
        let network = "192.0.2.4/32".parse().unwrap();
        let first_checkpoint = checkpoint(10);
        let second_checkpoint = checkpoint(20);
        let offenses = [offense("ssh", network, 2, 60, &ban, &action)];

        assert!(!process(&mut store, "event", 100, &first_checkpoint, &offenses).duplicate);
        assert!(process(&mut store, "event", 101, &second_checkpoint, &offenses).duplicate);
        assert_eq!(store.checkpoint("test").unwrap(), Some(first_checkpoint));
        assert!(store.active_leases(101).unwrap().is_empty());
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn counts_only_unconsumed_attempts_inside_findtime() {
        let path = database_path("window");
        let mut store = Store::open(&path).unwrap();
        let ban = schedule(Some(10));
        let action = action();
        let network = "192.0.2.5/32".parse().unwrap();
        let offenses = [offense("ssh", network, 2, 10, &ban, &action)];

        assert!(
            process(&mut store, "one", 100, &checkpoint(1), &offenses)
                .leases
                .is_empty()
        );
        assert!(
            process(&mut store, "two", 200, &checkpoint(2), &offenses)
                .leases
                .is_empty()
        );
        let outcome = process(&mut store, "three", 201, &checkpoint(3), &offenses);
        assert_eq!(outcome.leases.len(), 1);
        assert_eq!(outcome.leases[0].expires_at, Some(261));
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn distinct_attempt_keys_gate_threshold() {
        let path = database_path("distinct-attempts");
        let mut store = Store::open(&path).unwrap();
        let ban = schedule(Some(10));
        let action = action();
        let network = "192.0.2.18/32".parse().unwrap();

        for (id, time, key) in [
            ("one", 100, "/same"),
            ("two", 101, "/same"),
            ("three", 102, "/other"),
        ] {
            let mut attempt = offense("nginx", network, 3, 60, &ban, &action);
            attempt.attempt_key = Some(key);
            assert!(
                process(&mut store, id, time, &checkpoint(time), &[attempt])
                    .leases
                    .is_empty()
            );
        }

        let mut attempt = offense("nginx", network, 3, 60, &ban, &action);
        attempt.attempt_key = Some("/third");
        assert_eq!(
            process(&mut store, "four", 103, &checkpoint(103), &[attempt])
                .leases
                .len(),
            1
        );
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn migrates_schema_one_attempt_keys() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE offenses (id INTEGER) STRICT; \
                 PRAGMA user_version = 1;",
            )
            .unwrap();

        migrate_schema_1_to_2(&connection).unwrap();

        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let mut columns = connection.prepare("PRAGMA table_info(offenses)").unwrap();
        let has_attempt_key = columns
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .any(|column| column.is_ok_and(|column| column == "attempt_key"));
        assert_eq!(version, SCHEMA_VERSION);
        assert!(has_attempt_key);
    }

    #[test]
    fn findtime_uses_detector_timestamp_when_present() {
        let path = database_path("event-time");
        let mut store = Store::open(&path).unwrap();
        let ban = schedule(Some(10));
        let action = action();
        let network = "192.0.2.15/32".parse().unwrap();

        let mut first = offense("ssh", network, 2, 10, &ban, &action);
        first.observed_at = Some(100);
        assert!(
            process(&mut store, "one", 1_000, &checkpoint(1), &[first])
                .leases
                .is_empty()
        );
        let mut second = offense("ssh", network, 2, 10, &ban, &action);
        second.observed_at = Some(200);
        assert!(
            process(&mut store, "two", 1_001, &checkpoint(2), &[second])
                .leases
                .is_empty()
        );
        let mut third = offense("ssh", network, 2, 10, &ban, &action);
        third.observed_at = Some(201);
        let lease = &process(&mut store, "three", 1_002, &checkpoint(3), &[third]).leases[0];
        assert_eq!(lease.created_at, 201);
        assert_eq!(lease.expires_at, Some(261));
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn escalates_and_supports_permanent_leases() {
        let path = database_path("escalation");
        let mut store = Store::open(&path).unwrap();
        let timed = schedule(Some(10));
        let permanent = schedule(None);
        let action = action();
        let network = "192.0.2.6/32".parse().unwrap();

        let first = [offense("ssh", network, 1, 60, &timed, &action)];
        let lease = &process(&mut store, "one", 100, &checkpoint(1), &first).leases[0];
        assert_eq!(lease.escalation_count, 0);
        assert_eq!(lease.expires_at, Some(160));
        assert_eq!(store.expire(160).unwrap(), 1);

        let lease = &process(&mut store, "two", 161, &checkpoint(2), &first).leases[0];
        assert_eq!(lease.escalation_count, 1);
        assert_eq!(lease.expires_at, Some(261));

        let permanent_offense = [offense("web", network, 1, 60, &permanent, &action)];
        let lease =
            &process(&mut store, "three", 200, &checkpoint(3), &permanent_offense).leases[0];
        assert_eq!(lease.expires_at, None);
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn factor_matches_fail2ban_with_and_without_multipliers() {
        let mut ban = schedule(Some(10));
        assert_eq!(ban_duration(&ban, 0), Some(60));
        assert_eq!(ban_duration(&ban, 1), Some(100));

        ban.multipliers.clear();
        assert_eq!(ban_duration(&ban, 0), Some(20));
        assert_eq!(ban_duration(&ban, 1), Some(40));
        assert_eq!(ban_duration(&ban, 2), Some(80));
    }

    #[test]
    fn checkpoints_and_leases_survive_restart() {
        let path = database_path("restart");
        let ban = schedule(None);
        let action = action();
        let network = "2001:db8::4/128".parse().unwrap();
        {
            let mut store = Store::open(&path).unwrap();
            let offenses = [offense("ssh", network, 1, 60, &ban, &action)];
            process(&mut store, "one", 100, &checkpoint(99), &offenses);
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.checkpoint("test").unwrap(), Some(checkpoint(99)));
        let leases = store.active_leases(10_000).unwrap();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].network, network);
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn overall_escalation_counts_other_policies() {
        let path = database_path("overall");
        let mut store = Store::open(&path).unwrap();
        let mut ban = schedule(Some(10));
        ban.overall = true;
        let action = action();
        let network = "192.0.2.7/32".parse().unwrap();

        let first = [offense("ssh", network, 1, 60, &ban, &action)];
        process(&mut store, "one", 100, &checkpoint(1), &first);
        store.expire(160).unwrap();
        let second = [offense("nginx", network, 1, 60, &ban, &action)];
        let lease = &process(&mut store, "two", 161, &checkpoint(2), &second).leases[0];
        assert_eq!(lease.escalation_count, 1);
        assert_eq!(lease.expires_at, Some(261));
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn escalation_resets_after_history_retention() {
        let path = database_path("retention");
        let mut store = Store::open(&path).unwrap();
        let ban = schedule(Some(10));
        let action = action();
        let network = "192.0.2.17/32".parse().unwrap();
        let first = [offense("ssh", network, 1, 60, &ban, &action)];
        assert_eq!(
            process(&mut store, "one", 100, &checkpoint(1), &first).leases[0].escalation_count,
            0
        );
        store.expire(160).unwrap();

        let second = [offense("ssh", network, 1, 60, &ban, &action)];
        let lease = &process(&mut store, "two", 86_501, &checkpoint(2), &second).leases[0];
        assert_eq!(lease.escalation_count, 0);
        assert_eq!(lease.expires_at, Some(86_561));
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn manual_leases_can_be_removed_and_outcomes_are_persisted() {
        let path = database_path("manual");
        let mut store = Store::open(&path).unwrap();
        let network = "198.51.100.0/24".parse().unwrap();
        let ban = schedule(None);
        let action = action();
        let offenses = [offense("ssh", network, 1, 60, &ban, &action)];
        process(&mut store, "one", 99, &checkpoint(1), &offenses);
        let lease = store
            .manual_block(network, &Action::DropAll, 100, None)
            .unwrap();
        let automatic_id = store
            .active_leases(101)
            .unwrap()
            .into_iter()
            .find(|lease| !lease.manual)
            .unwrap()
            .id;
        assert!(
            store
                .mark_apply_results(&[
                    (automatic_id, ApplyOutcome::Applied),
                    (i64::MAX, ApplyOutcome::Applied),
                ])
                .is_err()
        );
        assert_ne!(
            store
                .active_leases(101)
                .unwrap()
                .into_iter()
                .find(|lease| lease.id == automatic_id)
                .unwrap()
                .apply_state,
            "applied"
        );
        store
            .mark_apply_results(&[
                (automatic_id, ApplyOutcome::Failed("nft failed".into())),
                (lease.id, ApplyOutcome::Failed("nft failed".into())),
            ])
            .unwrap();
        drop(store);
        let mut store = Store::open(&path).unwrap();
        let manual = store
            .active_leases(102)
            .unwrap()
            .into_iter()
            .find(|lease| lease.manual)
            .unwrap();
        assert_eq!(manual.apply_state, "failed");
        assert_eq!(manual.last_error.as_deref(), Some("nft failed"));
        let active = store.active_leases(102).unwrap();
        assert_eq!(active.len(), 2);
        assert!(
            active
                .iter()
                .all(|lease| lease.last_error.as_deref() == Some("nft failed"))
        );
        assert_eq!(store.manual_unblock(network, 103).unwrap(), 2);
        assert!(store.active_leases(104).unwrap().is_empty());
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn checkpoint_only_records_do_not_grow_event_history() {
        let path = database_path("checkpoint-only");
        let mut store = Store::open(&path).unwrap();
        for offset in 1..=100 {
            store
                .persist_checkpoint("nginx", &offset.to_string(), &checkpoint(offset), offset)
                .unwrap();
        }
        let events: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(events, 0);
        assert_eq!(store.checkpoint("nginx").unwrap(), Some(checkpoint(100)));
        drop(store);
        let _ = std::fs::remove_file(path);
    }
}
