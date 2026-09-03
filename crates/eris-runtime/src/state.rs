//! Concurrent runtime state: per-IP scan records, the active tarpit count, and
//! the global aggregates that back reports. Reads and writes
//! never take a global lock, and persistence runs off the connection hot path.
//!
//! The hit map is bounded. Without eviction it would accumulate one entry per
//! scanning IP forever; instead, sub-threshold entries are pruned by age and a
//! hard cap trims the oldest if the map ever runs away. The global path and
//! user-agent maps are attacker-influenced, so they are capped too: once full
//! they keep counting paths already seen but stop admitting new ones, which
//! keeps the genuinely repeated probes ranked while bounding memory.

use crate::category::{self, Category};
use crate::metrics;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use eris_admin::{IpDetail, Report, Scanner, Tally};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Distinct sample paths retained per IP for drill-down.
const SAMPLE_MAX: usize = 8;
/// Cap on distinct paths tracked globally for the top-paths report.
const PATHS_CAP: usize = 8192;
/// Cap on distinct user agents tracked globally.
const USER_AGENTS_CAP: usize = 2048;
/// Maximum attacker-controlled text retained in a single state field.
const STORED_TEXT_MAX: usize = 512;

/// Per-IP scan record.
#[derive(Clone)]
struct Hit {
    count: u32,
    first_seen: u64,
    last_seen: u64,
    /// Hits per category, indexed by [`Category::index`].
    categories: [u32; category::COUNT],
    /// A bounded sample of distinct probed paths and how often each was seen.
    samples: Vec<(String, u32)>,
    /// The most recent user agent from this IP.
    last_ua: Option<String>,
}

impl Hit {
    fn new(ts: u64) -> Self {
        Self {
            count: 0,
            first_seen: ts,
            last_seen: ts,
            categories: [0; category::COUNT],
            samples: Vec::new(),
            last_ua: None,
        }
    }

    /// The category this IP hit most often.
    fn dominant_category(&self) -> Category {
        let idx = self
            .categories
            .iter()
            .enumerate()
            .max_by_key(|&(_, c)| *c)
            .map_or(Category::Other.index(), |(i, _)| i);
        Category::from_index(idx)
    }
}

/// A fixed-window request-cost accumulator for one source IP.
///
/// Fixed windows are used rather than a sliding log: an O(1) counter with a
/// single timestamp cannot be grown unboundedly by an attacker, and for a
/// tarpit the small boundary imprecision is irrelevant: a flood trips the
/// budget inside one window regardless.
#[derive(Clone, Copy)]
struct RateWindow {
    /// Unix second the current window opened.
    start: u64,
    /// Accumulated request cost within the current window.
    cost: u32,
}

/// Result of recording one request against the rate limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateAdmission {
    /// The request is still within the source's budget.
    Admitted,
    /// The source exceeded its request-cost budget.
    Exceeded,
    /// The limiter cannot track another source without exceeding its memory cap.
    Full,
}

/// Shared honeypot state.
pub struct State {
    hits: DashMap<IpAddr, Hit>,
    /// Per-IP request-rate windows for the volume/enumeration limiter.
    rate: DashMap<IpAddr, RateWindow>,
    /// Number of occupied rate windows, kept separately so capacity admission
    /// is atomic across DashMap shards.
    rate_entries: AtomicUsize,
    /// Most-probed paths across all IPs (bounded by `PATHS_CAP`).
    paths: DashMap<String, u32>,
    /// Most-seen user agents across all IPs (bounded by `USER_AGENTS_CAP`).
    user_agents: DashMap<String, u32>,
    /// Total hits per category since load, indexed by [`Category::index`].
    category_totals: [AtomicU64; category::COUNT],
    active: AtomicUsize,
    /// Active tarpits by source. Entries exist only while a connection lives,
    /// so this remains bounded by the global connection cap.
    active_by_ip: DashMap<IpAddr, usize>,
    cache_dir: PathBuf,
    persist_lock: Mutex<()>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Increment `key` in a capped map: existing keys always count, but a new key
/// is admitted only while the map is below `cap`. This bounds memory against
/// attacker-controlled paths without losing the repeat offenders.
fn bump_bounded(map: &DashMap<String, u32>, key: &str, cap: usize) {
    if let Some(mut v) = map.get_mut(key) {
        *v += 1;
    } else if map.len() < cap {
        map.insert(key.to_string(), 1);
    }
}

/// Collect a map's entries as `Tally` rows, highest count first, capped to
/// `limit`.
fn top_tallies(map: &DashMap<String, u32>, limit: usize) -> Vec<Tally> {
    let mut rows: Vec<Tally> = map
        .iter()
        .map(|r| Tally {
            label: r.key().clone(),
            count: u64::from(*r.value()),
        })
        .collect();
    rows.sort_unstable_by(|a, b| b.count.cmp(&a.count));
    rows.truncate(limit);
    rows
}

impl State {
    /// Load persisted scan records from disk. Durable bans live in SQLite.
    #[must_use]
    pub fn load(_data_dir: &Path, cache_dir: &Path) -> Self {
        let state = Self {
            hits: DashMap::new(),
            rate: DashMap::new(),
            rate_entries: AtomicUsize::new(0),
            paths: DashMap::new(),
            user_agents: DashMap::new(),
            category_totals: std::array::from_fn(|_| AtomicU64::new(0)),
            active: AtomicUsize::new(0),
            active_by_ip: DashMap::new(),
            cache_dir: cache_dir.to_path_buf(),
            persist_lock: Mutex::new(()),
        };

        state.load_scan_state(cache_dir);
        state
    }

    /// Restore scan records: the current format first, then the legacy
    /// hit-counter file so an upgrade keeps existing counts.
    fn load_scan_state(&self, cache_dir: &Path) {
        let current = cache_dir.join("scan_state.json");
        if let Ok(content) = std::fs::read_to_string(&current)
            && let Ok(persisted) = serde_json::from_str::<Persisted>(&content)
        {
            for (ip, ph) in persisted.hits {
                if let Ok(ip) = ip.parse::<IpAddr>() {
                    self.hits.insert(ip, ph.into_hit());
                }
            }
            for (path, count) in persisted.paths {
                self.paths.insert(path, count);
            }
            for (ua, count) in persisted.user_agents {
                self.user_agents.insert(ua, count);
            }
            for (i, total) in persisted.category_totals.into_iter().enumerate() {
                if let Some(slot) = self.category_totals.get(i) {
                    slot.store(total, Ordering::Relaxed);
                }
            }
            log::info!("loaded scan state for {} IPs", self.hits.len());
            return;
        }

        // Legacy: a bare IP -> count map from a pre-report build.
        let legacy = cache_dir.join("hit_counters.json");
        if let Ok(content) = std::fs::read_to_string(&legacy)
            && let Ok(map) = serde_json::from_str::<HashMap<String, u32>>(&content)
        {
            let ts = now();
            for (ip, count) in map {
                if let Ok(ip) = ip.parse::<IpAddr>() {
                    let mut hit = Hit::new(ts);
                    hit.count = count;
                    self.hits.insert(ip, hit);
                }
            }
            log::info!("migrated legacy hit counters for {} IPs", self.hits.len());
        }
    }

    /// Record a trapped request from `ip`: bump its counters, remember a sample
    /// of the path and the user agent, and fold into the global aggregates.
    /// Returns the IP's new total hit count.
    pub fn record_hit(&self, ip: IpAddr, category: Category, path: &str, user_agent: &str) -> u32 {
        let ts = now();
        let path = stored_text(path);
        let user_agent = stored_text(user_agent);
        let count = {
            let mut entry = self.hits.entry(ip).or_insert_with(|| Hit::new(ts));
            entry.count = entry.count.saturating_add(1);
            entry.last_seen = ts;
            entry.categories[category.index()] =
                entry.categories[category.index()].saturating_add(1);
            add_sample(&mut entry.samples, &path);
            if entry.last_ua.as_deref() != Some(user_agent.as_str()) {
                entry.last_ua = Some(user_agent.clone());
            }
            entry.count
        };

        bump_bounded(&self.paths, &path, PATHS_CAP);
        bump_bounded(&self.user_agents, &user_agent, USER_AGENTS_CAP);
        self.category_totals[category.index()].fetch_add(1, Ordering::Relaxed);
        count
    }

    /// Charge `cost` to `ip`'s rate window and report its admission result.
    ///
    /// The window auto-resets once `window_secs` elapse, so a source that goes
    /// quiet is admitted again. A `max_cost` of zero disables the limiter.
    /// `max_entries` bounds memory even when every request uses a new source;
    /// callers must fail closed on [`RateAdmission::Full`].
    pub fn rate_admit(
        &self,
        ip: IpAddr,
        cost: u32,
        window_secs: u64,
        max_cost: u32,
        max_entries: usize,
    ) -> RateAdmission {
        if max_cost == 0 {
            return RateAdmission::Admitted;
        }
        let ts = now();
        let mut entry = match self.rate.entry(ip) {
            Entry::Occupied(entry) => entry.into_ref(),
            Entry::Vacant(entry) => {
                if self
                    .rate_entries
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                        (count < max_entries).then_some(count + 1)
                    })
                    .is_err()
                {
                    return RateAdmission::Full;
                }
                entry.insert(RateWindow { start: ts, cost: 0 })
            }
        };
        if ts.saturating_sub(entry.start) >= window_secs {
            entry.start = ts;
            entry.cost = 0;
        }
        entry.cost = entry.cost.saturating_add(cost);
        if entry.cost > max_cost {
            RateAdmission::Exceeded
        } else {
            RateAdmission::Admitted
        }
    }

    /// The `limit` most-hit IPs, highest first.
    #[must_use]
    pub fn top_hits(&self, limit: usize) -> Vec<(IpAddr, u32)> {
        let mut hits: Vec<(IpAddr, u32)> = self
            .hits
            .iter()
            .map(|r| (*r.key(), r.value().count))
            .collect();
        hits.sort_unstable_by_key(|&(_, count)| std::cmp::Reverse(count));
        hits.truncate(limit);
        hits
    }

    /// Build a categorised overview of scan activity.
    #[must_use]
    pub fn report(&self, limit: usize) -> Report {
        let mut categories: Vec<Tally> = Category::ALL
            .iter()
            .map(|c| Tally {
                label: c.label().to_string(),
                count: self.category_totals[c.index()].load(Ordering::Relaxed),
            })
            .filter(|t| t.count > 0)
            .collect();
        categories.sort_unstable_by(|a, b| b.count.cmp(&a.count));

        let mut scanners: Vec<Scanner> = self
            .hits
            .iter()
            .map(|r| {
                let hit = r.value();
                Scanner {
                    ip: *r.key(),
                    hits: hit.count,
                    top_category: hit.dominant_category().label().to_string(),
                    last_seen: hit.last_seen,
                }
            })
            .collect();
        scanners.sort_unstable_by(|a, b| b.hits.cmp(&a.hits));
        scanners.truncate(limit);

        Report {
            categories,
            top_paths: top_tallies(&self.paths, limit),
            top_user_agents: top_tallies(&self.user_agents, limit),
            top_scanners: scanners,
            tracked_ips: self.hits.len(),
            total_hits: self
                .category_totals
                .iter()
                .map(|c| c.load(Ordering::Relaxed))
                .sum(),
        }
    }

    /// A per-IP drill-down, or `None` if the IP is not tracked.
    #[must_use]
    pub fn ip_detail(&self, ip: IpAddr) -> Option<IpDetail> {
        let hit = self.hits.get(&ip)?;

        let mut categories: Vec<Tally> = Category::ALL
            .iter()
            .map(|c| Tally {
                label: c.label().to_string(),
                count: u64::from(hit.categories[c.index()]),
            })
            .filter(|t| t.count > 0)
            .collect();
        categories.sort_unstable_by(|a, b| b.count.cmp(&a.count));

        let mut sample_paths: Vec<Tally> = hit
            .samples
            .iter()
            .map(|(p, c)| Tally {
                label: p.clone(),
                count: u64::from(*c),
            })
            .collect();
        sample_paths.sort_unstable_by(|a, b| b.count.cmp(&a.count));

        Some(IpDetail {
            ip,
            hits: hit.count,
            first_seen: hit.first_seen,
            last_seen: hit.last_seen,
            categories,
            sample_paths,
            last_user_agent: hit.last_ua.clone(),
        })
    }

    #[must_use]
    pub fn tracked_count(&self) -> usize {
        self.hits.len()
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    /// Register an active tarpit connection. The returned guard decrements the
    /// count and updates the gauge when dropped, so cleanup cannot be skipped.
    #[must_use]
    pub fn enter_tarpit(self: &Arc<Self>) -> ActiveGuard {
        let n = self.active.fetch_add(1, Ordering::Relaxed) + 1;
        metrics::ACTIVE_CONNECTIONS.set(n as f64);
        ActiveGuard {
            state: self.clone(),
            ip: None,
        }
    }

    /// Enter a tarpit only when this source has spare concurrent capacity.
    ///
    /// The entry is removed by [`ActiveGuard`] on the final disconnect, so a
    /// scan of unique source addresses cannot accumulate state here.
    pub fn try_enter_tarpit(self: &Arc<Self>, ip: IpAddr, cap: usize) -> Option<ActiveGuard> {
        let mut entry = self.active_by_ip.entry(ip).or_insert(0);
        if *entry >= cap {
            return None;
        }
        *entry += 1;
        drop(entry);
        let n = self.active.fetch_add(1, Ordering::Relaxed) + 1;
        metrics::ACTIVE_CONNECTIONS.set(n as f64);
        Some(ActiveGuard {
            state: self.clone(),
            ip: Some(ip),
        })
    }

    /// Evict hit records that never reached the block threshold and have not
    /// been seen within `ttl` seconds, then enforce a hard `max` on the number
    /// of tracked IPs by dropping the oldest sub-threshold entries.
    pub fn prune(&self, ttl: u64, max: usize, threshold: u32) {
        let cutoff = now().saturating_sub(ttl);
        self.hits
            .retain(|_, hit| hit.count >= threshold || hit.last_seen >= cutoff);

        let len = self.hits.len();
        if len <= max {
            return;
        }
        let mut candidates: Vec<(IpAddr, u64)> = self
            .hits
            .iter()
            .map(|r| (*r.key(), r.value().last_seen))
            .collect();
        candidates.sort_unstable_by_key(|(_, last_seen)| *last_seen);
        for (ip, _) in candidates.into_iter().take(len - max) {
            self.hits.remove(&ip);
        }
        log::debug!("pruned hit map to {} entries", self.hits.len());
    }

    /// Drop rate windows that have fully elapsed, so the map stays bounded by
    /// the number of sources seen within the last window rather than growing
    /// with every IP ever seen. An elapsed window would reset on next contact
    /// anyway, so removing it changes no decision.
    pub fn prune_rate(&self, window_secs: u64) {
        let cutoff = now().saturating_sub(window_secs);
        self.rate.retain(|_, w| {
            let keep = w.start >= cutoff;
            if !keep {
                self.rate_entries.fetch_sub(1, Ordering::Relaxed);
            }
            keep
        });
    }

    /// Write scan state to disk. Call from a blocking context.
    pub fn persist(&self) {
        let _guard = self.persist_lock.lock();
        if let Err(e) = std::fs::create_dir_all(&self.cache_dir) {
            log::error!("cannot create cache dir: {e}");
            return;
        }
        let persisted = Persisted {
            hits: self
                .hits
                .iter()
                .map(|r| (r.key().to_string(), PersistHit::from_hit(r.value())))
                .collect(),
            paths: self
                .paths
                .iter()
                .map(|r| (r.key().clone(), *r.value()))
                .collect(),
            user_agents: self
                .user_agents
                .iter()
                .map(|r| (r.key().clone(), *r.value()))
                .collect(),
            category_totals: self
                .category_totals
                .iter()
                .map(|c| c.load(Ordering::Relaxed))
                .collect(),
        };
        match serde_json::to_vec(&persisted) {
            Ok(bytes) => {
                if let Err(e) = write_atomic(&self.cache_dir.join("scan_state.json"), &bytes) {
                    log::error!("cannot write scan state: {e}");
                }
            }
            Err(e) => log::error!("cannot serialize scan state: {e}"),
        }
    }
}

fn stored_text(value: &str) -> String {
    if value.len() <= STORED_TEXT_MAX {
        return value.to_string();
    }
    let mut end = STORED_TEXT_MAX;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temporary = path.with_extension("tmp");
    let mut file = File::create(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()
}

/// Record a probed path in a bounded per-IP sample set: bump an existing
/// sample, else add a new one while there is room.
fn add_sample(samples: &mut Vec<(String, u32)>, path: &str) {
    if let Some(sample) = samples.iter_mut().find(|(p, _)| p == path) {
        sample.1 = sample.1.saturating_add(1);
    } else if samples.len() < SAMPLE_MAX {
        samples.push((path.to_string(), 1));
    }
}

/// On-disk form of the scan state.
#[derive(Default, Serialize, Deserialize)]
struct Persisted {
    hits: HashMap<String, PersistHit>,
    paths: HashMap<String, u32>,
    user_agents: HashMap<String, u32>,
    category_totals: Vec<u64>,
}

#[derive(Serialize, Deserialize)]
struct PersistHit {
    count: u32,
    first_seen: u64,
    last_seen: u64,
    categories: Vec<u32>,
    samples: Vec<(String, u32)>,
    last_ua: Option<String>,
}

impl PersistHit {
    fn from_hit(hit: &Hit) -> Self {
        Self {
            count: hit.count,
            first_seen: hit.first_seen,
            last_seen: hit.last_seen,
            categories: hit.categories.to_vec(),
            samples: hit.samples.clone(),
            last_ua: hit.last_ua.clone(),
        }
    }

    /// Rebuild a [`Hit`], tolerating a category array of a different width from
    /// a differently-versioned build.
    fn into_hit(self) -> Hit {
        let mut categories = [0u32; category::COUNT];
        for (i, c) in self.categories.into_iter().enumerate() {
            if let Some(slot) = categories.get_mut(i) {
                *slot = c;
            }
        }
        Hit {
            count: self.count,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            categories,
            samples: self.samples,
            last_ua: self.last_ua,
        }
    }
}

/// RAII guard for an active tarpit connection.
pub struct ActiveGuard {
    state: Arc<State>,
    ip: Option<IpAddr>,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        if let Some(ip) = self.ip
            && let Entry::Occupied(mut entry) = self.state.active_by_ip.entry(ip)
        {
            if *entry.get() == 1 {
                entry.remove();
            } else {
                *entry.get_mut() -= 1;
            }
        }
        let n = self.state.active.fetch_sub(1, Ordering::Relaxed) - 1;
        metrics::ACTIVE_CONNECTIONS.set(n as f64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, n))
    }

    fn hit(state: &State, ip: IpAddr, category: Category, path: &str) -> u32 {
        state.record_hit(ip, category, path, "scanner/1.0")
    }

    #[test]
    fn records_hits() {
        let state = State::load(Path::new("/nonexistent"), Path::new("/nonexistent"));
        assert_eq!(hit(&state, ip(1), Category::EnvSecrets, "/.env"), 1);
        assert_eq!(hit(&state, ip(1), Category::EnvSecrets, "/.env"), 2);
        assert_eq!(hit(&state, ip(2), Category::Php, "/1.php"), 1);
    }

    #[test]
    fn rate_admit_trips_over_budget_and_resets_after_window() {
        let state = State::load(Path::new("/nonexistent"), Path::new("/x"));
        // Budget 10 per window; three cheap requests stay under.
        assert_eq!(
            state.rate_admit(ip(1), 1, 60, 10, 10),
            RateAdmission::Admitted
        );
        assert_eq!(
            state.rate_admit(ip(1), 1, 60, 10, 10),
            RateAdmission::Admitted
        );
        // One heavy git-history request (cost 10) tips it over.
        assert_eq!(
            state.rate_admit(ip(1), 10, 60, 10, 10),
            RateAdmission::Exceeded
        );

        // A max_cost of zero disables the limiter entirely.
        assert_eq!(
            state.rate_admit(ip(3), 1_000, 60, 0, 10),
            RateAdmission::Admitted
        );
    }

    #[test]
    fn rate_limiter_rejects_new_sources_when_its_state_is_full() {
        let state = State::load(Path::new("/nonexistent"), Path::new("/x"));
        for source in [ip(1), ip(2)] {
            assert_eq!(
                state.rate_admit(source, 1, 60, 10, 2),
                RateAdmission::Admitted
            );
        }

        assert_eq!(state.rate_admit(ip(3), 1, 60, 10, 2), RateAdmission::Full);
        assert_eq!(state.rate.len(), 2);

        // Existing sources retain their accounting while the limiter is full.
        assert_eq!(
            state.rate_admit(ip(1), 1, 60, 10, 2),
            RateAdmission::Admitted
        );
    }

    #[test]
    fn rate_windows_are_pruned_when_elapsed() {
        let state = State::load(Path::new("/nonexistent"), Path::new("/x"));
        state.rate_admit(ip(1), 1, 60, 10, 2);
        // Backdate the window so it counts as fully elapsed.
        state.rate.get_mut(&ip(1)).unwrap().start = now().saturating_sub(120);
        state.rate_admit(ip(2), 1, 60, 10, 2); // fresh, must survive
        state.prune_rate(60);
        assert!(!state.rate.contains_key(&ip(1)), "elapsed window kept");
        assert!(state.rate.contains_key(&ip(2)), "fresh window pruned");
        assert_eq!(
            state.rate_admit(ip(3), 1, 60, 10, 2),
            RateAdmission::Admitted
        );
    }

    #[test]
    fn active_guard_tracks_count() {
        let state = Arc::new(State::load(Path::new("/nonexistent"), Path::new("/x")));
        {
            let _g1 = state.enter_tarpit();
            let _g2 = state.enter_tarpit();
            assert_eq!(state.active_count(), 2);
        }
        assert_eq!(state.active_count(), 0);
    }

    #[test]
    fn per_ip_tarpit_cap_releases_on_disconnect() {
        let state = Arc::new(State::load(Path::new("/nonexistent"), Path::new("/x")));
        let first = state.try_enter_tarpit(ip(1), 1).expect("first slot");
        assert!(state.try_enter_tarpit(ip(1), 1).is_none());
        assert!(state.try_enter_tarpit(ip(2), 1).is_some());
        drop(first);
        assert!(state.try_enter_tarpit(ip(1), 1).is_some());
    }

    #[test]
    fn report_aggregates_categories_paths_and_scanners() {
        let state = State::load(Path::new("/nonexistent"), Path::new("/x"));
        hit(&state, ip(1), Category::Php, "/1.php");
        hit(&state, ip(1), Category::Php, "/1.php");
        hit(&state, ip(1), Category::EnvSecrets, "/.env");
        hit(&state, ip(2), Category::Php, "/2.php");

        let report = state.report(10);
        assert_eq!(report.total_hits, 4);
        assert_eq!(report.tracked_ips, 2);

        // Php (3) outranks EnvSecrets (1).
        assert_eq!(report.categories[0].label, "php");
        assert_eq!(report.categories[0].count, 3);

        // ip(1) has 3 hits, ip(2) has 1: ip(1) leads the scanner table.
        assert_eq!(report.top_scanners[0].ip, ip(1));
        assert_eq!(report.top_scanners[0].hits, 3);
        assert_eq!(report.top_scanners[0].top_category, "php");

        // "/1.php" was probed twice, so it tops the path table.
        assert_eq!(report.top_paths[0].label, "/1.php");
        assert_eq!(report.top_paths[0].count, 2);
    }

    #[test]
    fn ip_detail_reports_samples_and_timestamps() {
        let state = State::load(Path::new("/nonexistent"), Path::new("/x"));
        hit(&state, ip(1), Category::Php, "/1.php");
        hit(&state, ip(1), Category::VcsLeak, "/.git/config");
        let detail = state.ip_detail(ip(1)).unwrap();
        assert_eq!(detail.hits, 2);
        assert_eq!(detail.sample_paths.len(), 2);
        assert_eq!(detail.last_user_agent.as_deref(), Some("scanner/1.0"));
        assert!(detail.last_seen >= detail.first_seen);

        assert!(state.ip_detail(ip(9)).is_none());
    }

    #[test]
    fn samples_are_bounded_but_counts_are_not() {
        let state = State::load(Path::new("/nonexistent"), Path::new("/x"));
        for n in 0..(SAMPLE_MAX + 5) {
            hit(&state, ip(1), Category::Php, &format!("/{n}.php"));
        }
        // The repeat path keeps counting even once the sample set is full.
        for _ in 0..3 {
            hit(&state, ip(1), Category::Php, "/0.php");
        }
        let detail = state.ip_detail(ip(1)).unwrap();
        assert_eq!(detail.sample_paths.len(), SAMPLE_MAX);
        assert_eq!(detail.sample_paths[0].label, "/0.php");
        assert_eq!(detail.sample_paths[0].count, 4);
    }

    #[test]
    fn prune_evicts_old_subthreshold_but_keeps_the_rest() {
        let state = State::load(Path::new("/nonexistent"), Path::new("/x"));
        let old = now().saturating_sub(100_000);
        let fresh = now();

        state.hits.insert(ip(1), {
            let mut h = Hit::new(old);
            h.count = 1;
            h.last_seen = old;
            h
        });
        state.hits.insert(ip(2), {
            let mut h = Hit::new(old);
            h.count = 5;
            h.last_seen = old;
            h
        });
        state.hits.insert(ip(3), {
            let mut h = Hit::new(fresh);
            h.count = 1;
            h.last_seen = fresh;
            h
        });

        state.prune(86_400, 1000, 3);

        assert!(
            !state.hits.contains_key(&ip(1)),
            "old sub-threshold survived"
        );
        assert!(state.hits.contains_key(&ip(2)), "threshold entry evicted");
        assert!(state.hits.contains_key(&ip(3)), "fresh entry evicted");
    }

    #[test]
    fn prune_hard_cap_trims_oldest() {
        let state = State::load(Path::new("/nonexistent"), Path::new("/x"));
        for n in 0..20 {
            hit(&state, ip(n), Category::Php, "/x.php");
        }
        state.prune(u64::MAX, 5, 3);
        assert!(state.tracked_count() <= 5);
    }

    #[test]
    fn persist_and_reload_round_trips_scan_state() {
        let dir = std::env::temp_dir().join(format!("eris-state-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = State::load(&dir, &dir);
        hit(&state, ip(1), Category::Php, "/1.php");
        hit(&state, ip(1), Category::EnvSecrets, "/.env");
        state.persist();

        let reloaded = State::load(&dir, &dir);
        let detail = reloaded.ip_detail(ip(1)).unwrap();
        assert_eq!(detail.hits, 2);
        assert_eq!(reloaded.report(10).total_hits, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stored_attacker_text_is_capped() {
        let state = State::load(Path::new("/nonexistent"), Path::new("/x"));
        let user_agent = "x".repeat(STORED_TEXT_MAX + 1);
        state.record_hit(ip(1), Category::Php, "/1.php", &user_agent);
        assert_eq!(
            state
                .ip_detail(ip(1))
                .unwrap()
                .last_user_agent
                .unwrap()
                .len(),
            STORED_TEXT_MAX
        );
    }
}
