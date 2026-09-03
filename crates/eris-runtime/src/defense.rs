//! Durable detection, escalation, and nftables reconciliation.

use crate::detector::CompiledDetector;
use crate::firewall::{Firewall, Membership, Protocol, Scope, Verdict};
use crate::source::{self, SourceRecord};
use crate::store::{ApplyOutcome, EventInput, Lease, OffenseInput, Store};
use eris_admin::{Ban, PolicyStatus};
use eris_config::{Action, Config, EnforcementMode, Policy, Source, TransportProtocol};
use eris_core::{Error, Result};
use ipnetwork::IpNetwork;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

struct CompiledPolicy {
    policy: Policy,
    detector: CompiledDetector,
    ignored: Vec<IpNetwork>,
}

pub struct Defense {
    config: Arc<Config>,
    firewall: Arc<Firewall>,
    store: Arc<Mutex<Store>>,
    policies: BTreeMap<String, CompiledPolicy>,
    protected: Vec<IpNetwork>,
    no_block: Vec<IpNetwork>,
    source_ready: BTreeMap<String, Arc<AtomicBool>>,
    checkpoint_sequences: Mutex<BTreeMap<String, u64>>,
    listener_locks: BTreeMap<String, Arc<AsyncMutex<()>>>,
    processor_ready: AtomicBool,
}

impl Defense {
    pub fn open(config: Arc<Config>) -> Result<Arc<Self>> {
        let store = Store::open(&config.database_path)?;
        let mut checkpoint_sequences = BTreeMap::new();
        let mut listener_locks = BTreeMap::new();
        for (name, source) in &config.sources {
            if matches!(source, Source::Listener { .. }) {
                let sequence = match store.checkpoint(name)? {
                    Some(source::Checkpoint::Listener { sequence }) => sequence,
                    _ => 0,
                };
                checkpoint_sequences.insert(name.clone(), sequence);
                listener_locks.insert(name.clone(), Arc::new(AsyncMutex::new(())));
            }
        }
        let mut policies = BTreeMap::new();
        for (name, policy) in &config.policies {
            policies.insert(
                name.clone(),
                CompiledPolicy {
                    detector: CompiledDetector::new(&policy.detector)?,
                    ignored: parse_networks(&policy.ignore_networks)?,
                    policy: policy.clone(),
                },
            );
        }
        let required = config.enforcement.mode == EnforcementMode::Required;
        let source_ready = config
            .sources
            .iter()
            .map(|(name, source)| {
                (
                    name.clone(),
                    Arc::new(AtomicBool::new(matches!(source, Source::Listener { .. }))),
                )
            })
            .collect();
        let firewall = Arc::new(Firewall::new(
            config.nft_path.clone(),
            config.enforcement.table.clone(),
            config.enforcement.chain_priority,
            required,
        ));
        Ok(Arc::new(Self {
            protected: parse_networks(&config.protected_networks)?,
            no_block: parse_networks(&config.no_block_networks)?,
            config,
            firewall,
            store: Arc::new(Mutex::new(store)),
            policies,
            source_ready,
            checkpoint_sequences: Mutex::new(checkpoint_sequences),
            listener_locks,
            processor_ready: AtomicBool::new(false),
        }))
    }

    #[must_use]
    pub fn firewall(&self) -> Arc<Firewall> {
        self.firewall.clone()
    }

    #[must_use]
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    #[must_use]
    pub fn source_count(&self) -> usize {
        self.config.sources.len()
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        let mut sources_ready = true;
        for (name, ready) in &self.source_ready {
            let ready = ready.load(Ordering::Acquire);
            crate::metrics::SOURCE_READY
                .with_label_values(&[name])
                .set(f64::from(u8::from(ready)));
            sources_ready &= ready;
        }
        self.firewall.is_ready() && self.processor_ready.load(Ordering::Acquire) && sources_ready
    }

    #[must_use]
    pub fn policies(&self) -> Vec<PolicyStatus> {
        self.policies
            .iter()
            .map(|(name, compiled)| PolicyStatus {
                name: name.clone(),
                source: compiled.policy.source.clone(),
                action: action_description(&compiled.policy.action),
            })
            .collect()
    }

    pub async fn initialize(&self) -> Result<()> {
        self.expire().await?;
        self.reconcile().await?;
        self.processor_ready.store(true, Ordering::Release);
        Ok(())
    }

    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) -> Result<()> {
        let (sender, mut receiver) = mpsc::channel(1024);
        for (name, source) in self.config.sources.clone() {
            if matches!(source, Source::Listener { .. }) {
                continue;
            }
            self.spawn_source(name, source, sender.clone(), shutdown.clone());
        }
        drop(sender);

        let mut interval = tokio::time::interval(Duration::from_secs(
            self.config.enforcement.reconcile_interval_secs,
        ));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                Some(record) = receiver.recv(), if !receiver.is_closed() => {
                    match self.process_record(record).await {
                        Ok(()) => self.processor_ready.store(true, Ordering::Release),
                        Err(error) => {
                            self.processor_ready.store(false, Ordering::Release);
                            return Err(error);
                        }
                    }
                }
                _ = interval.tick() => {
                    let result = match self.expire().await {
                        Ok(_) => self.reconcile().await,
                        Err(error) => Err(error),
                    };
                    match result {
                        Ok(()) => self.processor_ready.store(true, Ordering::Release),
                        Err(error) => {
                            self.processor_ready.store(false, Ordering::Release);
                            return Err(error);
                        }
                    }
                }
            }
        }
    }

    fn spawn_source(
        self: &Arc<Self>,
        name: String,
        source: Source,
        sender: mpsc::Sender<SourceRecord>,
        shutdown: CancellationToken,
    ) {
        let defense = self.clone();
        let ready = self
            .source_ready
            .get(&name)
            .expect("configured source has a readiness slot")
            .clone();
        tokio::spawn(async move {
            loop {
                let checkpoint = match defense.checkpoint(name.clone()).await {
                    Ok(checkpoint) => checkpoint,
                    Err(error) => {
                        log::error!("source {name} checkpoint failed: {error}");
                        None
                    }
                };
                let result = source::run(
                    name.clone(),
                    source.clone(),
                    defense.config.journalctl_path.clone(),
                    checkpoint,
                    sender.clone(),
                    ready.clone(),
                    shutdown.clone(),
                )
                .await;
                if shutdown.is_cancelled() {
                    return;
                }
                ready.store(false, Ordering::Release);
                if let Err(error) = result {
                    log::error!("source {name} failed: {error}");
                }
                tokio::select! {
                    () = shutdown.cancelled() => return,
                    () = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
            }
        });
    }

    async fn checkpoint(&self, source: String) -> Result<Option<source::Checkpoint>> {
        let store = self.store.clone();
        blocking(move || store.lock().checkpoint(&source)).await
    }

    async fn process_record(&self, record: SourceRecord) -> Result<()> {
        let mut owned = Vec::new();
        let mut detected = false;
        crate::metrics::SOURCE_LAG
            .with_label_values(&[&record.source])
            .set(now().saturating_sub(record.observed_at) as f64);
        if !record.oversized {
            for (name, compiled) in self
                .policies
                .iter()
                .filter(|(_, compiled)| compiled.policy.source == record.source)
            {
                let Some(detection) = compiled.detector.detect(
                    &record.payload,
                    record.observed_at,
                    record.correlation.as_deref(),
                ) else {
                    continue;
                };
                detected = true;
                let network = detection.network;
                if self.is_protected(network)? {
                    crate::metrics::POLICY_MATCHES
                        .with_label_values(&[name, "protected"])
                        .inc();
                    continue;
                }
                if compiled
                    .ignored
                    .iter()
                    .any(|ignored| overlaps(*ignored, network))
                {
                    crate::metrics::POLICY_MATCHES
                        .with_label_values(&[name, "ignored"])
                        .inc();
                    continue;
                }
                crate::metrics::POLICY_MATCHES
                    .with_label_values(&[name, "accepted"])
                    .inc();
                owned.push((
                    name.clone(),
                    network,
                    compiled.policy.max_attempts,
                    compiled.policy.findtime_secs,
                    compiled.policy.ban.clone(),
                    self.enforcement_action(network, &compiled.policy.action),
                    detection.observed_at,
                    detection.attempt_key,
                ));
            }
        }
        let outcome = if record.oversized {
            "oversized"
        } else if detected {
            "matched"
        } else {
            "unmatched"
        };
        crate::metrics::SOURCE_RECORDS
            .with_label_values(&[&record.source, outcome])
            .inc();

        if owned.is_empty() && !record.oversized {
            let mut sequences = self.checkpoint_sequences.lock();
            let sequence = sequences.entry(record.source.clone()).or_default();
            *sequence = sequence.saturating_add(1);
            if !(*sequence).is_multiple_of(128) {
                return Ok(());
            }
        }

        let store = self.store.clone();
        let source = record.source;
        let event_id = record.id;
        let checkpoint = record.checkpoint;
        let observed_at = record.observed_at;
        let history_retention_secs = self.config.history_retention_secs;
        let created = blocking(move || {
            let offenses = owned
                .iter()
                .map(
                    |(
                        policy,
                        network,
                        max_attempts,
                        findtime_secs,
                        ban,
                        action,
                        observed_at,
                        attempt_key,
                    )| {
                        OffenseInput {
                            policy,
                            network: *network,
                            max_attempts: *max_attempts,
                            findtime_secs: *findtime_secs,
                            history_retention_secs,
                            ban,
                            action,
                            observed_at: Some(*observed_at),
                            attempt_key: attempt_key.as_deref(),
                        }
                    },
                )
                .collect::<Vec<_>>();
            let mut store = store.lock();
            if offenses.is_empty() {
                store.persist_checkpoint(&source, &event_id, &checkpoint, observed_at)?;
                Ok(Vec::new())
            } else {
                Ok(store
                    .process_event(EventInput {
                        source: &source,
                        event_id: &event_id,
                        checkpoint: &checkpoint,
                        observed_at,
                        offenses: &offenses,
                    })?
                    .leases)
            }
        })
        .await?;
        if !created.is_empty() {
            for lease in &created {
                if self.is_spared_lease(lease) {
                    crate::metrics::NO_BLOCK_SPARED.inc();
                }
                log::info!(
                    "event=ban_created policy={} network={} expires_at={:?} escalation={}",
                    lease.policy,
                    lease.network,
                    lease.expires_at,
                    lease.escalation_count
                );
            }
            self.reconcile().await?;
        }
        Ok(())
    }

    pub async fn record_listener(&self, policy_name: &str, address: IpAddr) -> Result<()> {
        let compiled = self
            .policies
            .get(policy_name)
            .ok_or_else(|| Error::Config(format!("unknown listener policy {policy_name}")))?;
        let network = host_network(address)?;
        if self.is_protected(network)?
            || compiled
                .ignored
                .iter()
                .any(|ignored| overlaps(*ignored, network))
        {
            return Ok(());
        }
        let now = now();
        let policy_name = policy_name.to_owned();
        let policy = compiled.policy.clone();
        let action = self.enforcement_action(network, &policy.action);
        let source = policy.source.clone();
        let _listener_guard = self
            .listener_locks
            .get(&source)
            .ok_or_else(|| Error::Config(format!("listener source {source} has no lock")))?
            .lock()
            .await;
        let sequence = {
            let mut sequences = self.checkpoint_sequences.lock();
            let sequence = sequences.entry(source.clone()).or_default();
            *sequence = sequence.saturating_add(1);
            *sequence
        };
        let event_id = format!("listener:{source}:{sequence}");
        let checkpoint = source::Checkpoint::Listener { sequence };
        let history_retention_secs = self.config.history_retention_secs;
        let created = loop {
            let store = self.store.clone();
            let policy_name = policy_name.clone();
            let policy = policy.clone();
            let source = source.clone();
            let event_id = event_id.clone();
            let checkpoint = checkpoint.clone();
            let action = action.clone();
            match blocking(move || {
                let offense = OffenseInput {
                    policy: &policy_name,
                    network,
                    max_attempts: policy.max_attempts,
                    findtime_secs: policy.findtime_secs,
                    history_retention_secs,
                    ban: &policy.ban,
                    action: &action,
                    observed_at: Some(now),
                    attempt_key: None,
                };
                Ok(store
                    .lock()
                    .process_event(EventInput {
                        source: &source,
                        event_id: &event_id,
                        checkpoint: &checkpoint,
                        observed_at: now,
                        offenses: &[offense],
                    })?
                    .leases)
            })
            .await
            {
                Ok(created) => break created,
                Err(error) => {
                    self.processor_ready.store(false, Ordering::Release);
                    log::error!("listener offense persistence failed; retrying: {error}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        };
        self.processor_ready.store(true, Ordering::Release);
        if !created.is_empty() {
            for lease in &created {
                if self.is_spared_lease(lease) {
                    crate::metrics::NO_BLOCK_SPARED.inc();
                }
                log::info!(
                    "event=ban_created policy={} network={} expires_at={:?} escalation={}",
                    lease.policy,
                    lease.network,
                    lease.expires_at,
                    lease.escalation_count
                );
            }
            loop {
                match self.reconcile().await {
                    Ok(()) => break,
                    Err(error) => {
                        self.processor_ready.store(false, Ordering::Release);
                        log::error!("listener offense reconciliation failed; retrying: {error}");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
            self.processor_ready.store(true, Ordering::Release);
        }
        Ok(())
    }

    pub async fn bans(&self) -> Result<Vec<Ban>> {
        Ok(self
            .leases()
            .await?
            .into_iter()
            .map(|lease| Ban {
                network: lease.network.to_string(),
                policy: lease.policy,
                action: action_description(&lease.action),
                created_at: lease.created_at,
                expires_at: lease.expires_at,
                escalation_count: u32::try_from(lease.escalation_count).unwrap_or(u32::MAX),
                manual: lease.manual,
                blocking: is_blocking(&lease.action),
                apply_state: lease.apply_state,
                last_error: lease.last_error,
            })
            .collect())
    }

    pub async fn manual_block(&self, raw: &str, duration_secs: Option<u64>) -> Result<()> {
        if duration_secs == Some(0) {
            return Err(Error::Config("manual ban duration must be non-zero".into()));
        }
        let network = parse_network(raw)?;
        if self.is_protected(network)? {
            return Err(Error::Config(format!(
                "refusing to block protected network {network}"
            )));
        }
        if self.is_no_block_network(network) {
            return Err(Error::Config(format!(
                "refusing to block shared network {network}"
            )));
        }
        let store = self.store.clone();
        blocking(move || {
            let lease =
                store
                    .lock()
                    .manual_block(network, &Action::DropAll, now(), duration_secs)?;
            log::info!(
                "event=manual_ban network={} expires_at={:?}",
                lease.network,
                lease.expires_at
            );
            Ok(())
        })
        .await?;
        self.reconcile().await
    }

    pub async fn unblock(&self, raw: &str) -> Result<usize> {
        let network = parse_network(raw)?;
        let store = self.store.clone();
        let changed = blocking(move || store.lock().manual_unblock(network, now())).await?;
        if changed != 0 {
            log::info!("event=unban network={network} leases={changed}");
        }
        self.reconcile().await?;
        Ok(changed)
    }

    pub async fn reconcile(&self) -> Result<()> {
        let store = self.store.clone();
        let reconciled_at = now();
        let leases = blocking(move || {
            let mut store = store.lock();
            store.begin_reconcile(reconciled_at)?;
            store.active_leases(reconciled_at)
        })
        .await?;
        let mut memberships = Vec::new();
        let mut protected = std::collections::BTreeSet::new();
        let mut spared = std::collections::BTreeSet::new();
        for lease in &leases {
            if self.is_protected(lease.network)? {
                protected.insert(lease.id);
            } else if self.is_no_block_network(lease.network) {
                spared.insert(lease.id);
            } else {
                memberships.extend(membership(lease, &self.config)?);
            }
        }
        let result = self.firewall.reconcile(&memberships).await;
        crate::metrics::RECONCILES
            .with_label_values(&[if result.is_ok() { "success" } else { "failure" }])
            .inc();
        crate::metrics::FIREWALL_READY.set(f64::from(u8::from(self.firewall.is_ready())));
        let outcomes = leases
            .iter()
            .map(|lease| {
                let outcome = match &result {
                    Err(error) => ApplyOutcome::Failed(error.to_string()),
                    Ok(())
                        if !self.firewall.required()
                            || matches!(lease.action, Action::Observe)
                            || protected.contains(&lease.id)
                            || spared.contains(&lease.id) =>
                    {
                        ApplyOutcome::Observed
                    }
                    Ok(()) => ApplyOutcome::Applied,
                };
                (lease.id, outcome)
            })
            .collect::<Vec<_>>();
        let store = self.store.clone();
        blocking(move || {
            let mut store = store.lock();
            store.mark_apply_results(&outcomes)
        })
        .await?;
        let blocked = if self.firewall.required() {
            leases
                .iter()
                .filter(|lease| {
                    is_blocking(&lease.action)
                        && !protected.contains(&lease.id)
                        && !spared.contains(&lease.id)
                })
                .map(|lease| lease.network)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        } else {
            0
        };
        crate::metrics::BLOCKED_IPS.set(blocked as f64);
        for policy in self.policies.keys() {
            crate::metrics::ACTIVE_LEASES
                .with_label_values(&[policy])
                .set(0.0);
        }
        crate::metrics::ACTIVE_LEASES
            .with_label_values(&["__manual__"])
            .set(0.0);
        let mut counts = BTreeMap::<&str, usize>::new();
        for lease in &leases {
            *counts.entry(&lease.policy).or_default() += 1;
        }
        for (policy, count) in counts {
            crate::metrics::ACTIVE_LEASES
                .with_label_values(&[policy])
                .set(count as f64);
        }
        match &result {
            Ok(()) => log::debug!("event=reconcile result=success leases={}", leases.len()),
            Err(error) => log::error!("event=reconcile result=failure error={error}"),
        }
        result.map_err(Error::Io)
    }

    async fn leases(&self) -> Result<Vec<Lease>> {
        let store = self.store.clone();
        blocking(move || store.lock().active_leases(now())).await
    }

    async fn expire(&self) -> Result<usize> {
        let store = self.store.clone();
        let retention = self
            .policies
            .values()
            .map(|compiled| compiled.policy.findtime_secs)
            .max()
            .unwrap_or_default()
            .max(86_400);
        let history_retention = self.config.history_retention_secs;
        blocking(move || {
            let now = now();
            let mut store = store.lock();
            let expired = store.expire(now)?;
            store.prune_offenses(now.saturating_sub(retention))?;
            store.prune_leases(now.saturating_sub(history_retention), now)?;
            if expired != 0 {
                log::info!("event=leases_expired count={expired}");
            }
            Ok(expired)
        })
        .await
    }

    fn is_protected(&self, network: IpNetwork) -> Result<bool> {
        if self
            .protected
            .iter()
            .any(|protected| overlaps(*protected, network))
        {
            return Ok(true);
        }
        Ok(local_addresses()?
            .into_iter()
            .map(host_network)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .any(|local| overlaps(local, network)))
    }

    fn is_no_block_network(&self, network: IpNetwork) -> bool {
        self.no_block
            .iter()
            .any(|no_block| overlaps(*no_block, network))
    }

    fn enforcement_action(&self, network: IpNetwork, action: &Action) -> Action {
        if self.is_no_block_network(network) && is_blocking(action) {
            Action::Observe
        } else {
            action.clone()
        }
    }

    fn is_spared_lease(&self, lease: &Lease) -> bool {
        self.is_no_block_network(lease.network)
            && matches!(&lease.action, Action::Observe)
            && self
                .policies
                .get(&lease.policy)
                .is_some_and(|policy| is_blocking(&policy.policy.action))
    }
}

fn local_addresses() -> std::io::Result<Vec<IpAddr>> {
    let mut head = std::ptr::null_mut();
    // SAFETY: getifaddrs initializes `head` on success. Every pointer is
    // checked before dereference and the list is released exactly once.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    struct Guard(*mut libc::ifaddrs);
    impl Drop for Guard {
        fn drop(&mut self) {
            // SAFETY: the pointer came from a successful getifaddrs call.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let _guard = Guard(head);
    let mut addresses = Vec::new();
    let mut current = head;
    while !current.is_null() {
        // SAFETY: getifaddrs returns a null-terminated linked list valid until
        // freeifaddrs; `current` was checked above.
        let entry = unsafe { &*current };
        if !entry.ifa_addr.is_null() {
            // SAFETY: ifa_addr points to a sockaddr whose concrete type is
            // identified by sa_family.
            let family = unsafe { (*entry.ifa_addr).sa_family as i32 };
            match family {
                libc::AF_INET => {
                    // SAFETY: AF_INET guarantees sockaddr_in layout.
                    let address = unsafe { &*(entry.ifa_addr.cast::<libc::sockaddr_in>()) };
                    addresses.push(IpAddr::V4(std::net::Ipv4Addr::from(
                        address.sin_addr.s_addr.to_ne_bytes(),
                    )));
                }
                libc::AF_INET6 => {
                    // SAFETY: AF_INET6 guarantees sockaddr_in6 layout.
                    let address = unsafe { &*(entry.ifa_addr.cast::<libc::sockaddr_in6>()) };
                    addresses.push(IpAddr::V6(std::net::Ipv6Addr::from(
                        address.sin6_addr.s6_addr,
                    )));
                }
                _ => {}
            }
        }
        current = entry.ifa_next;
    }
    Ok(addresses)
}

fn membership(lease: &Lease, config: &Config) -> Result<Option<Membership>> {
    let scope = match &lease.action {
        Action::Observe => return Ok(None),
        Action::DropAll => Scope::all_ports(),
        Action::Drop { protocol, ports } => {
            Scope::new(map_protocol(*protocol), ports.clone(), Verdict::Drop)?
        }
        Action::DropProtocol { protocol } => Scope::protocol(map_protocol(*protocol)),
        Action::Reject { protocol, ports } => {
            Scope::new(map_protocol(*protocol), ports.clone(), Verdict::Reject)?
        }
        Action::RejectProtocol { protocol } => {
            let mut scope = Scope::protocol(map_protocol(*protocol));
            scope.verdict = Verdict::Reject;
            scope
        }
        Action::RejectAll => {
            let mut scope = Scope::all_ports();
            scope.verdict = Verdict::Reject;
            scope
        }
        Action::TarpitRedirect {
            protocol,
            ports,
            listener,
        } => {
            let port = config
                .listeners
                .iter()
                .find(|candidate| candidate.name() == listener)
                .ok_or_else(|| Error::Config(format!("unknown redirect listener {listener}")))?
                .listen_addr()
                .parse::<std::net::SocketAddr>()
                .map_err(|error| Error::Config(error.to_string()))?
                .port();
            Scope::new(
                map_protocol(*protocol),
                ports.clone(),
                Verdict::Redirect(port),
            )?
        }
    };
    Ok(Some(Membership {
        network: lease.network,
        scope,
    }))
}

const fn map_protocol(protocol: TransportProtocol) -> Protocol {
    match protocol {
        TransportProtocol::Tcp => Protocol::Tcp,
        TransportProtocol::Udp => Protocol::Udp,
    }
}

fn action_description(action: &Action) -> String {
    match action {
        Action::Observe => "observe".into(),
        Action::Drop { protocol, ports } => {
            format!("drop {} {}", protocol_name(*protocol), format_ports(ports))
        }
        Action::DropProtocol { protocol } => {
            format!("drop_protocol {}", protocol_name(*protocol))
        }
        Action::DropAll => "drop_all".into(),
        Action::Reject { protocol, ports } => {
            format!(
                "reject {} {}",
                protocol_name(*protocol),
                format_ports(ports)
            )
        }
        Action::RejectProtocol { protocol } => {
            format!("reject_protocol {}", protocol_name(*protocol))
        }
        Action::RejectAll => "reject_all".into(),
        Action::TarpitRedirect {
            protocol,
            ports,
            listener,
        } => format!(
            "tarpit_redirect {} {} -> {listener}",
            protocol_name(*protocol),
            format_ports(ports)
        ),
    }
}

fn is_blocking(action: &Action) -> bool {
    matches!(
        action,
        Action::Drop { .. }
            | Action::DropProtocol { .. }
            | Action::DropAll
            | Action::Reject { .. }
            | Action::RejectProtocol { .. }
            | Action::RejectAll
    )
}

fn format_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

const fn protocol_name(protocol: TransportProtocol) -> &'static str {
    match protocol {
        TransportProtocol::Tcp => "tcp",
        TransportProtocol::Udp => "udp",
    }
}

fn host_network(address: IpAddr) -> Result<IpNetwork> {
    IpNetwork::new(address, if address.is_ipv4() { 32 } else { 128 })
        .map_err(|error| Error::Network(error.to_string()))
}

fn parse_network(raw: &str) -> Result<IpNetwork> {
    if raw.contains('/') {
        raw.parse::<IpNetwork>()
            .map_err(|error| Error::Network(error.to_string()))
    } else {
        host_network(
            raw.parse::<IpAddr>()
                .map_err(|error| Error::Network(error.to_string()))?,
        )
    }
}

fn parse_networks(raw: &[String]) -> Result<Vec<IpNetwork>> {
    raw.iter().map(|network| parse_network(network)).collect()
}

fn overlaps(left: IpNetwork, right: IpNetwork) -> bool {
    left.is_ipv4() == right.is_ipv4() && (left.contains(right.ip()) || right.contains(left.ip()))
}

async fn blocking<T, F>(operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| Error::Io(std::io::Error::other(error)))?
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
    use std::sync::atomic::AtomicUsize;

    static NEXT_DATABASE: AtomicUsize = AtomicUsize::new(0);

    #[tokio::test]
    async fn maintenance_continues_without_streaming_sources() {
        let path = std::env::temp_dir().join(format!(
            "eris-defense-{}-{}.sqlite3",
            std::process::id(),
            NEXT_DATABASE.fetch_add(1, Ordering::Relaxed)
        ));
        let config = Config {
            database_path: path.clone(),
            nft_path: "true".into(),
            enforcement: eris_config::Enforcement {
                mode: EnforcementMode::Observe,
                reconcile_interval_secs: 1,
                ..eris_config::Enforcement::default()
            },
            ..Config::default()
        };
        let defense = Defense::open(Arc::new(config)).unwrap();
        defense.initialize().await.unwrap();
        defense.manual_block("198.51.100.4", Some(2)).await.unwrap();
        assert_eq!(defense.bans().await.unwrap().len(), 1);

        let shutdown = CancellationToken::new();
        let task = tokio::spawn(defense.clone().run(shutdown.clone()));
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
}
