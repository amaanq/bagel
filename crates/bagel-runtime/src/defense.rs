//! Durable detection, escalation, and nftables reconciliation.

use std::{
   collections::{
      BTreeMap,
      BTreeSet,
   },
   net::IpAddr,
   sync::{
      Arc,
      atomic::{
         AtomicBool,
         Ordering,
      },
   },
   time::{
      Duration,
      SystemTime,
      UNIX_EPOCH,
   },
};

use bagel_admin::{
   Ban,
   PolicyStatus,
};
use bagel_config::{
   Action,
   BlockTarget,
   BlockVerdict,
   Config,
   EnforcementMode,
   Policy,
   Source,
   TransportProtocol,
};
use bagel_core::{
   Error,
   Result,
};
use ipnetwork::IpNetwork;
use metrics::{
   counter,
   gauge,
};
use parking_lot::{
   Mutex,
   RwLock,
};
use tokio::sync::{
   Mutex as AsyncMutex,
   mpsc,
};
use tokio_util::sync::CancellationToken;

use crate::{
   detector::CompiledDetector,
   firewall::{
      Firewall,
      Membership,
      Protocol,
      Scope,
      Verdict,
      networks_overlap,
   },
   offense::WebOffenseSource,
   source::{
      self,
      SourceRecord,
   },
   store::{
      EventInput,
      Lease,
      OffenseInput,
      Store,
   },
};

struct CompiledPolicy {
   policy:   Policy,
   detector: CompiledDetector,
   ignored:  Vec<IpNetwork>,
}

#[derive(Default)]
pub struct ActiveLeases {
   networks: RwLock<Vec<IpNetwork>>,
}

impl ActiveLeases {
   #[must_use]
   pub fn contains(&self, ip: IpAddr) -> bool {
      self
         .networks
         .read()
         .iter()
         .any(|network| network.contains(ip))
   }

   pub fn replace(&self, networks: Vec<IpNetwork>) {
      *self.networks.write() = networks;
   }

   pub fn insert(&self, network: IpNetwork) {
      let mut guard = self.networks.write();
      if !guard.contains(&network) {
         guard.push(network);
      }
   }
}

pub struct Defense {
   config:               Arc<Config>,
   firewall:             Arc<Firewall>,
   store:                Arc<Mutex<Store>>,
   active_leases:        Arc<ActiveLeases>,
   policies:             BTreeMap<String, CompiledPolicy>,
   protected:            Vec<IpNetwork>,
   no_block:             Vec<IpNetwork>,
   source_ready:         BTreeMap<String, Arc<AtomicBool>>,
   checkpoint_sequences: Mutex<BTreeMap<String, u64>>,
   listener_locks:       BTreeMap<String, Arc<AsyncMutex<()>>>,
   processor_ready:      AtomicBool,
   records:              mpsc::Sender<SourceRecord>,
   inbox:                Mutex<Option<mpsc::Receiver<SourceRecord>>>,
   web_sources_taken:    Mutex<BTreeSet<String>>,
}

/// Records buffered between the sources and the defense loop.
pub(crate) const RECORD_QUEUE: usize = 1024;

pub(crate) const RECORD_BATCH: usize = 256;

impl Defense {
   pub fn open(config: Arc<Config>) -> Result<Arc<Self>> {
      let store = Store::open(&config.database_path)?;
      let mut checkpoint_sequences = BTreeMap::new();
      let mut listener_locks = BTreeMap::new();
      for (name, source) in &config.sources {
         if matches!(source, Source::Listener { .. } | Source::Web) {
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
         policies.insert(name.clone(), CompiledPolicy {
            detector: CompiledDetector::new(&policy.detector)?,
            ignored:  parse_networks(&policy.ignore_networks)?,
            policy:   policy.clone(),
         });
      }
      let required = config.enforcement.mode == EnforcementMode::Required;
      let source_ready = config
         .sources
         .iter()
         .map(|(name, source)| {
            (
               name.clone(),
               Arc::new(AtomicBool::new(matches!(
                  source,
                  Source::Listener { .. } | Source::Web
               ))),
            )
         })
         .collect();
      let firewall = Arc::new(Firewall::new(
         config.nft_path.clone(),
         config.enforcement.table.clone(),
         config.enforcement.chain_priority,
         required,
      ));
      let (records, inbox) = mpsc::channel(RECORD_QUEUE);
      Ok(Arc::new(Self {
         protected: parse_networks(&config.protected_networks)?,
         no_block: parse_networks(&config.no_block_networks)?,
         config,
         firewall,
         store: Arc::new(Mutex::new(store)),
         active_leases: Arc::default(),
         policies,
         source_ready,
         checkpoint_sequences: Mutex::new(checkpoint_sequences),
         listener_locks,
         processor_ready: AtomicBool::new(false),
         records,
         inbox: Mutex::new(Some(inbox)),
         web_sources_taken: Mutex::new(BTreeSet::new()),
      }))
   }

   /// Hand the HTTP data plane its configured record source.
   pub fn web_source(&self, name: &str) -> Result<WebOffenseSource> {
      if !matches!(self.config.sources.get(name), Some(Source::Web)) {
         return Err(Error::Config(format!(
            "{name} is not a configured web source"
         )));
      }
      if !self.web_sources_taken.lock().insert(name.to_owned()) {
         return Err(Error::Config(format!(
            "web source {name} is already attached"
         )));
      }
      let checkpoint = self
         .checkpoint_sequences
         .lock()
         .get(name)
         .copied()
         .unwrap_or_default();
      let stored = self.store.lock().last_listener_sequence(name)?;
      Ok(WebOffenseSource::new(
         name,
         self.records.clone(),
         checkpoint.max(stored),
      ))
   }

   #[must_use]
   pub fn firewall(&self) -> Arc<Firewall> {
      Arc::clone(&self.firewall)
   }

   pub(crate) const fn config_ref(&self) -> &Arc<Config> {
      &self.config
   }

   pub(crate) const fn firewall_ref(&self) -> &Arc<Firewall> {
      &self.firewall
   }

   pub(crate) const fn store_ref(&self) -> &Arc<Mutex<Store>> {
      &self.store
   }

   pub(crate) const fn active_leases_ref(&self) -> &Arc<ActiveLeases> {
      &self.active_leases
   }

   pub(crate) fn policy_names(&self) -> Vec<&str> {
      self.policies.keys().map(String::as_str).collect()
   }

   pub(crate) fn max_findtime_secs(&self) -> u64 {
      self
         .policies
         .values()
         .map(|compiled| compiled.policy.findtime_secs)
         .max()
         .unwrap_or_default()
   }

   #[must_use]
   pub fn active_leases(&self) -> Arc<ActiveLeases> {
      Arc::clone(&self.active_leases)
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
         crate::metrics::set_source_ready(name, f64::from(u8::from(ready)));
         sources_ready &= ready;
      }
      self.firewall.is_ready() && self.processor_ready.load(Ordering::Acquire) && sources_ready
   }

   #[must_use]
   pub fn policies(&self) -> Vec<PolicyStatus> {
      self
         .policies
         .iter()
         .map(|(name, compiled)| {
            PolicyStatus {
               name:   name.clone(),
               source: compiled.policy.source.clone(),
               action: compiled.policy.action.to_string(),
            }
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
      let mut receiver = self
         .inbox
         .lock()
         .take()
         .ok_or_else(|| Error::Config("defense loop is already running".into()))?;
      for (name, source) in self.config.sources.clone() {
         if matches!(source, Source::Listener { .. } | Source::Web) {
            continue;
         }
         self.spawn_source(name, source, self.records.clone(), shutdown.clone());
      }

      let mut interval = tokio::time::interval(Duration::from_secs(
         self.config.enforcement.reconcile_interval_secs,
      ));
      interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
      interval.tick().await;
      loop {
         let mut batch = Vec::new();
         tokio::select! {
             () = shutdown.cancelled(), if !receiver.is_closed() => {
                 receiver.close();
                 self.processor_ready.store(false, Ordering::Release);
             },
             count = receiver.recv_many(&mut batch, RECORD_BATCH) => {
                 if count == 0 {
                     return Ok(());
                 }
                 match self.process_records(batch).await {
                     Ok(()) => self.processor_ready.store(!receiver.is_closed(), Ordering::Release),
                     Err(error) => {
                         self.processor_ready.store(false, Ordering::Release);
                         return Err(error);
                     }
                 }
             }
             _ = interval.tick(), if !receiver.is_closed() => {
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
      let defense = Arc::clone(self);
      let ready = Arc::clone(
         self
            .source_ready
            .get(&name)
            .expect("configured source has a readiness slot"),
      );
      tokio::spawn(async move {
         loop {
            let checkpoint = match defense.checkpoint(name.clone()).await {
               Ok(checkpoint) => checkpoint,
               Err(error) => {
                  tracing::error!("source {name} checkpoint failed: {error}");
                  None
               },
            };
            let result = source::run(
               name.clone(),
               source.clone(),
               defense.config.journalctl_path.clone(),
               checkpoint,
               sender.clone(),
               Arc::clone(&ready),
               shutdown.clone(),
            )
            .await;
            if shutdown.is_cancelled() {
               return;
            }
            ready.store(false, Ordering::Release);
            if let Err(error) = result {
               tracing::error!("source {name} failed: {error}");
            }
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
         }
      });
   }

   async fn checkpoint(&self, source: String) -> Result<Option<source::Checkpoint>> {
      let store = Arc::clone(&self.store);
      blocking(move || store.lock().checkpoint(&source)).await
   }

   const fn offense_input<'a>(
      policy_name: &'a str,
      policy: &'a Policy,
      history_retention_secs: u64,
      network: IpNetwork,
      observed_at: Option<u64>,
      attempt_key: Option<&'a str>,
      group_key: Option<&'a str>,
   ) -> OffenseInput<'a> {
      OffenseInput {
         policy: policy_name,
         network,
         max_attempts: policy.max_attempts,
         findtime_secs: policy.findtime_secs,
         history_retention_secs,
         ban: &policy.ban,
         action: &policy.action,
         observed_at,
         attempt_key,
         group_key,
      }
   }

   #[expect(
      clippy::cast_precision_loss,
      reason = "source lag is a span of seconds, far below 2^53"
   )]
   async fn process_records(&self, records: Vec<SourceRecord>) -> Result<()> {
      struct PendingOffense {
         policy_name: String,
         policy:      Policy,
         network:     IpNetwork,
         observed_at: Option<u64>,
         attempt_key: Option<String>,
         group_key:   Option<String>,
      }
      struct PendingEvent {
         source:      String,
         event_id:    String,
         checkpoint:  source::Checkpoint,
         observed_at: u64,
         offenses:    Vec<PendingOffense>,
      }
      let mut pending = Vec::with_capacity(records.len());
      for record in records {
         gauge!("bagel_source_lag_seconds", "source" => record.source.clone())
            .set(now().saturating_sub(record.observed_at) as f64);
         let mut owned: Vec<PendingOffense> = Vec::new();
         let mut detected = false;
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
                  crate::metrics::record_policy_match(name, "protected");
                  continue;
               }
               if compiled
                  .ignored
                  .iter()
                  .any(|ignored| networks_overlap(*ignored, network))
               {
                  crate::metrics::record_policy_match(name, "ignored");
                  continue;
               }
               crate::metrics::record_policy_match(name, "accepted");
               let action = self.enforcement_action(network, &compiled.policy.action);
               let mut policy = compiled.policy.clone();
               policy.action = action;
               owned.push(PendingOffense {
                  policy_name: name.clone(),
                  policy,
                  network,
                  observed_at: Some(detection.observed_at),
                  attempt_key: detection.attempt_key,
                  group_key: detection.group_key,
               });
            }
         }
         let outcome = if record.oversized {
            "oversized"
         } else if detected {
            "matched"
         } else {
            "unmatched"
         };
         counter!("bagel_source_records_total", "source" => record.source.clone(), "outcome" => outcome.to_owned()).increment(1);

         if owned.is_empty() && !record.oversized {
            let mut sequences = self.checkpoint_sequences.lock();
            let sequence = sequences.entry(record.source.clone()).or_default();
            *sequence = sequence.saturating_add(1);
            if !(*sequence).is_multiple_of(128) {
               continue;
            }
         }
         pending.push(PendingEvent {
            source:      record.source,
            event_id:    record.id,
            checkpoint:  record.checkpoint,
            observed_at: record.observed_at,
            offenses:    owned,
         });
      }
      if pending.is_empty() {
         return Ok(());
      }

      let history_retention_secs = self.config.history_retention_secs;
      let store = Arc::clone(&self.store);
      let outcomes = blocking(move || {
         let mut store = store.lock();
         let mut offense_bufs = Vec::with_capacity(pending.len());
         for event in &pending {
            offense_bufs.push(
               event
                  .offenses
                  .iter()
                  .map(|offense| {
                     Self::offense_input(
                        &offense.policy_name,
                        &offense.policy,
                        history_retention_secs,
                        offense.network,
                        offense.observed_at,
                        offense.attempt_key.as_deref(),
                        offense.group_key.as_deref(),
                     )
                  })
                  .collect::<Vec<_>>(),
            );
         }
         let inputs = pending
            .iter()
            .zip(offense_bufs.iter())
            .map(|(event, offenses)| {
               EventInput {
                  source: &event.source,
                  event_id: &event.event_id,
                  checkpoint: &event.checkpoint,
                  observed_at: event.observed_at,
                  offenses,
               }
            })
            .collect::<Vec<_>>();
         store.process_events(&inputs)
      })
      .await?;
      let mut created = false;
      for outcome in &outcomes {
         for lease in &outcome.leases {
            created = true;
            if self.is_spared_lease(lease) {
               crate::metrics::record_no_block_spared();
            }
            if !matches!(lease.action, Action::Observe) && !self.is_protected(lease.network)? {
               self.active_leases.insert(lease.network);
            }
            tracing::debug!(
               "event=ban_created policy={} network={} expires_at={:?} escalation={}",
               lease.policy,
               lease.network,
               lease.expires_at,
               lease.escalation_count
            );
         }
      }
      if created {
         self.reconcile().await?;
      }
      Ok(())
   }

   pub async fn record_listener(&self, policy_name: &str, address: IpAddr) -> Result<()> {
      let compiled = self
         .policies
         .get(policy_name)
         .ok_or_else(|| Error::Config(format!("unknown listener policy {policy_name}")))?;
      if !matches!(
         self.config.sources.get(&compiled.policy.source),
         Some(Source::Listener { .. })
      ) {
         return Err(Error::Config(format!(
            "listener policy {policy_name} reads source {} which is not a listener source",
            compiled.policy.source
         )));
      }
      let network = host_network(address)?;
      if self.is_protected(network)?
         || compiled
            .ignored
            .iter()
            .any(|ignored| networks_overlap(*ignored, network))
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
         let store = Arc::clone(&self.store);
         let policy_name = policy_name.clone();
         let policy = policy.clone();
         let source = source.clone();
         let event_id = event_id.clone();
         let checkpoint = checkpoint.clone();
         let action = action.clone();
         match blocking(move || {
            let mut offense_policy = policy.clone();
            offense_policy.action = action.clone();
            let offense = Self::offense_input(
               &policy_name,
               &offense_policy,
               history_retention_secs,
               network,
               Some(now),
               None,
               None,
            );
            Ok(store
               .lock()
               .process_event(&EventInput {
                  source:      &source,
                  event_id:    &event_id,
                  checkpoint:  &checkpoint,
                  observed_at: now,
                  offenses:    &[offense],
               })?
               .leases)
         })
         .await
         {
            Ok(created) => break created,
            Err(error) => {
               self.processor_ready.store(false, Ordering::Release);
               tracing::error!("listener offense persistence failed; retrying: {error}");
               tokio::time::sleep(Duration::from_millis(100)).await;
            },
         }
      };
      self.processor_ready.store(true, Ordering::Release);
      if !created.is_empty() {
         for lease in &created {
            if self.is_spared_lease(lease) {
               crate::metrics::record_no_block_spared();
            }
            if !matches!(lease.action, Action::Observe) && !self.is_protected(lease.network)? {
               self.active_leases.insert(lease.network);
            }
            tracing::info!(
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
                  tracing::error!("listener offense reconciliation failed; retrying: {error}");
                  tokio::time::sleep(Duration::from_secs(1)).await;
               },
            }
         }
         self.processor_ready.store(true, Ordering::Release);
      }
      Ok(())
   }

   pub async fn bans(&self) -> Result<Vec<Ban>> {
      crate::defense_maintenance::bans(self).await
   }

   pub async fn manual_block(&self, raw: &str, duration_secs: Option<u64>) -> Result<()> {
      crate::defense_maintenance::manual_block(self, raw, duration_secs).await
   }

   pub async fn unblock(&self, raw: &str) -> Result<usize> {
      crate::defense_maintenance::unblock(self, raw).await
   }

   pub async fn reconcile(&self) -> Result<()> {
      crate::defense_maintenance::reconcile(self).await
   }

   pub(super) async fn expire(&self) -> Result<usize> {
      crate::defense_maintenance::expire(self).await
   }

   pub(super) fn is_protected(&self, network: IpNetwork) -> Result<bool> {
      if self
         .protected
         .iter()
         .any(|protected| networks_overlap(*protected, network))
      {
         return Ok(true);
      }
      Ok(local_addresses()?
         .into_iter()
         .map(host_network)
         .collect::<Result<Vec<_>>>()?
         .into_iter()
         .any(|local| networks_overlap(local, network)))
   }

   pub(crate) fn is_no_block_network(&self, network: IpNetwork) -> bool {
      self
         .no_block
         .iter()
         .any(|no_block| networks_overlap(*no_block, network))
   }

   fn enforcement_action(&self, network: IpNetwork, action: &Action) -> Action {
      if self.is_no_block_network(network) && action.block_parts().is_some() {
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
            .is_some_and(|policy| policy.policy.action.block_parts().is_some())
   }
}

#[expect(
   clippy::cast_lossless,
   clippy::items_after_statements,
   clippy::semicolon_inside_block,
   reason = "the getifaddrs block and the guard that frees its list are audited as written and \
             are not reshaped for style"
)]
fn local_addresses() -> std::io::Result<Vec<IpAddr>> {
   let mut head = std::ptr::null_mut();
   // SAFETY: getifaddrs initializes `head` on success. Every pointer is
   // checked before dereference and the list is released exactly once.
   if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
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
               #[expect(
                  clippy::host_endian_bytes,
                  reason = "the libc address value is stored in network byte order"
               )]
               let octets = address.sin_addr.s_addr.to_ne_bytes();
               addresses.push(IpAddr::V4(std::net::Ipv4Addr::from(octets)));
            },
            libc::AF_INET6 => {
               // SAFETY: AF_INET6 guarantees sockaddr_in6 layout.
               let address = unsafe { &*(entry.ifa_addr.cast::<libc::sockaddr_in6>()) };
               addresses.push(IpAddr::V6(std::net::Ipv6Addr::from(
                  address.sin6_addr.s6_addr,
               )));
            },
            _ => {},
         }
      }
      current = entry.ifa_next;
   }
   Ok(addresses)
}

pub(crate) fn membership(lease: &Lease, config: &Config) -> Result<Option<Membership>> {
   let scope = if let Some((verdict, target)) = lease.action.block_parts() {
      let verdict = Verdict::from(verdict);
      match target {
         BlockTarget::All => Scope::all_ports(verdict),
         BlockTarget::Protocol(protocol) => Scope::protocol(protocol.into(), verdict),
         BlockTarget::Ports(protocol, ports) => {
            Scope::new(protocol.into(), ports.to_vec(), verdict)?
         },
      }
   } else if let Action::TarpitRedirect {
      protocol,
      ports,
      listener,
   } = &lease.action
   {
      let port = config
         .listeners
         .iter()
         .find(|candidate| candidate.name() == listener)
         .ok_or_else(|| Error::Config(format!("unknown redirect listener {listener}")))?
         .listen_addr()
         .parse::<std::net::SocketAddr>()
         .map_err(|error| Error::Config(error.to_string()))?
         .port();
      Scope::new((*protocol).into(), ports.clone(), Verdict::Redirect(port))?
   } else {
      return Ok(None);
   };
   Ok(Some(Membership {
      network: lease.network,
      scope,
   }))
}

impl From<TransportProtocol> for Protocol {
   fn from(protocol: TransportProtocol) -> Self {
      match protocol {
         TransportProtocol::Tcp => Self::Tcp,
         TransportProtocol::Udp => Self::Udp,
      }
   }
}

impl From<BlockVerdict> for Verdict {
   fn from(verdict: BlockVerdict) -> Self {
      match verdict {
         BlockVerdict::Drop => Self::Drop,
         BlockVerdict::Reject => Self::Reject,
      }
   }
}

fn host_network(address: IpAddr) -> Result<IpNetwork> {
   IpNetwork::new(address, if address.is_ipv4() { 32 } else { 128 })
      .map_err(|error| Error::Network(error.to_string()))
}

pub(crate) fn parse_network(raw: &str) -> Result<IpNetwork> {
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

pub(crate) async fn blocking<T, F>(operation: F) -> Result<T>
where
   T: Send + 'static,
   F: FnOnce() -> Result<T> + Send + 'static,
{
   tokio::task::spawn_blocking(operation)
      .await
      .map_err(|error| Error::Io(std::io::Error::other(error)))?
}

pub(crate) fn now() -> u64 {
   SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map(|duration| duration.as_secs())
      .unwrap_or_default()
}
