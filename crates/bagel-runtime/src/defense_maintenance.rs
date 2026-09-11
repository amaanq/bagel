use std::{
   collections::BTreeMap,
   sync::Arc,
};

use bagel_admin::Ban;
use bagel_config::Action;
use bagel_core::{
   Error,
   Result,
};
use metrics::{
   counter,
   gauge,
};

use crate::{
   defense::{
      Defense,
      blocking,
      membership,
      now,
      parse_network,
   },
   store::{
      ApplyOutcome,
      Lease,
   },
};

pub async fn bans(defense: &Defense) -> Result<Vec<Ban>> {
   Ok(leases(defense)
      .await?
      .into_iter()
      .map(|lease| {
         Ban {
            network:          lease.network.to_string(),
            policy:           lease.policy,
            action:           lease.action.to_string(),
            created_at:       lease.created_at,
            expires_at:       lease.expires_at,
            escalation_count: u32::try_from(lease.escalation_count).unwrap_or(u32::MAX),
            manual:           lease.manual,
            blocking:         lease.action.block_parts().is_some(),
            apply_state:      lease.apply_state,
            last_error:       lease.last_error,
         }
      })
      .collect())
}

pub async fn manual_block(defense: &Defense, raw: &str, duration_secs: Option<u64>) -> Result<()> {
   if duration_secs == Some(0) {
      return Err(Error::Config("manual ban duration must be non-zero".into()));
   }
   let network = parse_network(raw)?;
   if defense.is_protected(network)? {
      return Err(Error::Config(format!(
         "refusing to block protected network {network}"
      )));
   }
   if defense.is_no_block_network(network) {
      return Err(Error::Config(format!(
         "refusing to block shared network {network}"
      )));
   }
   let store = Arc::clone(defense.store_ref());
   blocking(move || {
      let lease = store
         .lock()
         .manual_block(network, &Action::DropAll, now(), duration_secs)?;
      tracing::info!(
         "event=manual_ban network={} expires_at={:?}",
         lease.network,
         lease.expires_at
      );
      Ok(())
   })
   .await?;
   defense.reconcile().await
}

pub async fn unblock(defense: &Defense, raw: &str) -> Result<usize> {
   let network = parse_network(raw)?;
   let store = Arc::clone(defense.store_ref());
   let changed = blocking(move || store.lock().manual_unblock(network, now())).await?;
   if changed != 0 {
      tracing::info!("event=unban network={network} leases={changed}");
   }
   defense.reconcile().await?;
   Ok(changed)
}

#[expect(
   clippy::cast_precision_loss,
   reason = "lease counts are bounded by the store, far below 2^53"
)]
pub async fn reconcile(defense: &Defense) -> Result<()> {
   let store = Arc::clone(defense.store_ref());
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
      if defense.is_protected(lease.network)? {
         protected.insert(lease.id);
      } else if defense.is_no_block_network(lease.network) {
         spared.insert(lease.id);
      } else {
         memberships.extend(membership(lease, defense.config_ref())?);
      }
   }
   defense.active_leases_ref().replace(
      leases
         .iter()
         .filter(|lease| !matches!(lease.action, Action::Observe) && !protected.contains(&lease.id))
         .map(|lease| lease.network)
         .collect(),
   );
   let result = defense.firewall_ref().reconcile(&memberships).await;
   counter!("bagel_reconciliations_total", "result" => if result.is_ok() { "success" } else { "failure" }).increment(1);
   gauge!("bagel_firewall_ready").set(f64::from(u8::from(defense.firewall_ref().is_ready())));
   let outcomes = leases
      .iter()
      .map(|lease| {
         let outcome = match &result {
            Err(error) => ApplyOutcome::Failed(error.to_string()),
            Ok(())
               if !defense.firewall_ref().required()
                  || matches!(lease.action, Action::Observe)
                  || protected.contains(&lease.id)
                  || spared.contains(&lease.id) =>
            {
               ApplyOutcome::Observed
            },
            Ok(()) => ApplyOutcome::Applied,
         };
         (lease.id, outcome)
      })
      .collect::<Vec<_>>();
   let store = Arc::clone(defense.store_ref());
   blocking(move || {
      let mut store = store.lock();
      store.mark_apply_results(&outcomes)
   })
   .await?;
   let blocked = if defense.firewall_ref().required() {
      leases
         .iter()
         .filter(|lease| {
            lease.action.block_parts().is_some()
               && !protected.contains(&lease.id)
               && !spared.contains(&lease.id)
         })
         .map(|lease| lease.network)
         .collect::<std::collections::BTreeSet<_>>()
         .len()
   } else {
      0
   };
   gauge!("bagel_blocked_ips").set(blocked as f64);
   for policy in defense.policy_names() {
      crate::metrics::set_active_leases(policy, 0.0);
   }
   crate::metrics::set_active_leases("__manual__", 0.0);
   let mut counts = BTreeMap::<&str, usize>::new();
   for lease in &leases {
      *counts.entry(&lease.policy).or_default() += 1;
   }
   for (policy, count) in counts {
      crate::metrics::set_active_leases(policy, count as f64);
   }
   match &result {
      Ok(()) => tracing::debug!("event=reconcile result=success leases={}", leases.len()),
      Err(error) => tracing::error!("event=reconcile result=failure error={error}"),
   }
   result.map_err(Error::Io)
}

async fn leases(defense: &Defense) -> Result<Vec<Lease>> {
   let store = Arc::clone(defense.store_ref());
   blocking(move || store.lock().active_leases(now())).await
}

pub async fn expire(defense: &Defense) -> Result<usize> {
   let store = Arc::clone(defense.store_ref());
   let retention = defense.max_findtime_secs().max(86_400);
   let history_retention = defense.config_ref().history_retention_secs;
   blocking(move || {
      let now = now();
      let mut store = store.lock();
      let expired = store.expire(now)?;
      store.prune_offenses(now.saturating_sub(retention))?;
      store.prune_leases(now.saturating_sub(history_retention), now)?;
      if expired != 0 {
         tracing::info!("event=leases_expired count={expired}");
      }
      Ok(expired)
   })
   .await
}
