use std::net::IpAddr;

use super::types::ChallengeKey;
use crate::ip_network_prefix as network_prefix;

/// Keep challenge keys stable for one duration bucket and accept adjacent
/// buckets.
#[must_use]
pub fn bucket_expiry(now: i64, duration_secs: i64) -> i64 {
   let step = duration_secs.max(1);
   now.div_euclid(step).saturating_add(1).saturating_mul(step)
}

/// Derive a challenge key from request parameters.
#[must_use]
pub fn derive_challenge_key(
   challenge_name: &str,
   client_ip: Option<IpAddr>,
   expiry_epoch: i64,
   key_fingerprint: &[u8; 32],
) -> ChallengeKey {
   let mut buf = Vec::new();

   buf.extend_from_slice(b"challenge\0");
   buf.extend_from_slice(challenge_name.as_bytes());

   if let Some(ip) = client_ip {
      let prefix = network_prefix(ip);
      buf.extend_from_slice(prefix.as_bytes());
   }

   buf.extend_from_slice(&expiry_epoch.to_le_bytes());

   buf.extend_from_slice(key_fingerprint);

   ring::digest::digest(&ring::digest::SHA256, &buf)
      .as_ref()
      .try_into()
      .expect("sha256 output is 32 bytes")
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn bucketed_expiry_is_stable_within_a_bucket() {
      assert_eq!(bucket_expiry(1000, 3600), bucket_expiry(1001, 3600));
      assert_eq!(bucket_expiry(1000, 3600), bucket_expiry(3599, 3600));
      assert_ne!(bucket_expiry(3599, 3600), bucket_expiry(3600, 3600));
      assert!(bucket_expiry(1000, 3600) > 1000);
   }
}
