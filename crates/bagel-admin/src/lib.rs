//! Newline-delimited admin control protocol.

use std::{
   fmt,
   io,
   path::Path,
   time::{
      SystemTime,
      UNIX_EPOCH,
   },
};

use serde::{
   Deserialize,
   Serialize,
};
use tokio::{
   io::{
      AsyncBufReadExt,
      AsyncWriteExt,
      BufReader,
   },
   net::UnixStream,
};

/// A command from the CLI to the daemon.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Request {
   /// Daemon status and counters.
   Status,
   /// Block an IP now.
   Block {
      network:       String,
      duration_secs: Option<u64>,
   },
   /// Unblock an address or CIDR now.
   Unblock {
      network: String,
   },
   /// Active durable enforcement leases.
   ListBans,
   ListPolicies,
   /// Rebuild the owned nftables table from durable leases.
   Reconcile,
}

/// The daemon's reply.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
   Status(Status),
   Bans(Vec<Ban>),
   Policies(Vec<PolicyStatus>),
   /// A management command succeeded, with a human-readable note.
   Ok(String),
   /// The request could not be served.
   Error(String),
}

/// Daemon status snapshot.
#[derive(Clone, Serialize, Deserialize)]
pub struct Status {
   pub version:            String,
   pub uptime_secs:        u64,
   pub blocked_ips:        usize,
   pub active_connections: usize,
   pub firewall_ready:     bool,
   pub active_bans:        usize,
   pub policy_count:       usize,
   pub source_count:       usize,
   /// Independently configured HTTP and SSH endpoint snapshots.
   #[serde(default)]
   pub endpoints:          Vec<EndpointStatus>,
}

/// One active desired enforcement lease.
#[derive(Clone, Serialize, Deserialize)]
pub struct Ban {
   pub network:          String,
   pub policy:           String,
   pub action:           String,
   pub created_at:       u64,
   pub expires_at:       Option<u64>,
   pub escalation_count: u32,
   pub manual:           bool,
   pub blocking:         bool,
   pub apply_state:      String,
   pub last_error:       Option<String>,
}

/// Static policy identity exposed for operator inspection.
#[derive(Clone, Serialize, Deserialize)]
pub struct PolicyStatus {
   pub name:   String,
   pub source: String,
   pub action: String,
}

/// Bounded operational counters for one configured endpoint.
#[derive(Clone, Serialize, Deserialize)]
pub struct EndpointStatus {
   pub name:                      String,
   pub listen_addr:               String,
   pub ready:                     bool,
   pub accepted:                  u64,
   pub active:                    usize,
   pub rejected:                  u64,
   pub closed:                    u64,
   pub bytes_sent:                u64,
   pub trapped_seconds:           u64,
   pub tarpit_capacity:           usize,
   pub available_tarpit_capacity: usize,
}

impl fmt::Display for Status {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      writeln!(
         f,
         "bagel {} - up {}",
         self.version,
         format_uptime(self.uptime_secs)
      )?;
      writeln!(f, "  blocked IPs:        {}", self.blocked_ips)?;
      writeln!(f, "  active bans:        {}", self.active_bans)?;
      writeln!(
         f,
         "  firewall:           {}",
         if self.firewall_ready {
            "ready"
         } else {
            "not ready"
         }
      )?;
      writeln!(
         f,
         "  policies/sources:   {}/{}",
         self.policy_count, self.source_count
      )?;
      writeln!(f, "  active connections: {}", self.active_connections)?;
      if !self.endpoints.is_empty() {
         writeln!(f, "\nendpoints:")?;
         for endpoint in &self.endpoints {
            writeln!(
               f,
               "  {:<12} {:<21} {} active {}/{} ({} free) accepted {} rejected {} closed {} bytes \
                {} trapped {}s",
               endpoint.name,
               endpoint.listen_addr,
               if endpoint.ready { "ready" } else { "down " },
               endpoint.active,
               endpoint.tarpit_capacity,
               endpoint.available_tarpit_capacity,
               endpoint.accepted,
               endpoint.rejected,
               endpoint.closed,
               endpoint.bytes_sent,
               endpoint.trapped_seconds,
            )?;
         }

         // Fleet-wide rollup so the headline numbers do not require
         // mentally summing per-endpoint rows.
         let accepted: u64 = self.endpoints.iter().map(|e| e.accepted).sum();
         let rejected: u64 = self.endpoints.iter().map(|e| e.rejected).sum();
         let bytes: u64 = self.endpoints.iter().map(|e| e.bytes_sent).sum();
         let trapped: u64 = self.endpoints.iter().map(|e| e.trapped_seconds).sum();
         let active: usize = self.endpoints.iter().map(|e| e.active).sum();
         let capacity: usize = self.endpoints.iter().map(|e| e.tarpit_capacity).sum();
         #[expect(
            clippy::cast_precision_loss,
            clippy::float_arithmetic,
            reason = "live connection counts stay far below 2^53, where f64 is still exact"
         )]
         let used = if capacity == 0 {
            0.0
         } else {
            active as f64 / capacity as f64
         };
         writeln!(
            f,
            "  {:<12} {:<21}       active {}/{}      accepted {} rejected {} bytes {} trapped {}",
            "TOTAL",
            "",
            active,
            capacity,
            accepted,
            rejected,
            bytes,
            format_uptime(trapped),
         )?;
         writeln!(
            f,
            "  capacity used:      {:>5.1}%  {}",
            {
               #[expect(
                  clippy::float_arithmetic,
                  reason = "percentage formatting requires converting the ratio to percent"
               )]
               let percent = used * 100.0;
               percent
            },
            bar(used, 24)
         )?;
      }
      Ok(())
   }
}

impl fmt::Display for Ban {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      write!(
         f,
         "{:<43} {:<20} {:<16} {} [{}]",
         self.network,
         self.policy,
         self.action,
         self.expires_at.map_or_else(|| "permanent".to_owned(), rel),
         self.apply_state,
      )?;
      if let Some(error) = &self.last_error {
         write!(f, "\n  error: {error}")?;
      }
      Ok(())
   }
}

impl fmt::Display for PolicyStatus {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      write!(f, "{:<24} {:<24} {}", self.name, self.source, self.action)
   }
}

impl fmt::Display for Response {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
         Self::Status(status) => write!(f, "{status}"),
         Self::Bans(bans) if bans.is_empty() => {
            writeln!(f, "no active bans")
         },
         Self::Bans(bans) => {
            for ban in bans {
               writeln!(f, "{ban}")?;
            }
            Ok(())
         },
         Self::Policies(policies) if policies.is_empty() => {
            writeln!(f, "no policies configured")
         },
         Self::Policies(policies) => {
            for policy in policies {
               writeln!(f, "{policy}")?;
            }
            Ok(())
         },
         Self::Ok(msg) => writeln!(f, "{msg}"),
         Self::Error(msg) => writeln!(f, "error: {msg}"),
      }
   }
}

fn bar(frac: f64, width: usize) -> String {
   #[expect(
      clippy::cast_precision_loss,
      reason = "width is the caller's fixed column count and never approaches 2^53"
   )]
   #[expect(
      clippy::float_arithmetic,
      clippy::cast_sign_loss,
      reason = "the clamped ratio is converted to a bounded display width"
   )]
   let filled = (frac.clamp(0.0, 1.0) * width as f64).round() as usize;
   let mut s = String::with_capacity(width);
   for _ in 0..filled {
      s.push('\u{2588}');
   }
   for _ in filled..width {
      s.push('\u{2591}');
   }
   s
}

fn rel(ts: u64) -> String {
   let now = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map(|d| d.as_secs())
      .unwrap_or_default();
   let secs = now.saturating_sub(ts);
   match secs {
      0..=59 => format!("{secs}s ago"),
      60..=3599 => format!("{}m ago", secs / 60),
      3600..=86_399 => format!("{}h ago", secs / 3600),
      _ => format!("{}d ago", secs / 86_400),
   }
}

fn format_uptime(secs: u64) -> String {
   let (d, h, m, s) = (
      secs / 86400,
      secs % 86400 / 3600,
      secs % 3600 / 60,
      secs % 60,
   );
   match (d, h) {
      (0, 0) => format!("{m}m {s}s"),
      (0, _) => format!("{h}h {m}m"),
      _ => format!("{d}d {h}h {m}m"),
   }
}

/// Send one request to the daemon socket and read one response.
pub async fn query(socket: &Path, request: &Request) -> io::Result<Response> {
   let stream = UnixStream::connect(socket).await?;
   let mut reader = BufReader::new(stream);

   let mut line = serde_json::to_vec(request).map_err(io::Error::other)?;
   line.push(b'\n');
   reader.get_mut().write_all(&line).await?;

   let mut buf = String::new();
   reader.read_line(&mut buf).await?;
   if buf.trim().is_empty() {
      return Err(io::Error::other(
         "daemon closed the connection without a reply",
      ));
   }
   serde_json::from_str(buf.trim_end()).map_err(io::Error::other)
}
