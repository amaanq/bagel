//! Admin control protocol for the Eris daemon.
//!
//! The daemon exposes a Unix-domain socket; the CLI connects and exchanges one
//! newline-delimited JSON `Request` for one `Response`. Keeping the wire types
//! here lets the daemon (server) and CLI (client) share one definition.

use serde::{Deserialize, Serialize};
use std::io;
use std::net::IpAddr;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// A command from the CLI to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    /// Daemon status and counters.
    Status,
    /// The `limit` most-hit IPs, highest first.
    TopHits { limit: usize },
    /// A categorised overview of scan activity, `limit` rows per section.
    Report { limit: usize },
    /// A per-IP drill-down: categories, sample paths, timestamps.
    IpDetail { ip: IpAddr },
    /// Block an IP now (in memory and in the firewall).
    Block {
        network: String,
        duration_secs: Option<u64>,
    },
    /// Unblock an address or CIDR now.
    Unblock { network: String },
    /// Active durable enforcement leases.
    ListBans,
    /// Configured defense policies.
    ListPolicies,
    /// Rebuild the owned nftables table from durable leases.
    Reconcile,
}

/// The daemon's reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    Status(Status),
    Hits(Vec<Hit>),
    Bans(Vec<Ban>),
    Policies(Vec<PolicyStatus>),
    /// A categorised overview of scan activity.
    Report(Report),
    /// A per-IP drill-down, or `None` if the IP is not tracked.
    IpDetail(Option<IpDetail>),
    /// A management command succeeded, with a human-readable note.
    Ok(String),
    /// The request could not be served.
    Error(String),
}

/// Daemon status snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub version: String,
    pub uptime_secs: u64,
    pub blocked_ips: usize,
    pub active_connections: usize,
    pub tracked_ips: usize,
    pub firewall_ready: bool,
    pub active_bans: usize,
    pub policy_count: usize,
    pub source_count: usize,
    /// Independently configured HTTP and SSH endpoint snapshots.
    #[serde(default)]
    pub endpoints: Vec<EndpointStatus>,
}

/// One active desired enforcement lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ban {
    pub network: String,
    pub policy: String,
    pub action: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub escalation_count: u32,
    pub manual: bool,
    pub blocking: bool,
    pub apply_state: String,
    pub last_error: Option<String>,
}

/// Static policy identity exposed for operator inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStatus {
    pub name: String,
    pub source: String,
    pub action: String,
}

/// Bounded operational counters for one configured endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointStatus {
    pub name: String,
    pub protocol: String,
    pub listen_addr: String,
    pub ready: bool,
    pub accepted: u64,
    pub active: usize,
    pub rejected: u64,
    pub closed: u64,
    pub bytes_sent: u64,
    pub trapped_seconds: u64,
    pub tarpit_capacity: usize,
    pub available_tarpit_capacity: usize,
}

/// An IP and its hit count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hit {
    pub ip: IpAddr,
    pub count: u32,
}

/// A labelled count, used for category totals, top paths, and top user agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tally {
    pub label: String,
    pub count: u64,
}

/// One row of the top-scanners table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scanner {
    pub ip: IpAddr,
    pub hits: u32,
    /// The category this IP hit most often.
    pub top_category: String,
    /// Unix timestamp (seconds) of the most recent hit.
    pub last_seen: u64,
}

/// A categorised overview of scan activity across all tracked IPs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Total hits per category, highest first.
    pub categories: Vec<Tally>,
    /// The most-probed paths, highest first.
    pub top_paths: Vec<Tally>,
    /// The most-seen user agents, highest first.
    pub top_user_agents: Vec<Tally>,
    /// The busiest scanner IPs, highest first.
    pub top_scanners: Vec<Scanner>,
    /// Total tracked IPs and total recorded hits, for context.
    pub tracked_ips: usize,
    pub total_hits: u64,
}

/// A per-IP drill-down.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpDetail {
    pub ip: IpAddr,
    pub hits: u32,
    /// Unix timestamps (seconds).
    pub first_seen: u64,
    pub last_seen: u64,
    /// Per-category hit counts for this IP, highest first.
    pub categories: Vec<Tally>,
    /// A bounded sample of the paths this IP probed, highest first.
    pub sample_paths: Vec<Tally>,
    /// The most recent user agent seen from this IP.
    pub last_user_agent: Option<String>,
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
