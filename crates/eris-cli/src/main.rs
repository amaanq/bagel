//! `eris`: the admin CLI for the Eris tarpit daemon.
//!
//! It speaks the `eris-admin` protocol over the daemon's Unix control socket:
//! observability (`status`, `bans`, `hits`, `report`, `ip`) and management
//! (`block`, `unblock`).

use anyhow::Context;
use clap::{Parser, Subcommand};
use eris_admin::{Request, Response, Tally};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "eris", version, about = "Admin CLI for the Eris tarpit daemon")]
struct Cli {
    /// Path to the daemon admin socket.
    #[arg(
        long,
        short = 's',
        env = "ERIS_ADMIN_SOCKET",
        default_value = eris_core::DEFAULT_ADMIN_SOCKET,
        global = true
    )]
    socket: PathBuf,

    /// Emit machine-readable JSON instead of formatted text.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show daemon status and counters.
    Status,
    /// Show the most-hit IPs, highest first.
    Hits {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Categorised overview: who is scanning and what they probe for.
    Report {
        /// Rows to show per section.
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
    /// Drill into one IP: categories, sample paths, first/last seen.
    Ip { ip: IpAddr },
    /// Add a manual durable ban for an address or CIDR.
    Block {
        network: String,
        #[arg(long)]
        duration_secs: Option<u64>,
    },
    /// Remove manual and automatic bans for an address or CIDR.
    Unblock { network: String },
    /// List active durable enforcement leases.
    Bans,
    /// List configured defense policies.
    Policies,
    /// Rebuild Eris' nftables table from durable leases.
    Reconcile,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let request = match &cli.command {
        Command::Status => Request::Status,
        Command::Hits { limit } => Request::TopHits { limit: *limit },
        Command::Report { limit } => Request::Report { limit: *limit },
        Command::Ip { ip } => Request::IpDetail { ip: *ip },
        Command::Block {
            network,
            duration_secs,
        } => Request::Block {
            network: network.clone(),
            duration_secs: *duration_secs,
        },
        Command::Unblock { network } => Request::Unblock {
            network: network.clone(),
        },
        Command::Bans => Request::ListBans,
        Command::Policies => Request::ListPolicies,
        Command::Reconcile => Request::Reconcile,
    };

    let response = eris_admin::query(&cli.socket, &request)
        .await
        .with_context(|| format!("cannot reach the eris daemon at {}", cli.socket.display()))?;

    let is_error = matches!(response, Response::Error(_));
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        print_human(&response);
    }

    // Surface a daemon-side error as a non-zero exit.
    if is_error {
        std::process::exit(1);
    }
    Ok(())
}

fn print_human(response: &Response) {
    match response {
        Response::Status(s) => {
            println!("eris {} - up {}", s.version, format_uptime(s.uptime_secs));
            println!("  blocked IPs:        {}", s.blocked_ips);
            println!("  active bans:        {}", s.active_bans);
            println!(
                "  firewall:           {}",
                if s.firewall_ready {
                    "ready"
                } else {
                    "not ready"
                }
            );
            println!(
                "  policies/sources:   {}/{}",
                s.policy_count, s.source_count
            );
            println!("  active connections: {}", s.active_connections);
            println!("  tracked IPs:        {}", s.tracked_ips);
            if !s.endpoints.is_empty() {
                println!("\nendpoints:");
                for endpoint in &s.endpoints {
                    println!(
                        "  {:<12} {:<4} {:<21} {} active {}/{} ({} free) accepted {} rejected {} closed {} bytes {} trapped {}s",
                        endpoint.name,
                        endpoint.protocol,
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
                    );
                }

                // Fleet-wide rollup so the headline numbers do not require
                // mentally summing per-endpoint rows.
                let accepted: u64 = s.endpoints.iter().map(|e| e.accepted).sum();
                let rejected: u64 = s.endpoints.iter().map(|e| e.rejected).sum();
                let bytes: u64 = s.endpoints.iter().map(|e| e.bytes_sent).sum();
                let trapped: u64 = s.endpoints.iter().map(|e| e.trapped_seconds).sum();
                let active: usize = s.endpoints.iter().map(|e| e.active).sum();
                let capacity: usize = s.endpoints.iter().map(|e| e.tarpit_capacity).sum();
                let used = if capacity == 0 {
                    0.0
                } else {
                    active as f64 / capacity as f64
                };
                println!(
                    "  {:<12} {:<4} {:<21}       active {}/{}      accepted {} rejected {} bytes {} trapped {}",
                    "TOTAL",
                    "",
                    "",
                    active,
                    capacity,
                    accepted,
                    rejected,
                    bytes,
                    format_uptime(trapped),
                );
                println!(
                    "  capacity used:      {:>5.1}%  {}",
                    used * 100.0,
                    bar(used, 24)
                );
            }
        }
        Response::Hits(hits) if hits.is_empty() => println!("no hits recorded"),
        Response::Hits(hits) => hits
            .iter()
            .for_each(|h| println!("{:>8}  {}", h.count, h.ip)),
        Response::Bans(bans) if bans.is_empty() => println!("no active bans"),
        Response::Bans(bans) => {
            for ban in bans {
                println!(
                    "{:<43} {:<20} {:<16} {} [{}]",
                    ban.network,
                    ban.policy,
                    ban.action,
                    ban.expires_at.map_or_else(|| "permanent".to_string(), rel),
                    ban.apply_state,
                );
                if let Some(error) = &ban.last_error {
                    println!("  error: {error}");
                }
            }
        }
        Response::Policies(policies) if policies.is_empty() => println!("no policies configured"),
        Response::Policies(policies) => {
            for policy in policies {
                println!(
                    "{:<24} {:<24} {}",
                    policy.name, policy.source, policy.action
                );
            }
        }
        Response::Report(r) => print_report(r),
        Response::IpDetail(None) => println!("IP not tracked"),
        Response::IpDetail(Some(d)) => {
            println!("{}", d.ip);
            println!("  hits:       {}", d.hits);
            println!("  first seen: {}", rel(d.first_seen));
            println!("  last seen:  {}", rel(d.last_seen));
            if let Some(ua) = &d.last_user_agent {
                println!("  user agent: {}", display(ua));
            }
            print_tallies("categories", &d.categories);
            print_tallies("sample paths", &d.sample_paths);
        }
        Response::Ok(msg) => println!("{msg}"),
        Response::Error(msg) => eprintln!("error: {msg}"),
    }
}

fn display(value: &str) -> String {
    value.escape_default().to_string()
}

fn print_report(r: &eris_admin::Report) {
    println!(
        "scan report > {} tracked IPs, {} total hits",
        r.tracked_ips, r.total_hits
    );
    print_defense_breakdown(&r.categories, r.total_hits);
    print_distribution("categories", &r.categories, r.total_hits);
    print_tallies("top paths", &r.top_paths);
    print_tallies("top user agents", &r.top_user_agents);

    println!("\ntop scanners:");
    if r.top_scanners.is_empty() {
        println!("  none");
        return;
    }
    for s in &r.top_scanners {
        println!(
            "  {:>8}  {:<39}  {:<15}  seen {}",
            s.hits,
            s.ip.to_string(),
            s.top_category,
            rel(s.last_seen),
        );
    }
}

/// Roll the per-category totals up into the four defence mechanisms that
/// produced them, so an operator can see at a glance how traffic is being
/// caught: path signatures, abusive user agents, volume floods, and git
/// enumeration. Categories map to mechanisms by their stable labels.
fn print_defense_breakdown(categories: &[Tally], total: u64) {
    let sum = |labels: &[&str]| -> u64 {
        categories
            .iter()
            .filter(|t| labels.contains(&t.label.as_str()))
            .map(|t| t.count)
            .sum()
    };
    let scraper = sum(&["scraper"]);
    let flood = sum(&["flood"]);
    let git_scan = sum(&["git_scan"]);
    let ssh = sum(&["ssh"]);
    // Everything else is a path/request signature match.
    let signature = total.saturating_sub(scraper + flood + git_scan + ssh);

    println!("\ndefense breakdown:");
    for (label, count) in [
        ("path signatures", signature),
        ("abusive agents", scraper),
        ("volume floods", flood),
        ("git enumeration", git_scan),
        ("ssh tarpit", ssh),
    ] {
        print_share_row(label, count, total);
    }
}

/// Print a titled distribution: each row as count, percentage, and a bar. A
/// text stand-in for a pie chart.
fn print_distribution(title: &str, rows: &[Tally], total: u64) {
    println!("\n{title}:");
    if rows.is_empty() {
        println!("  none");
        return;
    }
    for row in rows {
        print_share_row(&display(&row.label), row.count, total);
    }
}

/// One `label  count  pct  bar` row scaled against `total`.
fn print_share_row(label: &str, count: u64, total: u64) {
    let frac = if total == 0 {
        0.0
    } else {
        count as f64 / total as f64
    };
    println!(
        "  {:<16} {:>8}  {:>5.1}%  {}",
        label,
        count,
        frac * 100.0,
        bar(frac, 24)
    );
}

/// A unicode block bar `width` cells wide representing `frac` in `[0, 1]`.
fn bar(frac: f64, width: usize) -> String {
    let filled = (frac.clamp(0.0, 1.0) * width as f64).round() as usize;
    let mut s = String::with_capacity(width);
    for _ in 0..filled {
        s.push('█');
    }
    for _ in filled..width {
        s.push('░');
    }
    s
}

/// Print a titled list of labelled counts, count first.
fn print_tallies(title: &str, rows: &[Tally]) {
    println!("\n{title}:");
    if rows.is_empty() {
        println!("  none");
        return;
    }
    for row in rows {
        println!("  {:>8}  {}", row.count, display(&row.label));
    }
}

/// Render a Unix timestamp as an approximate age relative to now.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_escapes_terminal_controls() {
        assert_eq!(display("bot\u{1b}[2J"), "bot\\u{1b}[2J");
    }
}
