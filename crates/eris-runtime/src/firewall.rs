//! Authoritative nftables enforcement.
//!
//! SQLite owns desired ban leases; this module renders their aggregate kernel
//! state in one atomic nft batch. A failed batch never becomes a reported ban.

use ipnetwork::IpNetwork;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    const fn nft(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Verdict {
    Drop,
    Reject,
    Redirect(u16),
}

/// A canonical enforcement scope. Empty ports means every input port.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Scope {
    pub protocol: Option<Protocol>,
    pub ports: Vec<u16>,
    pub verdict: Verdict,
}

impl Scope {
    #[must_use]
    pub fn all_ports() -> Self {
        Self {
            protocol: None,
            ports: Vec::new(),
            verdict: Verdict::Drop,
        }
    }

    #[must_use]
    pub fn protocol(protocol: Protocol) -> Self {
        Self {
            protocol: Some(protocol),
            ports: Vec::new(),
            verdict: Verdict::Drop,
        }
    }

    pub fn new(protocol: Protocol, mut ports: Vec<u16>, verdict: Verdict) -> std::io::Result<Self> {
        ports.sort_unstable();
        ports.dedup();
        if ports.is_empty() {
            return Err(std::io::Error::other(
                "a protocol-scoped firewall rule requires at least one port",
            ));
        }
        if matches!(verdict, Verdict::Redirect(_)) && protocol != Protocol::Tcp {
            return Err(std::io::Error::other(
                "only TCP bans can redirect to a tarpit",
            ));
        }
        Ok(Self {
            protocol: Some(protocol),
            ports,
            verdict,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Membership {
    pub network: IpNetwork,
    pub scope: Scope,
}

pub struct Firewall {
    nft_path: PathBuf,
    table: String,
    priority: i32,
    required: bool,
    ready: AtomicBool,
}

impl Firewall {
    #[must_use]
    pub fn new(nft_path: PathBuf, table: String, priority: i32, required: bool) -> Self {
        Self {
            nft_path,
            table,
            priority,
            required,
            ready: AtomicBool::new(false),
        }
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }

    pub async fn reconcile(&self, memberships: &[Membership]) -> std::io::Result<()> {
        let ruleset = render_ruleset(
            &self.table,
            self.priority,
            if self.required { memberships } else { &[] },
        )?;
        let result = run_nft(&self.nft_path, &ruleset).await;
        self.ready.store(result.is_ok(), Ordering::Release);
        result
    }
}

#[derive(Default)]
struct Families {
    v4: BTreeSet<IpNetwork>,
    v6: BTreeSet<IpNetwork>,
}

fn render_ruleset(
    table: &str,
    priority: i32,
    memberships: &[Membership],
) -> std::io::Result<String> {
    validate_name(table)?;
    let memberships = normalize_memberships(memberships)?;
    let mut grouped: BTreeMap<&Scope, Families> = BTreeMap::new();
    for membership in &memberships {
        let family = grouped.entry(&membership.scope).or_default();
        if membership.network.is_ipv4() {
            family.v4.insert(membership.network);
        } else {
            family.v6.insert(membership.network);
        }
    }

    let mut output = format!("destroy table inet {table}\ntable inet {table} {{\n");
    for (index, families) in grouped.values().enumerate() {
        write_set(&mut output, index, "v4", "ipv4_addr", &families.v4);
        write_set(&mut output, index, "v6", "ipv6_addr", &families.v6);
    }

    let _ = writeln!(
        output,
        "  chain input {{ type filter hook input priority {priority}; policy accept;"
    );
    output.push_str("    fib saddr type local accept\n");
    for verdict in [Verdict::Drop, Verdict::Reject] {
        for (index, scope) in grouped.keys().enumerate() {
            if scope.verdict == verdict {
                write_filter_rules(&mut output, index, scope);
            }
        }
    }
    output.push_str("  }\n");

    if grouped
        .keys()
        .any(|scope| matches!(scope.verdict, Verdict::Redirect(_)))
    {
        output.push_str(
            "  chain prerouting { type nat hook prerouting priority dstnat; policy accept;\n",
        );
        for (index, scope) in grouped.keys().enumerate() {
            if matches!(scope.verdict, Verdict::Redirect(_)) {
                write_redirect_rules(&mut output, index, scope);
            }
        }
        output.push_str("  }\n");
    }
    output.push_str("}\n");
    Ok(output)
}

fn normalize_memberships(memberships: &[Membership]) -> std::io::Result<Vec<Membership>> {
    let mut normalized = memberships
        .iter()
        .filter(|membership| !matches!(membership.scope.verdict, Verdict::Redirect(_)))
        .cloned()
        .collect::<Vec<_>>();
    for (index, membership) in memberships.iter().enumerate() {
        let Verdict::Redirect(target) = membership.scope.verdict else {
            continue;
        };
        let mut ports = membership.scope.ports.clone();
        for blocker in memberships.iter().filter(|candidate| {
            matches!(candidate.scope.verdict, Verdict::Drop | Verdict::Reject)
                && networks_overlap(candidate.network, membership.network)
                && protocols_overlap(&candidate.scope, &membership.scope)
        }) {
            if blocker.scope.protocol.is_none() || blocker.scope.ports.is_empty() {
                ports.clear();
                break;
            }
            ports.retain(|port| !blocker.scope.ports.contains(port));
        }
        if ports.is_empty() {
            continue;
        }
        for other in memberships.iter().skip(index + 1) {
            let Verdict::Redirect(other_target) = other.scope.verdict else {
                continue;
            };
            if target != other_target
                && networks_overlap(other.network, membership.network)
                && protocols_overlap(&other.scope, &membership.scope)
                && ports.iter().any(|port| other.scope.ports.contains(port))
            {
                return Err(std::io::Error::other(format!(
                    "conflicting tarpit redirects for overlapping network {}",
                    membership.network
                )));
            }
        }
        let mut adjusted = membership.clone();
        adjusted.scope.ports = ports;
        normalized.push(adjusted);
    }
    Ok(normalized)
}

fn networks_overlap(left: IpNetwork, right: IpNetwork) -> bool {
    left.is_ipv4() == right.is_ipv4() && (left.contains(right.ip()) || right.contains(left.ip()))
}

fn protocols_overlap(left: &Scope, right: &Scope) -> bool {
    left.protocol.is_none() || right.protocol.is_none() || left.protocol == right.protocol
}

fn write_set(
    output: &mut String,
    index: usize,
    family: &str,
    kind: &str,
    elements: &BTreeSet<IpNetwork>,
) {
    if elements.is_empty() {
        let _ = writeln!(
            output,
            "  set scope_{index}_{family} {{ type {kind}; flags interval; auto-merge; }}"
        );
        return;
    }
    let values = elements
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(
        output,
        "  set scope_{index}_{family} {{ type {kind}; flags interval; auto-merge; elements = {{ {values} }}; }}"
    );
}

fn write_filter_rules(output: &mut String, index: usize, scope: &Scope) {
    let predicate = port_predicate(scope);
    let verdict = match scope.verdict {
        Verdict::Drop => "drop",
        Verdict::Reject => "reject",
        Verdict::Redirect(_) => return,
    };
    let _ = writeln!(
        output,
        "    ip saddr @scope_{index}_v4{predicate} {verdict}"
    );
    let _ = writeln!(
        output,
        "    ip6 saddr @scope_{index}_v6{predicate} {verdict}"
    );
}

fn write_redirect_rules(output: &mut String, index: usize, scope: &Scope) {
    let Verdict::Redirect(port) = scope.verdict else {
        return;
    };
    let predicate = port_predicate(scope);
    let _ = writeln!(
        output,
        "    ip saddr @scope_{index}_v4{predicate} redirect to :{port}"
    );
    let _ = writeln!(
        output,
        "    ip6 saddr @scope_{index}_v6{predicate} redirect to :{port}"
    );
}

fn port_predicate(scope: &Scope) -> String {
    let Some(protocol) = scope.protocol else {
        return String::new();
    };
    if scope.ports.is_empty() {
        return format!(" meta l4proto {}", protocol.nft());
    }
    let ports = scope
        .ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!(" {} dport {{ {ports} }}", protocol.nft())
}

fn validate_name(name: &str) -> std::io::Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(std::io::Error::other(format!(
            "invalid nftables table name {name:?}"
        )));
    }
    Ok(())
}

async fn run_nft(path: &Path, ruleset: &str) -> std::io::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), run_nft_inner(path, ruleset))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "nftables timed out"))?
}

async fn run_nft_inner(path: &Path, ruleset: &str) -> std::io::Result<()> {
    let mut child = Command::new(path)
        .args(["-f", "-"])
        .kill_on_drop(true)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let _write_result = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("nft stdin was not piped"))?
        .write_all(ruleset.as_bytes())
        .await;
    let output = child.wait_with_output().await?;
    if output.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "nftables reconciliation failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_keeps_scopes_and_families_separate() {
        let tcp = Scope::new(Protocol::Tcp, vec![443, 80, 443], Verdict::Drop).unwrap();
        let udp = Scope::protocol(Protocol::Udp);
        let all = Scope::all_ports();
        let rules = render_ruleset(
            "eris",
            -10,
            &[
                Membership {
                    network: "192.0.2.1/32".parse().unwrap(),
                    scope: tcp,
                },
                Membership {
                    network: "2001:db8::/64".parse().unwrap(),
                    scope: all,
                },
                Membership {
                    network: "198.51.100.2/32".parse().unwrap(),
                    scope: udp,
                },
            ],
        )
        .unwrap();
        assert!(rules.contains("tcp dport { 80, 443 } drop"));
        assert!(rules.contains("meta l4proto udp drop"));
        assert!(rules.contains("2001:db8::/64"));
        assert!(rules.contains("priority -10"));
        assert!(!rules.contains("elements = {  }"));
    }

    #[test]
    fn redirect_rejects_udp() {
        assert!(Scope::new(Protocol::Udp, vec![53], Verdict::Redirect(2222)).is_err());
    }

    #[test]
    fn blocks_override_redirects_and_redirect_conflicts_fail() {
        let network = "192.0.2.0/24".parse().unwrap();
        let drop = Membership {
            network,
            scope: Scope::new(Protocol::Tcp, vec![443], Verdict::Drop).unwrap(),
        };
        let redirect = Membership {
            network: "192.0.2.4/32".parse().unwrap(),
            scope: Scope::new(Protocol::Tcp, vec![80, 443], Verdict::Redirect(2222)).unwrap(),
        };
        let rules = render_ruleset("eris", -10, &[drop, redirect.clone()]).unwrap();
        assert!(rules.contains("tcp dport { 80 } redirect to :2222"));
        assert!(!rules.contains("80, 443 } redirect"));

        let conflicting = Membership {
            network,
            scope: Scope::new(Protocol::Tcp, vec![80], Verdict::Redirect(3333)).unwrap(),
        };
        assert!(render_ruleset("eris", -10, &[redirect, conflicting]).is_err());
    }
}
