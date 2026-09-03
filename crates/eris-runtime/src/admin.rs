//! The daemon's admin control socket: a Unix-domain socket speaking the
//! newline-delimited JSON protocol from `eris-admin`. Observability queries are
//! read-only; management commands mutate live state and the firewall.

use crate::defense::Defense;
use crate::server::EndpointStats;
use crate::state::State;
use eris_admin::{Hit, Request, Response, Status};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

const MAX_REQUEST: u64 = 64 * 1024;
const MAX_HANDLERS: usize = 64;

/// Bind the admin socket at `path` and serve requests until `shutdown`.
pub async fn serve(
    path: PathBuf,
    state: Arc<State>,
    defense: Arc<Defense>,
    started: Instant,
    endpoints: Arc<Vec<Arc<EndpointStats>>>,
    shutdown: CancellationToken,
) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // A stale socket from a previous run would make bind fail with EADDRINUSE.
    let _ = std::fs::remove_file(&path);

    let listener = UnixListener::bind(&path)?;
    // Owner + group only: the socket is a privileged control channel.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))?;
    log::info!("admin socket listening on {}", path.display());

    let handlers = Arc::new(Semaphore::new(MAX_HANDLERS));
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let Ok(permit) = handlers.clone().try_acquire_owned() else {
                        continue;
                    };
                    let ctx = Ctx { state: state.clone(), defense: defense.clone(), started, endpoints: endpoints.clone() };
                    tokio::spawn(async move {
                        let _permit = permit;
                        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle(stream, ctx)).await;
                    });
                }
                Err(e) => log::warn!("admin accept error: {e}"),
            },
        }
    }

    let _ = std::fs::remove_file(&path);
    Ok(())
}

struct Ctx {
    state: Arc<State>,
    defense: Arc<Defense>,
    started: Instant,
    endpoints: Arc<Vec<Arc<EndpointStats>>>,
}

async fn handle(stream: UnixStream, ctx: Ctx) {
    let mut reader = BufReader::new(stream);
    let mut bytes = Vec::with_capacity(MAX_REQUEST as usize);
    loop {
        let Ok(chunk) = reader.fill_buf().await else {
            return;
        };
        if chunk.is_empty() {
            return;
        }
        let length = chunk
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(chunk.len(), |index| index + 1);
        if bytes.len() + length > MAX_REQUEST as usize {
            return;
        }
        bytes.extend_from_slice(&chunk[..length]);
        reader.consume(length);
        if bytes.last() == Some(&b'\n') {
            break;
        }
    }
    let Ok(line) = std::str::from_utf8(&bytes) else {
        return;
    };
    if line.trim().is_empty() {
        return;
    }

    let response = match serde_json::from_str::<Request>(line.trim_end()) {
        Ok(request) => dispatch(request, &ctx).await,
        Err(e) => Response::Error(format!("malformed request: {e}")),
    };

    if let Ok(mut bytes) = serde_json::to_vec(&response) {
        bytes.push(b'\n');
        let _ = reader.get_mut().write_all(&bytes).await;
    }
}

async fn dispatch(request: Request, ctx: &Ctx) -> Response {
    match request {
        Request::Status => match ctx.defense.bans().await {
            Ok(bans) => Response::Status(Status {
                version: env!("CARGO_PKG_VERSION").to_string(),
                uptime_secs: ctx.started.elapsed().as_secs(),
                blocked_ips: bans
                    .iter()
                    .filter(|ban| ban.apply_state == "applied" && ban.blocking)
                    .map(|ban| &ban.network)
                    .collect::<std::collections::BTreeSet<_>>()
                    .len(),
                active_connections: ctx.state.active_count(),
                tracked_ips: ctx.state.tracked_count(),
                firewall_ready: ctx.defense.firewall().is_ready(),
                active_bans: bans.len(),
                policy_count: ctx.defense.policy_count(),
                source_count: ctx.defense.source_count(),
                endpoints: ctx
                    .endpoints
                    .iter()
                    .map(|endpoint| endpoint.snapshot())
                    .collect(),
            }),
            Err(error) => Response::Error(error.to_string()),
        },
        Request::TopHits { limit } => Response::Hits(
            ctx.state
                .top_hits(limit)
                .into_iter()
                .map(|(ip, count)| Hit { ip, count })
                .collect(),
        ),
        Request::Report { limit } => Response::Report(ctx.state.report(limit)),
        Request::IpDetail { ip } => Response::IpDetail(ctx.state.ip_detail(ip)),
        Request::Block {
            network,
            duration_secs,
        } => match ctx.defense.manual_block(&network, duration_secs).await {
            Ok(()) => Response::Ok(format!("blocked {network}")),
            Err(error) => Response::Error(error.to_string()),
        },
        Request::Unblock { network } => match ctx.defense.unblock(&network).await {
            Ok(0) => Response::Ok(format!("{network} was not blocked")),
            Ok(_) => Response::Ok(format!("unblocked {network}")),
            Err(error) => Response::Error(error.to_string()),
        },
        Request::ListBans => match ctx.defense.bans().await {
            Ok(bans) => Response::Bans(bans),
            Err(error) => Response::Error(error.to_string()),
        },
        Request::ListPolicies => Response::Policies(ctx.defense.policies()),
        Request::Reconcile => match ctx.defense.reconcile().await {
            Ok(()) => Response::Ok("reconciled nftables state".into()),
            Err(error) => Response::Error(error.to_string()),
        },
    }
}

/// Best-effort removal of the admin socket, e.g. on shutdown.
pub fn cleanup(path: &Path) {
    let _ = std::fs::remove_file(path);
}
