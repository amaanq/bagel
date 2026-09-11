use std::{
   convert::Infallible,
   fs,
   net::{
      IpAddr,
      Ipv4Addr,
      SocketAddr,
   },
   path::Path,
   sync::Arc,
   time::Duration,
};

#[cfg(not(feature = "acme"))] use bagel_core::Error;
use hyper::{
   Request as HyperRequest,
   body::Incoming,
   service::service_fn,
};
use hyper_util::{
   rt::{
      TokioExecutor,
      TokioIo,
      TokioTimer,
   },
   server::conn::auto::Builder as AutoBuilder,
};
use ring::{
   rand::SystemRandom,
   signature::Ed25519KeyPair,
};
use tokio::{
   io::{
      AsyncRead,
      AsyncWrite,
   },
   net::{
      TcpListener,
      UnixListener,
   },
   sync::{
      OwnedSemaphorePermit,
      Semaphore,
   },
};
use tokio_util::sync::CancellationToken;

use crate::{
   body::{
      Body,
      Request,
   },
   config::{
      BindNetwork,
      Config,
      TlsConfig,
   },
   error,
   hex_decode,
   hex_encode,
   metrics as bmetrics,
   net::DropHandle,
   routes::dispatch,
   state::{
      self,
      SharedState,
      StateInner,
   },
   tls::{
      self as bagel_tls,
      PeekStream,
      TlsFingerprint,
      fingerprint::parse_client_hello,
      validate_bind,
   },
};

/// Build and install a new web state from `config`.
pub async fn reload_shared(config: Config, shared: &SharedState) {
   let old_state = shared.load();
   let (old_bind, new_bind) = (&old_state.config.bind, &config.bind);
   if old_bind.network != new_bind.network
      || old_bind.address != new_bind.address
      || old_bind.socket_mode != new_bind.socket_mode
      || old_bind.tls != new_bind.tls
   {
      tracing::error!(
         "reload rejected, changing the bind network, address, socket mode, or TLS needs a restart"
      );
      return;
   }
   let pkcs8_seed = old_state.keys.pkcs8_seed.clone();
   match StateInner::rebuild(
      config,
      pkcs8_seed,
      old_state.keys.seed_persistent,
      Some(&old_state),
   )
   .await
   {
      Ok(new_inner) => {
         shared.store(Arc::new(new_inner));
         tracing::info!("configuration reloaded successfully");
      },
      Err(err) => {
         tracing::error!(error = %err, "failed to build state from new config");
      },
   }
}

trait ConnStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> ConnStream for S {}

/// An accepted socket with its stream type erased.
type BoxedStream = Box<dyn ConnStream>;

const MAX_WEB_CONNECTIONS: usize = 8_192;
const PREFACE_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_HEADER_TIMEOUT: Duration = Duration::from_secs(30);

/// Complete a PROXY header the peer may have split across segments. Returns
/// the source address it carried, if any, after skipping the header bytes.
async fn take_proxy_header(peek_stream: &mut PeekStream<BoxedStream>) -> Option<SocketAddr> {
   use bagel_proto::proxy_protocol::Parsed;
   const PROXY_HEADER_CAP: usize = 536;
   loop {
      match bagel_proto::proxy_protocol::parse(peek_stream.peeked_data()) {
         Parsed::Complete { source, consumed } => {
            peek_stream.advance(consumed);
            return source;
         },
         Parsed::NotProxy => return None,
         Parsed::Incomplete => {
            if peek_stream.peeked_data().len() >= PROXY_HEADER_CAP
               || !matches!(peek_stream.peek_more(512).await, Ok(n) if n > 0)
            {
               return None;
            }
         },
      }
   }
}

pub(super) fn trusts_proxy_peer(shared: &SharedState, peer: IpAddr) -> bool {
   let state = shared.load();
   state.config.bind.proxy_protocol && state.policy.client_ip.trusts(peer)
}

#[derive(Clone)]
pub(super) enum Tls {
   None,
   Manual(tokio_rustls::TlsAcceptor),
   #[cfg(feature = "acme")]
   Acme(Arc<bagel_tls::acme::AcmeHandles>),
}

/// Read until the whole `ClientHello` record is buffered, so it can be
/// fingerprinted.
async fn fill_client_hello(peek_stream: &mut PeekStream<BoxedStream>) {
   const RECORD_HEADER: usize = 5;
   const MAX_CLIENT_HELLO: usize = 64 * 1024;
   const HANDSHAKE: u8 = 0x16;

   let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
      loop {
         let have = peek_stream.peeked_data().len();
         if have >= MAX_CLIENT_HELLO {
            return;
         }
         if have < RECORD_HEADER {
            if peek_stream
               .peek_more(RECORD_HEADER - have)
               .await
               .unwrap_or(0)
               == 0
            {
               return;
            }
            continue;
         }
         if peek_stream.peeked_data()[0] != HANDSHAKE {
            return;
         }
         let mut record_end = 0;
         while record_end + RECORD_HEADER <= have {
            let data = peek_stream.peeked_data();
            let length = usize::from(u16::from_be_bytes([
               data[record_end + 3],
               data[record_end + 4],
            ]));
            record_end += RECORD_HEADER + length;
            if record_end > have {
               break;
            }
         }
         if record_end > have {
            let want = record_end.min(MAX_CLIENT_HELLO);
            if peek_stream.peek_more(want - have).await.unwrap_or(0) == 0 {
               return;
            }
            continue;
         }
         if parse_client_hello(peek_stream.peeked_data()).is_some() {
            return;
         }
         if peek_stream
            .peek_more(RECORD_HEADER.min(MAX_CLIENT_HELLO - have))
            .await
            .unwrap_or(0)
            == 0
         {
            return;
         }
      }
   })
   .await;
}

async fn serve_stream(
   stream: BoxedStream,
   peer: Option<SocketAddr>,
   drop_fd: Option<std::os::fd::RawFd>,
   tls: Tls,
   shared: SharedState,
   _connection_slot: OwnedSemaphorePermit,
) {
   let mut addr = peer.unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
   let proxy_allowed = peer.map_or_else(
      || shared.load().config.bind.proxy_protocol,
      |peer_addr| trusts_proxy_peer(&shared, peer_addr.ip()),
   );
   let mut peek_stream = PeekStream::new(stream, 1500);
   if tokio::time::timeout(PREFACE_TIMEOUT, async {
      let peeked = peek_stream.peek(1500).await.is_ok();
      if peeked
         && proxy_allowed
         && let Some(proxy_addr) = take_proxy_header(&mut peek_stream).await
      {
         addr = proxy_addr;
      }
   })
   .await
   .is_err()
   {
      tracing::debug!(peer = %addr, "connection preface timed out");
      return;
   }
   let fingerprint = if matches!(tls, Tls::None) {
      None
   } else {
      fill_client_hello(&mut peek_stream).await;
      parse_client_hello(peek_stream.peeked_data()).map(|fields| {
         TlsFingerprint {
            ja4: fields.compute_ja4(),
         }
      })
   };
   match tls {
      Tls::None => {
         serve_one_connection(Box::new(peek_stream), shared, addr, fingerprint, drop_fd).await;
      },
      Tls::Manual(acceptor) => {
         let tls_stream =
            match tokio::time::timeout(PREFACE_TIMEOUT, acceptor.accept(peek_stream)).await {
               Ok(Ok(stream)) => stream,
               Ok(Err(err)) => {
                  tracing::debug!(error = %err, peer = %addr, "TLS handshake failed");
                  return;
               },
               Err(_) => {
                  tracing::debug!(peer = %addr, "TLS handshake timed out");
                  return;
               },
            };
         serve_one_connection(Box::new(tls_stream), shared, addr, fingerprint, drop_fd).await;
      },
      #[cfg(feature = "acme")]
      Tls::Acme(handles) => {
         use tokio::io::AsyncWriteExt as _;
         let acceptor =
            tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), peek_stream);
         let start = match tokio::time::timeout(PREFACE_TIMEOUT, acceptor).await {
            Ok(Ok(start)) => start,
            Ok(Err(err)) => {
               tracing::debug!(error = %err, peer = %addr, "TLS accept failed");
               return;
            },
            Err(_) => {
               tracing::debug!(peer = %addr, "TLS accept timed out");
               return;
            },
         };
         if bagel_tls::acme::is_tls_alpn_challenge(&start.client_hello()) {
            match tokio::time::timeout(
               PREFACE_TIMEOUT,
               start.into_stream(Arc::clone(&handles.challenge_config)),
            )
            .await
            {
               Ok(Ok(mut tls)) => {
                  let _ = tls.shutdown().await;
               },
               Ok(Err(err)) => {
                  tracing::debug!(error = %err, "ACME challenge handshake failed");
               },
               Err(_) => {
                  tracing::debug!("ACME challenge handshake timed out");
               },
            }
            return;
         }
         match tokio::time::timeout(
            PREFACE_TIMEOUT,
            start.into_stream(Arc::clone(&handles.default_config)),
         )
         .await
         {
            Ok(Ok(tls)) => {
               serve_one_connection(Box::new(tls), shared, addr, fingerprint, drop_fd).await;
            },
            Ok(Err(err)) => {
               tracing::debug!(error = %err, peer = %addr, "TLS handshake failed");
            },
            Err(_) => {
               tracing::debug!(peer = %addr, "TLS handshake timed out");
            },
         }
      },
   }
}

/// Accept connections with TLS and PROXY protocol support.
#[expect(
   clippy::infinite_loop,
   reason = "the listener owns the process lifetime and accepts until shutdown"
)]
pub(super) async fn serve_tcp(listener: TcpListener, tls: Tls, shared: SharedState) {
   let connection_slots = Arc::new(Semaphore::new(MAX_WEB_CONNECTIONS));
   loop {
      let (tcp_stream, remote_addr) = match listener.accept().await {
         Ok(conn) => conn,
         Err(err) => {
            tracing::error!(error = %err, "accept failed");
            continue;
         },
      };
      let Ok(connection_slot) = Arc::clone(&connection_slots).try_acquire_owned() else {
         continue;
      };
      let drop_fd = Some(std::os::fd::AsRawFd::as_raw_fd(&tcp_stream));
      let tls = tls.clone();
      let shared = Arc::clone(&shared);
      tokio::spawn(serve_stream(
         Box::new(tcp_stream),
         Some(remote_addr),
         drop_fd,
         tls,
         shared,
         connection_slot,
      ));
   }
}

/// Accept Unix connections without peer address metadata.
#[expect(
   clippy::infinite_loop,
   reason = "the listener owns the process lifetime and accepts until shutdown"
)]
pub(super) async fn serve_unix(listener: UnixListener, tls: Tls, shared: SharedState) {
   let connection_slots = Arc::new(Semaphore::new(MAX_WEB_CONNECTIONS));
   loop {
      let (unix_stream, _peer) = match listener.accept().await {
         Ok(conn) => conn,
         Err(err) => {
            tracing::error!(error = %err, "unix accept failed");
            continue;
         },
      };
      let Ok(connection_slot) = Arc::clone(&connection_slots).try_acquire_owned() else {
         continue;
      };
      let tls = tls.clone();
      let shared = Arc::clone(&shared);
      tokio::spawn(serve_stream(
         Box::new(unix_stream),
         None,
         None,
         tls,
         shared,
         connection_slot,
      ));
   }
}

/// Serve one connection with peer metadata and a drop handle.
async fn serve_one_connection(
   stream: BoxedStream,
   shared: SharedState,
   addr: SocketAddr,
   fingerprint: Option<TlsFingerprint>,
   drop_fd: Option<std::os::fd::RawFd>,
) {
   let drop_handle = DropHandle::new();
   let conn_handle = drop_handle.clone();

   let service = service_fn(move |req: HyperRequest<Incoming>| {
      let shared = Arc::clone(&shared);
      let fp = fingerprint.clone();
      let handle = drop_handle.clone();
      async move {
         let (parts, body) = req.into_parts();
         let mut req = Request::from_parts(parts, Body::with_idle_timeout(body));
         req.extensions_mut().insert(addr);
         req.extensions_mut().insert(handle);
         if let Some(fp) = fp {
            req.extensions_mut().insert(fp);
         }
         Ok::<_, Infallible>(dispatch(&shared, addr, req).await)
      }
   });

   let mut builder = AutoBuilder::new(TokioExecutor::new());
   builder
      .http1()
      .timer(TokioTimer::new())
      .header_read_timeout(REQUEST_HEADER_TIMEOUT);
   let conn = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
   tokio::pin!(conn);

   tokio::select! {
      result = conn.as_mut() => {
         if let Err(err) = result {
            tracing::debug!(error = %err, "connection error");
         }
      },
      () = conn_handle.dropped() => {
         if let Some(fd) = drop_fd {
            // SAFETY: `conn` owns the socket and is still pinned on this
            // stack frame, so the fd stays open for the whole borrow.
            let socket = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
            let armed = socket2::SockRef::from(&socket)
               .set_linger(Some(std::time::Duration::ZERO));
            if let Err(err) = armed {
               tracing::warn!(error = %err, "SO_LINGER failed, drop degrades to FIN");
            }
         }
      },
   }
}

/// Resolve the key seed from an inline hex value or a file holding one.
/// Exactly one may be set, so a credential and an environment value can
/// never silently disagree.
pub fn key_seed_hex(inline: Option<&str>, file: Option<&Path>) -> error::Result<Option<String>> {
   match (inline, file) {
      (Some(_), Some(_)) => {
         Err(error::Error::Config(
            "exactly one key seed input may be active, not both --key-seed and --key-seed-file"
               .into(),
         ))
      },
      (Some(seed), None) => Ok(Some(seed.to_owned())),
      (None, Some(path)) => {
         let seed = fs::read_to_string(path).map_err(|err| {
            error::Error::Config(format!(
               "cannot read key seed file {}: {err}",
               path.display()
            ))
         })?;
         Ok(Some(seed.trim().to_owned()))
      },
      (None, None) => Ok(None),
   }
}

/// Generate a fresh Ed25519 PKCS8 seed and return it as lowercase hex.
pub fn generate_key_seed_hex() -> error::Result<String> {
   let rng = SystemRandom::new();
   let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
      .map_err(|_| error::Error::Config("failed to generate Ed25519 keypair".into()))?;
   Ok(hex_encode(pkcs8.as_ref()))
}

/// Build the shared state from a loaded config. A seed makes the state
/// persistent so mazes are allowed.
pub async fn build_shared(config: Config, seed_hex: Option<String>) -> error::Result<SharedState> {
   if let Some(ref seed_hex) = seed_hex {
      let seed = hex_decode(seed_hex)
         .ok_or_else(|| error::Error::Config("invalid hex in key seed".into()))?;
      let inner = StateInner::build_with_seed(config, seed).await?;
      Ok(Arc::new(arc_swap::ArcSwap::from_pointee(inner)))
   } else {
      Ok(state::new_shared_state(config).await?)
   }
}

pub async fn serve(shared: SharedState, shutdown: CancellationToken) -> error::Result<()> {
   let (bind_addr, bind_network, socket_mode, tls_config, cache_dir) = {
      let state = shared.load();
      let config = &state.config;
      validate_bind(&config.bind)?;
      (
         config.bind.socket_addr(),
         config.bind.network.clone(),
         config.bind.socket_mode,
         config.bind.tls.clone(),
         config.cache_dir.clone(),
      )
   };

   bmetrics::init_metrics();

   let tls = match &tls_config {
      TlsConfig::Manual {
         cert_path,
         key_path,
      } => {
         let acceptor = bagel_tls::build_tls_acceptor(cert_path, key_path)
            .map_err(|err| error::Error::Tls(format!("failed to build TLS acceptor: {err}")))?;
         tracing::info!("TLS enabled (manual certs)");
         Tls::Manual(acceptor)
      },
      TlsConfig::None => Tls::None,
      #[cfg(feature = "acme")]
      TlsConfig::Acme {
         directory_url,
         domains,
         contact,
      } => {
         let handles = bagel_tls::acme::build_acme_state(
            domains,
            contact,
            directory_url,
            cache_dir.as_deref(),
         );
         Tls::Acme(Arc::new(handles))
      },
      #[cfg(not(feature = "acme"))]
      TlsConfig::Acme { .. } => {
         return Err(Error::Config("ACME TLS requires the acme feature".into()));
      },
   };
   #[cfg(not(feature = "acme"))]
   let _ = cache_dir;

   match bind_network {
      BindNetwork::Unix => {
         let path = Path::new(&bind_addr);
         if path.exists() {
            fs::remove_file(path)?;
         }
         let unix_listener = UnixListener::bind(path)?;
         if let Some(mode) = socket_mode {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(u32::from(mode)))?;
         }
         tracing::info!(path = %bind_addr, "bagel listening (unix socket)");
         tokio::select! {
             () = serve_unix(unix_listener, tls, shared) => {}
             () = shutdown.cancelled() => {}
         }
      },
      BindNetwork::Tcp => {
         let listener = TcpListener::bind(&bind_addr).await?;
         tracing::info!(address = %bind_addr, "bagel listening");
         tokio::select! {
             () = serve_tcp(listener, tls, shared) => {}
             () = shutdown.cancelled() => {}
         }
      },
   }

   tracing::info!("bagel shutting down");
   Ok(())
}
