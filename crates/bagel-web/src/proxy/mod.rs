pub mod backend;

use std::{
   net::{
      IpAddr,
      Ipv4Addr,
      SocketAddr,
   },
   sync::Arc,
   time::Duration,
};

use bagel_config::web::backend::ProxyProtocolVersion;
use bagel_proto::proxy_protocol::{
   build_v1,
   build_v2,
};
use http::{
   HeaderMap,
   HeaderName,
   HeaderValue,
   StatusCode,
   Uri,
   header,
   uri::{
      Authority,
      PathAndQuery,
   },
};
use hyper::{
   Request as HyperRequest,
   body::Incoming,
   client::conn::http1,
};
use hyper_util::{
   client::legacy::{
      Client,
      connect::HttpConnector,
   },
   rt::{
      TokioExecutor,
      TokioIo,
   },
};
use tokio::{
   io::AsyncWriteExt as _,
   net::TcpStream,
};

use crate::{
   body::{
      self,
      Body,
      Request,
      Response,
   },
   hex_encode,
   proxy::backend::Backend,
   tls::TlsFingerprint,
};

const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const UPSTREAM_HEADER_TIMEOUT: Duration = Duration::from_secs(30);

#[must_use]
pub fn build_http_client() -> Client<HttpConnector, Body> {
   let mut connector = HttpConnector::new();
   connector.set_connect_timeout(Some(UPSTREAM_CONNECT_TIMEOUT));
   Client::builder(TokioExecutor::new()).build(connector)
}

fn bad_gateway(backend: &Backend, context: &'static str, err: &dyn std::fmt::Display) -> Response {
   tracing::error!(error = %err, backend = backend.config.name, "{context}");
   body::text(StatusCode::BAD_GATEWAY, "bad gateway")
}

fn upstream_timeout(backend: &Backend, context: &'static str) -> Response {
   bad_gateway(
      backend,
      context,
      &std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream timeout"),
   )
}

async fn connect_backend(backend: &Backend, address: &str) -> Result<TcpStream, Response> {
   match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(address)).await {
      Ok(Ok(stream)) => Ok(stream),
      Ok(Err(err)) => Err(bad_gateway(backend, "failed to connect to backend", &err)),
      Err(_) => Err(upstream_timeout(backend, "backend connect timed out")),
   }
}

fn backend_address(authority: &Authority) -> String {
   let host = authority.host();
   let port = authority.port_u16().unwrap_or(80);
   format!("{host}:{port}")
}

fn finish(resp: hyper::Response<Incoming>) -> Response {
   let (mut parts, body) = resp.into_parts();
   strip_hop_by_hop_headers(&mut parts.headers, false);
   let mut response = Response::from_parts(parts, Body::with_idle_timeout(body));
   response
      .headers_mut()
      .insert("via", HeaderValue::from_static("bagel/0.1"));
   response
}

pub async fn proxy_request(
   client: &Client<HttpConnector, Body>,
   backend: &Arc<Backend>,
   mut req: Request,
) -> Result<Response, Response> {
   let target = &backend.target;

   let scheme = target
      .scheme()
      .expect("backend pool validates an absolute HTTP URL")
      .clone();

   let authority = target
      .authority()
      .expect("backend pool validates an absolute HTTP URL")
      .clone();

   let path_and_query = req
      .uri()
      .path_and_query()
      .cloned()
      .unwrap_or_else(|| PathAndQuery::from_static("/"));

   // Preserve the public host in HTTP/2 `:authority`.
   let inbound_authority = req
      .uri()
      .authority()
      .map(Authority::as_str)
      .and_then(|raw| HeaderValue::from_str(raw).ok());

   let upgrade = requested_upgrade(&req);
   let new_uri = if upgrade.is_some() || backend.config.proxy_protocol_out.is_some() {
      Uri::from(path_and_query)
   } else {
      Uri::builder()
         .scheme(scheme)
         .authority(authority)
         .path_and_query(path_and_query)
         .build()
         .map_err(|err| bad_gateway(backend, "failed to build proxy URI", &err))?
   };

   *req.uri_mut() = new_uri;

   // The upstream client speaks HTTP/1.1, so an HTTP/2 ingress version must
   // not be forwarded or hyper rejects the request as unsupported.
   *req.version_mut() = http::Version::HTTP_11;

   if let Some(host_override) = &backend.host {
      req.headers_mut()
         .insert(header::HOST, host_override.clone());
   } else if !req.headers().contains_key(header::HOST)
      && let Some(authority) = inbound_authority
   {
      req.headers_mut().insert(header::HOST, authority);
   }

   if let Some(ip_header) = &backend.ip_header
      && let Some(addr) = req.extensions().get::<SocketAddr>()
   {
      let ip_str = addr.ip().to_string();
      let value =
         HeaderValue::from_str(&ip_str).expect("an IP address is a valid HTTP header value");
      req.headers_mut().insert(ip_header.clone(), value);
   }

   strip_hop_by_hop_headers(req.headers_mut(), upgrade.is_some());

   let bagel_id: String = {
      let mut buf = [0_u8; 8];
      let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut buf);
      hex_encode(&buf)
   };
   if let Ok(val) = HeaderValue::from_str(&bagel_id) {
      req.headers_mut().insert("x-bagel-id", val);
   }

   req.headers_mut().remove("x-bagel-ja4");
   if let Some(fp) = req.extensions().get::<TlsFingerprint>()
      && !fp.ja4.is_empty()
      && let Ok(val) = HeaderValue::from_str(&fp.ja4)
   {
      req.headers_mut().insert("x-bagel-ja4", val);
   }

   if upgrade.is_some() {
      return proxy_upgrade(req, backend).await;
   }

   if let Some(pp_version) = backend.config.proxy_protocol_out {
      return proxy_with_proxy_protocol(req, backend, pp_version).await;
   }

   let resp = tokio::time::timeout(UPSTREAM_HEADER_TIMEOUT, client.request(req))
      .await
      .map_err(|_| upstream_timeout(backend, "upstream response timed out"))?
      .map_err(|err| bad_gateway(backend, "proxy request failed", &err))?;

   Ok(finish(resp))
}

fn strip_hop_by_hop_headers(headers: &mut HeaderMap, preserve_upgrade: bool) {
   let connection_headers: Vec<HeaderName> = headers
      .get_all(header::CONNECTION)
      .iter()
      .flat_map(|value| value.to_str().unwrap_or_default().split(','))
      .filter_map(|name| name.trim().parse().ok())
      .collect();

   for name in connection_headers {
      if preserve_upgrade && (name == header::CONNECTION || name == header::UPGRADE) {
         continue;
      }
      headers.remove(name);
   }

   for name in [
      HeaderName::from_static("keep-alive"),
      HeaderName::from_static("proxy-connection"),
      header::PROXY_AUTHENTICATE,
      header::PROXY_AUTHORIZATION,
      header::TE,
      header::TRAILER,
      header::TRANSFER_ENCODING,
   ] {
      headers.remove(name);
   }

   if !preserve_upgrade {
      headers.remove(header::CONNECTION);
      headers.remove(header::UPGRADE);
   }
}

/// Both headers must agree, so a bare `Upgrade` cannot reach the splice path
/// without the handshake a backend expects.
fn requested_upgrade(req: &Request) -> Option<HeaderValue> {
   let connection = req.headers().get(header::CONNECTION)?.to_str().ok()?;
   let offers_upgrade = connection
      .split(',')
      .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
   if !offers_upgrade {
      return None;
   }
   req.headers().get(header::UPGRADE).cloned()
}

/// Announce the real client to a backend that expects the PROXY preamble,
/// before any HTTP bytes reach it.
async fn write_proxy_header(
   stream: &mut TcpStream,
   client: Option<SocketAddr>,
   version: ProxyProtocolVersion,
) -> std::io::Result<()> {
   let local_addr = stream
      .local_addr()
      .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
   let client_addr = client.unwrap_or(local_addr);
   let dst_addr = stream
      .peer_addr()
      .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));

   let header_bytes = match version {
      ProxyProtocolVersion::V1 => build_v1(client_addr, dst_addr).into_bytes(),
      ProxyProtocolVersion::V2 => build_v2(client_addr, dst_addr),
   };
   stream.write_all(&header_bytes).await
}

/// Bypasses the pooled client, since an upgrade consumes the socket and the
/// connection can never return to the pool.
async fn proxy_upgrade(mut req: Request, backend: &Arc<Backend>) -> Result<Response, Response> {
   let authority = backend
      .target
      .authority()
      .expect("backend pool validates an absolute HTTP URL");
   let addr_str = backend_address(authority);

   let mut tcp_stream = connect_backend(backend, &addr_str).await?;

   if let Some(pp_version) = backend.config.proxy_protocol_out {
      match tokio::time::timeout(
         UPSTREAM_HEADER_TIMEOUT,
         write_proxy_header(&mut tcp_stream, req.extensions().get().copied(), pp_version),
      )
      .await
      {
         Ok(Ok(())) => {},
         Ok(Err(err)) => {
            return Err(bad_gateway(
               backend,
               "failed to write PROXY protocol header",
               &err,
            ));
         },
         Err(_) => return Err(upstream_timeout(backend, "PROXY protocol write timed out")),
      }
   }

   let (mut sender, conn) = tokio::time::timeout(
      UPSTREAM_HEADER_TIMEOUT,
      http1::handshake(TokioIo::new(tcp_stream)),
   )
   .await
   .map_err(|_| upstream_timeout(backend, "backend HTTP handshake timed out"))?
   .map_err(|err| bad_gateway(backend, "HTTP handshake failed before upgrade", &err))?;

   tokio::spawn(async move {
      if let Err(err) = conn.with_upgrades().await {
         tracing::debug!(error = %err, "upgraded backend connection closed");
      }
   });

   let client_side = hyper::upgrade::on(&mut req);

   let (parts, body) = req.into_parts();
   let mut resp = tokio::time::timeout(
      UPSTREAM_HEADER_TIMEOUT,
      sender.send_request(HyperRequest::from_parts(parts, body)),
   )
   .await
   .map_err(|_| upstream_timeout(backend, "upgrade response timed out"))?
   .map_err(|err| bad_gateway(backend, "upgrade request failed", &err))?;

   if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
      return Ok(finish(resp));
   }

   let backend_side = hyper::upgrade::on(&mut resp);
   let name = backend.config.name.clone();
   tokio::spawn(async move {
      match tokio::try_join!(client_side, backend_side) {
         Ok((client_io, backend_io)) => {
            let mut client_io = TokioIo::new(client_io);
            let mut backend_io = TokioIo::new(backend_io);
            if let Err(err) = tokio::io::copy_bidirectional(&mut client_io, &mut backend_io).await {
               tracing::debug!(error = %err, backend = %name, "upgraded stream ended");
            }
         },
         Err(err) => {
            tracing::debug!(error = %err, backend = %name, "upgrade did not complete");
         },
      }
   });

   let (parts, _) = resp.into_parts();
   Ok(Response::from_parts(parts, Body::empty()))
}

/// Bypasses the pooled hyper client, so every PROXY-protocol request pays a
/// fresh TCP connect.
async fn proxy_with_proxy_protocol(
   req: Request,
   backend: &Arc<Backend>,
   pp_version: ProxyProtocolVersion,
) -> Result<Response, Response> {
   let authority = backend
      .target
      .authority()
      .expect("backend pool validates an absolute HTTP URL");
   let addr_str = backend_address(authority);

   let mut tcp_stream = connect_backend(backend, &addr_str).await?;

   match tokio::time::timeout(
      UPSTREAM_HEADER_TIMEOUT,
      write_proxy_header(&mut tcp_stream, req.extensions().get().copied(), pp_version),
   )
   .await
   {
      Ok(Ok(())) => {},
      Ok(Err(err)) => {
         return Err(bad_gateway(
            backend,
            "failed to write PROXY protocol header",
            &err,
         ));
      },
      Err(_) => return Err(upstream_timeout(backend, "PROXY protocol write timed out")),
   }

   let io = TokioIo::new(tcp_stream);
   let (mut sender, conn) = tokio::time::timeout(UPSTREAM_HEADER_TIMEOUT, http1::handshake(io))
      .await
      .map_err(|_| upstream_timeout(backend, "backend HTTP handshake timed out"))?
      .map_err(|err| {
         bad_gateway(
            backend,
            "HTTP handshake failed over PROXY protocol connection",
            &err,
         )
      })?;

   tokio::spawn(async move {
      if let Err(err) = conn.await {
         tracing::debug!(error = %err, "PROXY protocol backend connection closed");
      }
   });

   let (parts, body) = req.into_parts();
   let req = HyperRequest::from_parts(parts, body);
   let resp = tokio::time::timeout(UPSTREAM_HEADER_TIMEOUT, sender.send_request(req))
      .await
      .map_err(|_| upstream_timeout(backend, "upstream response timed out"))?
      .map_err(|err| {
         bad_gateway(
            backend,
            "proxy request failed over PROXY protocol connection",
            &err,
         )
      })?;

   Ok(finish(resp))
}
