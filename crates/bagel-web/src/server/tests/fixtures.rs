pub(super) use std::{
   convert::Infallible,
   fs,
   net::{
      IpAddr,
      Ipv4Addr,
      SocketAddr,
   },
   path::Path,
   sync::Arc,
};

pub(super) use arc_swap::ArcSwap;
pub(super) use bytes::Bytes;
pub(super) use http::{
   Method,
   StatusCode,
   header,
};
pub(super) use http_body_util::BodyExt as _;
pub(super) use hyper::{
   Request as HyperRequest,
   body::Incoming,
   service::service_fn,
};
pub(super) use hyper_util::{
   rt::{
      TokioExecutor,
      TokioIo,
   },
   server::conn::auto::Builder as AutoBuilder,
};
pub(super) use ring::{
   rand::SystemRandom,
   signature::Ed25519KeyPair,
};
pub(super) use tokio::net::{
   TcpListener,
   UnixListener,
};

pub(super) use super::super::*;
pub(super) use crate::{
   SourceNetwork,
   body::{
      Body,
      Request,
      Response,
   },
   routes::dispatch,
   state::{
      SharedState,
      StateInner,
   },
};

pub(super) const IP_A: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
pub(super) const IP_A2: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200));
pub(super) const IP_B: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));

pub(super) struct Config {
   pub backends: Vec<(String, String)>,
   pub policy:   String,
   pub extra:    String,
}

impl Config {
   pub(super) fn wildcard(main: SocketAddr) -> Self {
      Self {
         backends: vec![("*".to_owned(), format!("http://{main}"))],
         policy:   String::new(),
         extra:    String::new(),
      }
   }

   pub(super) fn host(main: SocketAddr) -> Self {
      Self {
         backends: vec![("example.test".to_owned(), format!("http://{main}"))],
         policy:   String::new(),
         extra:    String::new(),
      }
   }

   pub(super) fn backend(mut self, name: &str, addr: SocketAddr) -> Self {
      self
         .backends
         .push((name.to_owned(), format!("http://{addr}")));
      self
   }

   pub(super) fn policy(mut self, body: &str) -> Self {
      self.policy = body.to_owned();
      self
   }

   pub(super) fn extra(mut self, top: &str) -> Self {
      self.extra = top.to_owned();
      self
   }

   pub(super) fn kdl(&self) -> String {
      let backends = self
         .backends
         .iter()
         .map(|(name, url)| format!("backend \"{name}\" {{ url \"{url}\" }}"))
         .collect::<Vec<_>>()
         .join("\n");
      normalize(&format!(
         "{}\nbackends {{\n{backends}\n}}\npolicy {{\n{}\n}}",
         self.extra, self.policy
      ))
   }

   pub(super) async fn shared(&self) -> SharedState {
      build_shared(&self.kdl()).await
   }

   pub(super) async fn shared_seeded(&self) -> SharedState {
      build_shared_seeded(&self.kdl()).await
   }
}

/// Put every brace on its own line so single-line node lists parse. No
/// test literal carries braces inside a quoted string.
pub(super) fn normalize(kdl: &str) -> String {
   kdl.replace('{', "{\n")
      .replace('}', "\n}\n")
      .replace(';', "\n")
}

pub(super) async fn build_shared(kdl: &str) -> SharedState {
   let config = crate::config::Config::parse(kdl, Path::new("test.kdl")).unwrap();
   Arc::new(ArcSwap::from_pointee(
      StateInner::build(config).await.unwrap(),
   ))
}

pub(super) async fn build_shared_seeded(kdl: &str) -> SharedState {
   let config = crate::config::Config::parse(kdl, Path::new("test.kdl")).unwrap();
   let rng = SystemRandom::new();
   let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
   Arc::new(ArcSwap::from_pointee(
      StateInner::build_with_seed(config, pkcs8.as_ref().to_vec())
         .await
         .unwrap(),
   ))
}

pub(super) async fn policy_err(policy_body: &str) -> String {
   let kdl = normalize(&format!(
      "backends {{\nbackend \"*\" {{ url \"http://127.0.0.1:1\" }}\n}}\npolicy \
       {{\n{policy_body}\n}}"
   ));
   match crate::config::Config::parse(&kdl, Path::new("test.kdl")) {
      Err(err) => err.to_string(),
      Ok(config) => {
         StateInner::build(config)
            .await
            .err()
            .expect("config unexpectedly accepted")
            .to_string()
      },
   }
}

pub(super) async fn top_level_err(snippet: &str) -> String {
   let kdl = format!(
      "{snippet}\nbackends {{\nbackend \"*\" {{ url \"http://127.0.0.1:1\" }}\n}}\npolicy {{ }}"
   );
   let config = crate::config::Config::parse(&kdl, Path::new("test.kdl")).unwrap();
   StateInner::build(config)
      .await
      .err()
      .expect("config unexpectedly accepted")
      .to_string()
}

/// Stand-in origin. `handler` sees each request and returns the response the
/// test wants, so these fixtures need no router.
pub(super) async fn spawn_origin<F, Fut>(handler: F) -> SocketAddr
where
   F: Fn(Request<Incoming>) -> Fut + Clone + Send + 'static,
   Fut: Future<Output = Response> + Send,
{
   let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
   let addr = listener.local_addr().unwrap();
   tokio::spawn(async move {
      loop {
         let Ok((stream, _)) = listener.accept().await else {
            continue;
         };
         let handler = handler.clone();
         tokio::spawn(async move {
            let service = service_fn(move |req| {
               let handler = handler.clone();
               async move { Ok::<_, Infallible>(handler(req).await) }
            });
            let _ = AutoBuilder::new(TokioExecutor::new())
               .serve_connection(TokioIo::new(stream), service)
               .await;
         });
      }
   });
   addr
}

pub(super) async fn spawn_echo(tag: &'static str) -> SocketAddr {
   spawn_origin(move |req: Request<Incoming>| {
      async move {
         let ctx_header = req
            .headers()
            .get("x-ctx")
            .and_then(|hv| hv.to_str().ok())
            .unwrap_or("-")
            .to_owned();
         plain(format!("{tag} {} {ctx_header}", req.uri()))
      }
   })
   .await
}

pub(super) async fn spawn_html_echo(tag: &'static str) -> SocketAddr {
   spawn_origin(move |req: Request<Incoming>| {
      async move {
         let body = format!("<html><body>{tag} {}</body></html>", req.uri());
         crate::body::html(StatusCode::OK, body)
      }
   })
   .await
}

fn plain(text: String) -> Response {
   let mut resp = Response::new(Body::from(text));
   resp.headers_mut().insert(
      header::CONTENT_TYPE,
      header::HeaderValue::from_static("text/plain; charset=utf-8"),
   );
   resp
}

pub(super) async fn send_raw(shared: &SharedState, path: &str) -> Response {
   let req = Request::builder()
      .uri(path)
      .header("host", "example.test")
      .body(Body::empty())
      .unwrap();
   let addr = SocketAddr::from(([127, 0, 0, 1], 40000));
   handle_request(shared, addr, req).await
}

pub(super) async fn send(shared: &SharedState, path: &str) -> (StatusCode, String) {
   let resp = send_raw(shared, path).await;
   let status = resp.status();
   (status, body_text(resp).await)
}

pub(super) async fn send_req(
   shared: &SharedState,
   method: Method,
   path: &str,
   ip: IpAddr,
) -> Response {
   let req = Request::builder()
      .method(method)
      .uri(path)
      .header("host", "example.test")
      .body(Body::empty())
      .unwrap();
   let addr = SocketAddr::new(ip, 40_000);
   handle_request(shared, addr, req).await
}

/// Send through the full route table, so the internal endpoints are reachable.
pub(super) async fn app_send(
   shared: &SharedState,
   path: &str,
   extra_headers: &[(&str, &str)],
) -> Response {
   let mut builder = Request::builder().uri(path).header("host", "example.test");
   for (name, value) in extra_headers {
      builder = builder.header(*name, *value);
   }
   let mut req = builder.body(Body::empty()).unwrap();
   let addr = SocketAddr::from(([127, 0, 0, 1], 40_000));
   req.extensions_mut().insert(addr);
   dispatch(shared, addr, req).await
}

pub(super) async fn body_text(resp: Response) -> String {
   let bytes = resp.into_body().collect().await.unwrap().to_bytes();
   String::from_utf8_lossy(&bytes).into_owned()
}

pub(super) fn extract_links(html: &str) -> Vec<String> {
   regex::Regex::new(r#"href="([^"]+)""#)
      .unwrap()
      .captures_iter(html)
      .map(|caps| caps[1].to_owned())
      .collect()
}

pub(super) fn is_builtin_page(body: &str) -> bool {
   body.starts_with("<!doctype html>")
}

pub(super) fn assert_maze_envelope(resp: &Response) {
   assert_eq!(resp.status(), StatusCode::OK);
   assert_eq!(
      resp.headers().get(header::CONTENT_TYPE).unwrap(),
      "text/html; charset=utf-8"
   );
   assert_eq!(
      resp.headers().get(header::CACHE_CONTROL).unwrap(),
      "no-store"
   );
   assert_eq!(
      resp.headers().get(header::REFERRER_POLICY).unwrap(),
      "no-referrer"
   );
   assert!(resp.headers().get(header::SET_COOKIE).is_none());
}

pub(super) async fn drop_app() -> SharedState {
   let main = spawn_echo("main").await;
   Config::wildcard(main)
      .policy(r#"rules { rule "drop" condition="path == \"/drop\"" action="drop" }"#)
      .shared()
      .await
}

pub(super) async fn spawn_drop_server() -> SocketAddr {
   let shared = drop_app().await;
   let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
   let addr = listener.local_addr().unwrap();
   tokio::spawn(serve_tcp(listener, Tls::None, shared));
   addr
}

pub(super) async fn proxy_protocol_deny_app(trusted: &str) -> SharedState {
   let main = spawn_echo("main").await;
   Config::wildcard(main).extra(&format!("bind {{ proxy-protocol #true }}\ntrusted-proxies \"{trusted}\"")).policy(r#"rules { rule "deny-ip" condition="remote_address == \"203.0.113.7\"" action="deny" http-code=451 }"#).shared().await
}

pub(super) async fn trusted_proxy_app(trusted: &str) -> SharedState {
   let main = spawn_echo("main").await;
   Config::wildcard(main).extra(&format!("client-ip-header \"x-forwarded-for\"\ntrusted-proxies \"{trusted}\"")).policy(r#"rules { rule "deny-ip" condition="remote_address == \"203.0.113.7\"" action="deny" http-code=451 }"#).shared().await
}

pub(super) async fn context_shared(rules: &str) -> SharedState {
   let main = spawn_echo("main").await;
   Config::wildcard(main)
      .policy(&format!("rules {{\n{rules}\n}}"))
      .shared()
      .await
}

pub(super) async fn scoring_shared(policy_body: &str) -> SharedState {
   let main = spawn_echo("main").await;
   Config::wildcard(main).policy(policy_body).shared().await
}

pub(super) async fn smear_shared(smear: &str) -> SharedState {
   let main = spawn_echo("main").await;
   Config::wildcard(main)
      .extra(&format!(
         "deception {{\nnot-found-pct 0\nforbidden-pct 0\n}}\nsmear {{\n{smear}\n}}"
      ))
      .policy(r#"rules { rule "smear" condition="true" action="smear" }"#)
      .shared()
      .await
}

pub(super) async fn maze_shared() -> SharedState {
   let main = spawn_echo("main").await;
   Config::host(main).policy(r#"mazes { maze "default" { token-ttl "1h"; memory-ttl "1h" } } scoring { scorecard "default" mode="enforce" { signal "poison" condition="poison[\"returned\"]" weight=100; threshold 50 action="deny" } } rules { rule "trap" condition="path == \"/trap\"" action="tarpit" maze="default" }"#).shared_seeded().await
}

pub(super) async fn iocaine_shared(endpoint: SocketAddr, renderer_extra: &str) -> SharedState {
   let main = spawn_echo("main").await;
   let policy = format!(
      "renderers {{ renderer \"io\" kind=\"iocaine\" {{ endpoint \"http://{endpoint}/render\"; \
       timeout \"1s\"; {renderer_extra} }} }} mazes {{ maze \"default\" renderer=\"io\" {{ }} }} \
       rules {{ rule \"trap\" condition=\"path == \\\"/trap\\\"\" action=\"tarpit\" \
       maze=\"default\" }}"
   );
   Config::host(main).policy(&policy).shared_seeded().await
}

#[derive(Clone, Copy)]
pub(super) enum Iocaine {
   Ok,
   Slow,
   Status500,
   BadUtf8,
   Huge,
}

pub(super) async fn spawn_iocaine(
   mode: Iocaine,
) -> (SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
   let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
   let sink = Arc::clone(&captured);
   let addr = spawn_origin(move |req: Request<Incoming>| {
      let sink = Arc::clone(&sink);
      async move {
         let bytes = req.into_body().collect().await.unwrap().to_bytes();
         sink
            .lock()
            .unwrap()
            .push(String::from_utf8_lossy(&bytes).into_owned());
         match mode {
            Iocaine::Ok => plain("IOCAINE PAGE".to_owned()),
            Iocaine::Slow => {
               tokio::time::sleep(std::time::Duration::from_secs(3)).await;
               plain("IOCAINE PAGE".to_owned())
            },
            Iocaine::Status500 => crate::body::text(StatusCode::INTERNAL_SERVER_ERROR, "boom"),
            Iocaine::BadUtf8 => Response::new(Body::from(Bytes::from(vec![0xFF, 0xFE, 0xFD]))),
            Iocaine::Huge => plain("x".repeat(300_000)),
         }
      }
   })
   .await;
   (addr, captured)
}

pub(super) async fn read_text<S: tokio::io::AsyncReadExt + Unpin>(stream: &mut S) -> String {
   let mut buf = Vec::new();
   stream.read_to_end(&mut buf).await.unwrap();
   String::from_utf8_lossy(&buf).into_owned()
}

pub(super) fn declared_length(resp: &Response) -> usize {
   resp
      .headers()
      .get(header::CONTENT_LENGTH)
      .and_then(|hv| hv.to_str().ok())
      .and_then(|text| text.parse().ok())
      .expect("smear responses declare a content length")
}

pub(super) fn offense_payload(record: &bagel_runtime::source::SourceRecord) -> serde_json::Value {
   assert_eq!(record.source, "bagel-web");
   serde_json::from_str(&record.payload).unwrap()
}

pub(super) fn listener_sequence(record: &bagel_runtime::source::SourceRecord) -> u64 {
   assert!(matches!(
      &record.checkpoint,
      bagel_runtime::source::Checkpoint::Listener { .. }
   ));
   let bagel_runtime::source::Checkpoint::Listener { sequence } = record.checkpoint else {
      return 0;
   };
   sequence
}
