use ring::{
   rand::SystemRandom,
   signature::Ed25519KeyPair,
};
use tokio::{
   io::{
      AsyncReadExt as _,
      AsyncWriteExt as _,
   },
   net::TcpStream,
};

use super::fixtures::{
   Config,
   *,
};

#[tokio::test]
async fn proxy_rewrites_capture_groups() {
   let main = spawn_echo("main").await;
   let alt = spawn_echo("alt").await;
   let shared = Config::wildcard(main).backend("alt", alt).policy(r#"rules {
rule "rewrite" condition="path.starts_with(\"/old/\")" action="proxy" backend="alt" match="^/old/(.*)$" rewrite="/new/$1"; rule "keep" condition="path.starts_with(\"/keep\")" action="proxy" backend="alt" match="^/nomatch/(.*)$" rewrite="/x/$1"; rule "plain" condition="path.starts_with(\"/alt\")" action="proxy" backend="alt" }"#).shared().await;
   let (status, body) = send(&shared, "/old/thing?q=1").await;
   assert_eq!(status, StatusCode::OK);
   assert_eq!(body, "alt /new/thing?q=1 -");
}

#[tokio::test]
async fn drop_resets_tcp_connection_without_response() {
   let addr = spawn_drop_server().await;
   let mut stream = TcpStream::connect(addr).await.unwrap();
   stream
      .write_all(b"GET /drop HTTP/1.1\r\nHost: example.test\r\n\r\n")
      .await
      .unwrap();
   let mut buf = [0_u8; 1024];
   let err = stream
      .read(&mut buf)
      .await
      .expect_err("expected a reset, got response bytes");
   assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
}

#[tokio::test]
async fn h2_drop_terminates_every_stream_on_the_connection() {
   let addr = spawn_drop_server().await;
   let stream = TcpStream::connect(addr).await.unwrap();
   let io = TokioIo::new(stream);
   let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
      .await
      .unwrap();
   let conn_task = tokio::spawn(conn);

   let ok_req = || {
      HyperRequest::builder()
         .uri("http://example.test/ok")
         .body(Body::empty())
         .unwrap()
   };
   let resp = sender.send_request(ok_req()).await.unwrap();
   assert_eq!(resp.status(), StatusCode::OK);

   let drop_req = HyperRequest::builder()
      .uri("http://example.test/drop")
      .body(Body::empty())
      .unwrap();
   sender
      .send_request(drop_req)
      .await
      .expect_err("dropped stream should error");
   sender
      .send_request(ok_req())
      .await
      .expect_err("connection should be dead for later streams");
   conn_task
      .await
      .unwrap()
      .expect_err("connection future should end in error");
}

#[tokio::test]
async fn unix_drop_closes_without_response() {
   let shared = drop_app().await;
   let path = std::env::temp_dir().join(format!("bagel-drop-test-{}.sock", std::process::id()));
   let _ = fs::remove_file(&path);
   let listener = UnixListener::bind(&path).unwrap();
   tokio::spawn(serve_unix(listener, Tls::None, shared));

   let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
   stream
      .write_all(b"GET /drop HTTP/1.1\r\nHost: example.test\r\n\r\n")
      .await
      .unwrap();
   let mut buf = Vec::new();
   stream.read_to_end(&mut buf).await.unwrap();
   assert!(buf.is_empty(), "expected no response bytes, got {buf:?}");
   let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn unix_proxy_protocol_supplies_the_client_ip() {
   let shared = proxy_protocol_deny_app("127.0.0.0/8").await;
   let path =
      std::env::temp_dir().join(format!("bagel-proxy-unix-test-{}.sock", std::process::id()));
   let _ = fs::remove_file(&path);
   let listener = UnixListener::bind(&path).unwrap();
   tokio::spawn(serve_unix(listener, Tls::None, shared));

   let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
   stream.write_all(b"PROXY TCP4 203.0.113.7 10.0.0.1 56324 443\r\nGET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n").await.unwrap();
   let text = read_text(&mut stream).await;
   assert!(text.contains("451"), "{text}");

   let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
   stream
      .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
      .await
      .unwrap();
   let text = read_text(&mut stream).await;
   assert!(text.starts_with("HTTP/1.1 200"), "{text}");
   let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn proxy_protocol_header_supplies_the_client_ip() {
   let shared = proxy_protocol_deny_app("127.0.0.0/8").await;
   let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
   let addr = listener.local_addr().unwrap();
   tokio::spawn(serve_tcp(listener, Tls::None, shared));

   let mut stream = TcpStream::connect(addr).await.unwrap();
   stream.write_all(b"PROXY TCP4 203.0.113.7 10.0.0.1 56324 443\r\nGET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n").await.unwrap();
   let text = read_text(&mut stream).await;
   assert!(text.contains("451"), "{text}");

   let mut stream = TcpStream::connect(addr).await.unwrap();
   stream.write_all(b"PROXY TCP4 203.0.").await.unwrap();
   tokio::time::sleep(std::time::Duration::from_millis(50)).await;
   stream.write_all(b"113.7 10.0.0.1 56324 443\r\nGET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n").await.unwrap();
   let text = read_text(&mut stream).await;
   assert!(
      text.contains("451"),
      "split header must still be honoured: {text}"
   );

   let untrusted = TcpListener::bind("127.0.0.1:0").await.unwrap();
   let untrusted_addr = untrusted.local_addr().unwrap();
   let shared = proxy_protocol_deny_app("10.0.0.0/8").await;
   tokio::spawn(serve_tcp(untrusted, Tls::None, shared));
   let mut stream = TcpStream::connect(untrusted_addr).await.unwrap();
   stream.write_all(b"PROXY TCP4 203.0.113.7 10.0.0.1 56324 443\r\nGET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n").await.unwrap();
   let text = read_text(&mut stream).await;
   assert!(
      !text.contains("451"),
      "unlisted peers must not supply an address: {text}"
   );

   let mut stream = TcpStream::connect(addr).await.unwrap();
   stream
      .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
      .await
      .unwrap();
   let text = read_text(&mut stream).await;
   assert!(!text.contains("451"), "{text}");
   assert!(text.starts_with("HTTP/1.1 200"), "{text}");
}

#[tokio::test]
async fn trusted_proxies_gate_the_client_ip_header() {
   let app = trusted_proxy_app("10.0.0.0/8").await;
   let resp = app_send(&app, "/", &[("x-forwarded-for", "203.0.113.7")]).await;
   assert_eq!(resp.status(), StatusCode::OK);

   let app = trusted_proxy_app("127.0.0.0/8").await;
   let resp = app_send(&app, "/", &[("x-forwarded-for", "203.0.113.7")]).await;
   assert_eq!(resp.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
}

#[tokio::test]
async fn smear_stops_at_the_deadline() {
   let shared = smear_shared(
      "min-delay-ms 200\n    max-delay-ms 200\n    chunk-min 1\n    chunk-max 1\n    max-secs 1",
   )
   .await;
   let resp = send_raw(&shared, "/.env").await;
   assert_eq!(resp.status(), StatusCode::OK);
   assert_eq!(resp.headers().get("server").unwrap(), "nginx/1.24.0");
   assert!(resp.headers().contains_key("date"));
   let declared = declared_length(&resp);
   let started = std::time::Instant::now();
   let body = resp.into_body().collect().await.unwrap().to_bytes();
   let elapsed = started.elapsed();
   assert!(
      elapsed >= std::time::Duration::from_millis(900),
      "{elapsed:?}"
   );
   assert!(elapsed <= std::time::Duration::from_secs(3), "{elapsed:?}");
   assert!(body.len() < declared, "{} of {declared} bytes", body.len());
}

#[tokio::test]
async fn smear_capacity_exhaustion_degrades_to_drop() {
   let shared = smear_shared(
      "max-concurrent 1\n    min-delay-ms 1000\n    max-delay-ms 1000\n    chunk-min 1\n    \
       chunk-max 1",
   )
   .await;
   let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
   let addr = listener.local_addr().unwrap();
   tokio::spawn(serve_tcp(listener, Tls::None, shared));

   let mut first = TcpStream::connect(addr).await.unwrap();
   first
      .write_all(b"GET /.env HTTP/1.1\r\nHost: example.test\r\n\r\n")
      .await
      .unwrap();
   let mut head = Vec::new();
   let mut buf = [0_u8; 1024];
   while !head.windows(4).any(|window| window == b"\r\n\r\n") {
      let read = first.read(&mut buf).await.unwrap();
      assert_ne!(
         read, 0,
         "first connection closed before its headers arrived"
      );
      head.extend_from_slice(&buf[..read]);
   }
   assert!(
      head.starts_with(b"HTTP/1.1 200"),
      "{}",
      String::from_utf8_lossy(&head)
   );

   let mut second = TcpStream::connect(addr).await.unwrap();
   second
      .write_all(b"GET /.env HTTP/1.1\r\nHost: example.test\r\n\r\n")
      .await
      .unwrap();
   let mut rest = Vec::new();
   match second.read_to_end(&mut rest).await {
      Ok(_) => {
         assert!(
            rest.is_empty(),
            "expected no response bytes, got {}",
            String::from_utf8_lossy(&rest)
         );
      },
      Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset),
   }
   drop(first);
}

#[tokio::test]
async fn smear_and_poison_return_emit_offenses() {
   let main = spawn_echo("main").await;
   let shared = Config::host(main).extra("deception {\nnot-found-pct 0\nforbidden-pct 0\n}\nsmear {\nmin-delay-ms 0\nmax-delay-ms 0\nchunk-min 1\nchunk-max 4\n}").policy(r#"mazes { maze "default" { token-ttl "1h"; memory-ttl "1h" } } rules { rule "smear-probe" condition="path == \"/.env\"" action="smear"; rule "trap" condition="path == \"/trap\"" action="tarpit" maze="default" }"#).shared_seeded().await;

   let resp = send_req(&shared, Method::GET, "/trap", IP_A).await;
   let link = extract_links(&body_text(resp).await).remove(0);

   let (tx, mut rx) = tokio::sync::mpsc::channel(8);
   let source = Arc::new(bagel_runtime::WebOffenseSource::new("bagel-web", tx, 0));
   shared
      .load()
      .hooks
      .offenses
      .store(Some(Arc::clone(&source)));

   let resp = send_raw(&shared, "/.env").await;
   assert_eq!(resp.status(), StatusCode::OK);
   let record = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
      .await
      .unwrap()
      .unwrap();
   let payload = offense_payload(&record);
   assert_eq!(payload["kind"], "smear", "{payload}");
   assert_eq!(payload["address"], "127.0.0.1", "{payload}");
   assert_eq!(listener_sequence(&record), 1);

   let resp = send_req(&shared, Method::GET, &link, IP_A2).await;
   assert_maze_envelope(&resp);
   let record = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
      .await
      .unwrap()
      .unwrap();
   let payload = offense_payload(&record);
   assert_eq!(payload["kind"], "poison_return", "{payload}");
   assert_eq!(listener_sequence(&record), 2);
}

#[tokio::test]
async fn bagel_traps_reach_conditions_once_a_classifier_is_attached() {
   let main = spawn_echo("main").await;
   let shared = Config::wildcard(main).extra("deception { not-found-pct 0; forbidden-pct 0 }\nsmear { min-delay-ms 0; max-delay-ms 0; chunk-min 1; chunk-max 64 }").policy(r#"rules { rule "probe" condition="trap[\"any\"] && trap[\"category\"] == \"env_secrets\"" action="smear"; rule "ua" condition="trap[\"user_agent\"]" action="deny" http-code=451 }"#).shared().await;
   let (status, _) = send(&shared, "/.env").await;
   assert_eq!(
      status,
      StatusCode::OK,
      "no classifier attached means no trap"
   );

   let classifier =
      bagel_runtime::Classifier::new(&["(?i)\\.env".to_owned()], &["(?i)evilbot".to_owned()], &[])
         .unwrap();
   shared
      .load()
      .hooks
      .classifier
      .store(Some(Arc::new(classifier)));

   let resp = send_raw(&shared, "/.env").await;
   assert_eq!(resp.status(), StatusCode::OK);
   assert_eq!(resp.headers().get("server").unwrap(), "nginx/1.24.0");

   let resp = send_raw(&shared, "/%2eenv").await;
   assert_eq!(
      resp.headers().get("server").map(|v| v.to_str().unwrap()),
      Some("nginx/1.24.0"),
      "percent-decoded path must still trap"
   );

   let (status, _) = send(&shared, "/").await;
   assert_eq!(status, StatusCode::OK);

   let resp = app_send(&shared, "/", &[("user-agent", "EvilBot/1.0")]).await;
   assert_eq!(resp.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
}

#[tokio::test]
async fn equivalent_host_spellings_reach_the_same_backend() {
   let main = spawn_echo("main").await;
   let mut cfg = Config::wildcard(main);
   cfg.backends[0].0 = "Example.TEST".to_owned();
   let shared = cfg.shared().await;

   for host in ["example.test", "EXAMPLE.test:8080", "example.test."] {
      let req = Request::builder()
         .uri("/spell")
         .header("host", host)
         .body(Body::empty())
         .unwrap();
      let addr = SocketAddr::new(IP_A, 40_000);
      let resp = handle_request(&shared, addr, req).await;
      assert_eq!(resp.status(), StatusCode::OK, "{host}");
   }
}

#[tokio::test]
async fn authority_disagreement_is_rejected_with_400() {
   let main = spawn_echo("main").await;
   let shared = Config::wildcard(main).shared().await;

   let req = Request::builder()
      .uri("http://other.test/x")
      .header("host", "example.test")
      .body(Body::empty())
      .unwrap();
   let addr = SocketAddr::new(IP_A, 40_000);
   let resp = handle_request(&shared, addr, req).await;
   assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

   let req = Request::builder()
      .uri("http://EXAMPLE.test:8080/x")
      .header("host", "example.test")
      .body(Body::empty())
      .unwrap();
   let resp = handle_request(&shared, addr, req).await;
   assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn ip_hosts_get_host_only_cookies() {
   use crate::challenge::RequestChallengeState;

   let mut state = RequestChallengeState {
      token:      None,
      modified:   false,
      injections: Vec::new(),
   };
   state.issue_challenge("cookie", &[1_u8; 32], std::time::Duration::from_mins(1));

   let rng = SystemRandom::new();
   let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
   let signing_key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

   let dns_cookie = state
      .seal_cookie("example.test", false, &signing_key, pkcs8.as_ref(), None)
      .unwrap();
   assert!(dns_cookie.contains("Domain=example.test;"), "{dns_cookie}");

   let ip_cookie = state
      .seal_cookie("192.0.2.7", true, &signing_key, pkcs8.as_ref(), None)
      .unwrap();
   assert!(!ip_cookie.contains("Domain="), "{ip_cookie}");
}
