use bagel_solver::codec::{
   Kind,
   Solution,
   pack_solution,
   unpack_handoff,
};
use data_encoding::BASE64URL_NOPAD;

use super::fixtures::{
   Config,
   *,
};

#[tokio::test]
async fn cookie_challenge_flow_survives_second_boundaries() {
   let main = spawn_echo("main").await;
   let app = Config::wildcard(main).policy(r#"challenges { challenge "cookie" runtime="cookie" duration=3600 } rules { rule "gate" condition="true" action="challenge" { challenges "cookie" } }"#).shared().await;

   let resp = app_send(&app, "/", &[]).await;
   assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
   assert!(
      resp.headers().get(header::SET_COOKIE).is_none(),
      "issuing a challenge must not hand out the passed state"
   );
   let hv = resp
      .headers()
      .get(header::LOCATION)
      .and_then(|hv| hv.to_str().ok())
      .unwrap();
   let location = hv.to_owned();

   tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
   let resp = app_send(&app, &location, &[]).await;
   assert_eq!(
      resp.status(),
      StatusCode::TEMPORARY_REDIRECT,
      "verify endpoint must accept a token issued in an earlier second"
   );
   let cookie = resp
      .headers()
      .get(header::SET_COOKIE)
      .and_then(|hv| hv.to_str().ok())
      .map(|raw| raw.split(';').next().unwrap_or(raw).to_owned())
      .expect("verify must seal the passed state cookie");

   tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
   let resp = app_send(&app, "/", &[("cookie", &cookie)]).await;
   assert_eq!(resp.status(), StatusCode::OK);
   let body = body_text(resp).await;
   assert!(
      body.contains("main /"),
      "passed challenge must reach the origin across seconds, got {body}"
   );
}

#[tokio::test]
async fn pow_interstitial_cookie_grants_no_pass() {
   let main = spawn_echo("main").await;
   let app = Config::wildcard(main).policy(r#"challenges { challenge "pow" runtime="pow-sha256" difficulty=1 duration=3600 } rules { rule "wall" condition="true" action="challenge" { challenges "pow" } }"#).shared().await;

   let resp = app_send(&app, "/", &[]).await;
   assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);
   assert!(
      resp.headers().get(header::SET_COOKIE).is_none(),
      "the interstitial must not seal passed state before the proof"
   );
}

#[tokio::test]
async fn background_pow_solves_on_the_live_page() {
   use crate::challenge::pow::PowChallenge;

   let main = spawn_html_echo("main").await;
   let app = Config::wildcard(main).policy(r#"challenges { challenge "pow" runtime="pow-sha256" difficulty=1 duration=3600 } rules { rule "background" condition="!path.starts_with(\"/wall\")" action="check" { challenges "pow" }; rule "wall" condition="path.starts_with(\"/wall\")" action="challenge" { challenges "pow" } }"#).shared().await;

   let resp = app_send(&app, "/", &[]).await;
   assert_eq!(
      resp.status(),
      StatusCode::OK,
      "the page itself is never blocked"
   );
   let body = body_text(resp).await;
   assert!(
      body.starts_with("<html><body>main /"),
      "origin content must come first: {body}"
   );
   assert!(
      body.contains(r#"data-mode="background""#),
      "solver fragment must be injected: {body}"
   );

   let payload = regex::Regex::new(r#"data-p="([A-Za-z0-9_-]+)""#)
      .unwrap()
      .captures(&body)
      .map(|caps| caps[1].to_owned())
      .unwrap();
   let handoff = unpack_handoff(&BASE64URL_NOPAD.decode(payload.as_bytes()).unwrap()).unwrap();
   assert_eq!(handoff.difficulty, 1);
   let pow = PowChallenge {
      kind:        Kind::Sha256,
      difficulty:  1,
      blocks_log2: 0,
      embed:       crate::template::Presentation::Hidden,
   };
   let nonce = (0_u64..1_000_000)
      .find(|&candidate| pow.verify(&handoff.key, candidate, 1))
      .unwrap();
   let solution = Solution {
      key: handoff.key,
      nonce,
      difficulty: 1,
   };

   let mut req = Request::builder()
      .method(Method::POST)
      .uri("/__bagel/pow/verify")
      .header("host", "example.test")
      .header("content-type", "text/plain")
      .body(Body::from(
         BASE64URL_NOPAD.encode(&pack_solution([7, 7, 7, 7], &solution)),
      ))
      .unwrap();
   let addr = SocketAddr::from(([127, 0, 0, 1], 40_000));
   req.extensions_mut().insert(addr);
   let resp = dispatch(&app, addr, req).await;
   assert_eq!(resp.status(), StatusCode::OK);
   let cookie = resp
      .headers()
      .get(header::SET_COOKIE)
      .and_then(|hv| hv.to_str().ok())
      .map(|raw| raw.split(';').next().unwrap_or(raw).to_owned())
      .unwrap();

   let resp = app_send(&app, "/wall/page", &[("cookie", &cookie)]).await;
   assert_eq!(
      resp.status(),
      StatusCode::OK,
      "a background solve must satisfy the blocking wall"
   );
   assert!(body_text(resp).await.contains("main /wall/page"));
}
