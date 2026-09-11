use super::fixtures::{
   Config,
   *,
};

#[tokio::test]
async fn markov_renderer_embeds_only_minted_links_in_process() {
   let main = spawn_echo("main").await;
   let shared = Config::host(main).policy(r#"renderers { renderer "mk" kind="markov" { } } mazes { maze "default" renderer="mk" { } } rules { rule "trap" condition="path == \"/trap\"" action="tarpit" maze="default" }"#).shared_seeded().await;
   let resp = send_req(&shared, Method::GET, "/trap", IP_A).await;
   assert_maze_envelope(&resp);
   let body = body_text(resp).await;
   assert!(
      !is_builtin_page(&body),
      "fell back to the built-in renderer"
   );
   assert!(body.starts_with("<!DOCTYPE html>"), "{body}");

   let state = shared.load();
   let runtime = state.maze_by_name("example.test", "default").unwrap();
   let prefix = runtime.keys.route_prefix.clone();
   let (min_links, max_links) = (runtime.config.min_links, runtime.config.max_links);
   drop(state);
   let links = extract_links(&body);
   assert!(
      (min_links as usize..=max_links as usize).contains(&links.len()),
      "{} links outside {min_links}..={max_links}",
      links.len()
   );
   for link in &links {
      assert!(link.starts_with(&format!("/{prefix}/")), "{link}");
      assert_eq!(link.to_lowercase(), *link, "{link}");
   }
   assert!(
      !body.contains("/wp-admin"),
      "trap links leaked into the maze"
   );
}

#[tokio::test]
async fn iocaine_renders_low_rate_traffic_without_learning_classification() {
   let (endpoint, captured) = spawn_iocaine(Iocaine::Ok).await;
   let shared = iocaine_shared(endpoint, "").await;

   let resp = send_req(&shared, Method::GET, "/trap", IP_A).await;
   assert_maze_envelope(&resp);
   assert_eq!(body_text(resp).await, "IOCAINE PAGE");

   let state = shared.load();
   let runtime = state.maze_by_name("example.test", "default").unwrap();
   let prefix = runtime.keys.route_prefix.clone();
   drop(state);
   let resp = send_req(&shared, Method::GET, &format!("/{prefix}/x/y"), IP_A).await;
   assert_maze_envelope(&resp);
   assert_eq!(body_text(resp).await, "IOCAINE PAGE");

   let payloads = captured.lock().unwrap().clone();
   assert_eq!(payloads.len(), 2);
   for payload in &payloads {
      let json: serde_json::Value = serde_json::from_str(payload).unwrap();
      let object = json.as_object().unwrap();
      assert_eq!(object["mode"], "maze");
      assert_eq!(
         object.keys().count(),
         5,
         "unexpected payload keys: {payload}"
      );
      assert_eq!(object["host"], "example.test");
      assert_ne!(object["links"].as_array().unwrap().len(), 0);
      assert!(!payload.contains("203.0.113"), "{payload}");
   }
}

#[tokio::test]
async fn decoy_budget_exhaustion_cools_down_authenticated_traffic_too() {
   let (endpoint, _) = spawn_iocaine(Iocaine::Ok).await;
   let shared = iocaine_shared(endpoint, "decoy-rate 1\n            decoy-burst 1").await;

   let state = shared.load();
   let runtime = state.maze_by_name("example.test", "default").unwrap();
   let prefix = runtime.keys.route_prefix.clone();
   drop(state);
   let decoy_path = format!("/{prefix}/x/y");

   let resp = send_req(&shared, Method::GET, &decoy_path, IP_A).await;
   assert_eq!(body_text(resp).await, "IOCAINE PAGE");

   let resp = send_req(&shared, Method::GET, &decoy_path, IP_A).await;
   assert!(is_builtin_page(&body_text(resp).await));

   let resp = send_req(&shared, Method::GET, "/trap", IP_A).await;
   assert!(is_builtin_page(&body_text(resp).await));
}

#[tokio::test]
async fn concurrency_exhaustion_falls_back_without_cooldown() {
   let (endpoint, _) = spawn_iocaine(Iocaine::Ok).await;
   let shared = iocaine_shared(endpoint, "max-concurrency 1").await;

   let state = shared.load();
   let renderer = Arc::clone(&state.runtime.renderers["io"]);
   drop(state);

   let permit = Arc::clone(&renderer.semaphore).try_acquire_owned().unwrap();
   let resp = send_req(&shared, Method::GET, "/trap", IP_A).await;
   assert!(is_builtin_page(&body_text(resp).await));
   drop(permit);

   let resp = send_req(&shared, Method::GET, "/trap", IP_A).await;
   assert_eq!(body_text(resp).await, "IOCAINE PAGE");
}

#[tokio::test]
async fn renderer_failures_fall_back_and_start_cooldown() {
   for mode in [
      Iocaine::Slow,
      Iocaine::Status500,
      Iocaine::BadUtf8,
      Iocaine::Huge,
   ] {
      let (endpoint, captured) = spawn_iocaine(mode).await;
      let shared = iocaine_shared(endpoint, "").await;

      let resp = send_req(&shared, Method::GET, "/trap", IP_A).await;
      assert_maze_envelope(&resp);
      assert!(is_builtin_page(&body_text(resp).await));

      let resp = send_req(&shared, Method::GET, "/trap", IP_A).await;
      assert!(is_builtin_page(&body_text(resp).await));
      assert_eq!(
         captured.lock().unwrap().len(),
         1,
         "cooldown should stop the second external call"
      );
   }
}

#[tokio::test]
async fn tarpit_referencing_unknown_maze_fails_config() {
   let err = policy_err(r#"rules { rule "r" action="tarpit" maze="missing" }"#).await;
   assert!(err.contains("unknown maze 'missing'"), "{err}");

   let err = policy_err(r#"scoring { scorecard "default" { signal "always" condition="true" weight=100; threshold 50 action="tarpit" maze="missing" } }"#).await;
   assert!(err.contains("unknown maze 'missing'"), "{err}");
}

#[tokio::test]
async fn tarpit_mints_lowercase_maze_urls() {
   let shared = maze_shared().await;
   let resp = send_req(&shared, Method::GET, "/trap", IP_A).await;
   assert_maze_envelope(&resp);
   let links = extract_links(&body_text(resp).await);
   assert!((8..=16).contains(&links.len()), "{}", links.len());

   for link in &links {
      assert_eq!(link, &link.to_lowercase());
      assert!(!link.contains(['%', '=', '_', '?']), "{link}");
      let mut parts = link.strip_prefix('/').unwrap().splitn(3, '/');
      let prefix = parts.next().unwrap();
      let token = parts.next().unwrap();
      let path = parts.next().unwrap();
      assert_eq!(prefix.len(), 20);
      assert_eq!(token.len(), 93);
      assert!(
         crate::maze::path::normalize_maze_path(path).is_some(),
         "{path}"
      );
   }
}

#[tokio::test]
async fn valid_return_sets_poison_and_scoring_sees_it() {
   let shared = maze_shared().await;
   let resp = send_req(&shared, Method::GET, "/trap", IP_A).await;
   let link = extract_links(&body_text(resp).await).remove(0);

   let resp = send_req(&shared, Method::GET, &link, IP_A2).await;
   assert_maze_envelope(&resp);

   let resp = send_req(&shared, Method::GET, "/", IP_A).await;
   assert_eq!(resp.status(), StatusCode::FORBIDDEN);

   let resp = send_req(&shared, Method::GET, "/", IP_B).await;
   assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn transfer_renders_decoy_and_sets_no_poison() {
   let shared = maze_shared().await;
   let resp = send_req(&shared, Method::GET, "/trap", IP_A).await;
   let link = extract_links(&body_text(resp).await).remove(0);

   let resp = send_req(&shared, Method::GET, &link, IP_B).await;
   assert_maze_envelope(&resp);
   let decoy_links = extract_links(&body_text(resp).await);
   assert_ne!(decoy_links.len(), 0);

   let state = shared.load();
   let runtime = state.maze_by_name("example.test", "default").unwrap();
   for link in &decoy_links {
      let mut parts = link.strip_prefix('/').unwrap().splitn(3, '/');
      let _prefix = parts.next().unwrap();
      let token = parts.next().unwrap();
      let path = parts.next().unwrap();
      let class = crate::maze::token::classify(
         &runtime.keys,
         path,
         token,
         Some(SourceNetwork::from_ip(IP_B)),
         0,
      );
      assert_eq!(class, crate::maze::token::TokenClass::Invalid, "{link}");
   }

   let resp = send_req(&shared, Method::GET, "/", IP_B).await;
   assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn flipped_token_bytes_never_yield_fresh_valid_tokens() {
   let shared = maze_shared().await;
   let resp = send_req(&shared, Method::GET, "/trap", IP_A).await;
   let link = extract_links(&body_text(resp).await).remove(0);

   let mut parts = link.strip_prefix('/').unwrap().splitn(3, '/');
   let prefix = parts.next().unwrap();
   let token = parts.next().unwrap();
   let path = parts.next().unwrap();
   let mut token = token.to_owned();
   let replacement = if token.as_bytes()[40] == b'a' {
      "b"
   } else {
      "a"
   };
   token.replace_range(40..41, replacement);
   let flipped = format!("/{prefix}/{token}/{path}");
   let resp = send_req(&shared, Method::GET, &flipped, IP_A).await;
   assert_maze_envelope(&resp);
   let decoy_links = extract_links(&body_text(resp).await);

   let state = shared.load();
   let runtime = state.maze_by_name("example.test", "default").unwrap();
   for link in &decoy_links {
      let mut parts = link.strip_prefix('/').unwrap().splitn(3, '/');
      let _ = parts.next();
      let token = parts.next().unwrap();
      let path = parts.next().unwrap();
      let class = crate::maze::token::classify(
         &runtime.keys,
         path,
         token,
         Some(SourceNetwork::from_ip(IP_A)),
         0,
      );
      assert_ne!(class, crate::maze::token::TokenClass::ValidReturn, "{link}");
   }

   let resp = send_req(&shared, Method::GET, "/", IP_A).await;
   assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn partial_urls_and_wrong_methods_render_decoys() {
   let shared = maze_shared().await;
   let state = shared.load();
   let runtime = state.maze_by_name("example.test", "default").unwrap();
   let prefix = runtime.keys.route_prefix.clone();
   drop(state);

   for path in [
      format!("/{prefix}"),
      format!("/{prefix}/"),
      format!("/{prefix}/notatoken"),
      format!("/{prefix}/notatoken/some-path"),
   ] {
      let resp = send_req(&shared, Method::GET, &path, IP_A).await;
      assert_maze_envelope(&resp);
   }

   let resp = send_req(
      &shared,
      Method::POST,
      &format!("/{prefix}/notatoken/some-path"),
      IP_A,
   )
   .await;
   assert_maze_envelope(&resp);

   let resp = send_req(&shared, Method::GET, "/", IP_A).await;
   assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn maze_flood_does_not_inflate_normal_rates() {
   let main = spawn_echo("main").await;
   let shared = Config::host(main).policy(r#"mazes { maze "default" { } } scoring { scorecard "default" mode="enforce" { signal "burst" condition="rate[\"available\"] && rate[\"10s\"] > 2" weight=100; threshold 50 action="deny" } }"#).shared_seeded().await;
   let state = shared.load();
   let runtime = state.maze_by_name("example.test", "default").unwrap();
   let prefix = runtime.keys.route_prefix.clone();
   drop(state);

   for _ in 0..50 {
      let resp = send_req(&shared, Method::GET, &format!("/{prefix}/x/y"), IP_A).await;
      assert_eq!(resp.status(), StatusCode::OK);
   }

   for _ in 0..2 {
      let resp = send_req(&shared, Method::GET, "/", IP_A).await;
      assert_eq!(resp.status(), StatusCode::OK);
   }
   let resp = send_req(&shared, Method::GET, "/", IP_A).await;
   assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn poison_memory_expires_with_its_ttl() {
   let main = spawn_echo("main").await;
   let shared = Config::host(main).policy(r#"mazes { maze "default" { memory-ttl "1s" } } scoring { scorecard "default" mode="enforce" { signal "poison" condition="poison[\"returned\"]" weight=100; threshold 50 action="deny" } } rules { rule "trap" condition="path == \"/trap\"" action="tarpit" maze="default" }"#).shared_seeded().await;

   let resp = send_req(&shared, Method::GET, "/trap", IP_A).await;
   let link = extract_links(&body_text(resp).await).remove(0);
   let _ = send_req(&shared, Method::GET, &link, IP_A).await;

   let resp = send_req(&shared, Method::GET, "/", IP_A).await;
   assert_eq!(resp.status(), StatusCode::FORBIDDEN);

   tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
   let resp = send_req(&shared, Method::GET, "/", IP_A).await;
   assert_eq!(resp.status(), StatusCode::OK);
}
