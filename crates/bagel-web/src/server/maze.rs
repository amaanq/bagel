use std::{
   net::{
      IpAddr,
      Ipv4Addr,
   },
   sync::Arc,
};

use bagel_runtime::OffenseKind;
use http::{
   Method,
   StatusCode,
   header,
};

use super::pipeline::emit_offense;
use crate::{
   SourceNetwork,
   body::{
      self,
      Body,
      Response,
   },
   challenge::token::unix_timestamp,
   maze,
   metrics as bmetrics,
   state::StateInner,
};

pub(super) struct MazeServe<'a> {
   pub runtime:      &'a Arc<maze::MazeRuntime>,
   pub host:         &'a str,
   pub client_ip:    Option<IpAddr>,
   pub source:       Option<SourceNetwork>,
   pub peer_network: SourceNetwork,
   pub method:       &'a Method,
   pub raw_path:     &'a str,
}

/// Serve a recognized maze route. Every outcome, including a wrong method or
/// malformed pieces, renders through the same envelope so no edge of the trap
/// is distinguishable.
pub(super) async fn serve_maze(state: &StateInner, req: &MazeServe<'_>) -> Response {
   let keys = &req.runtime.keys;
   let after_prefix = &req.raw_path[1 + keys.route_prefix.len()..];
   let now = unix_timestamp().cast_unsigned();

   let (class, maze_path) = if *req.method == Method::GET || *req.method == Method::HEAD {
      maze::path::parse_route(after_prefix).map_or(
         (maze::token::TokenClass::Malformed, None),
         |parsed| {
            (
               maze::token::classify(keys, parsed.maze_path, parsed.token, req.source, now),
               Some(parsed.maze_path.to_owned()),
            )
         },
      )
   } else {
      (maze::token::TokenClass::Malformed, None)
   };

   if class.is_authenticated()
      && let Some(network) = req.source
   {
      let id = maze::memory::memory_id(&keys.memory_key, req.host, &req.runtime.name, network);
      state
         .runtime
         .poison
         .set(id, &req.runtime.name, req.runtime.config.memory_ttl);
      emit_offense(
         state,
         req.client_ip,
         req.host,
         Some(&req.runtime.name),
         "valid_return",
         OffenseKind::PoisonReturn,
         None,
      );
   }

   let seed_input = maze_path
      .as_deref()
      .map_or(after_prefix.as_bytes(), str::as_bytes);
   let rendered = render_maze(state, req.runtime, &MazeRender {
      host: req.host,
      source: req.source,
      budget_source: req.source.unwrap_or(req.peer_network),
      authenticated: class.is_authenticated(),
      seed_input,
      payload_path: maze_path.as_deref().unwrap_or(""),
      head_only: *req.method == Method::HEAD,
   })
   .await;

   bmetrics::record_poison_request(req.host, &req.runtime.name, class.as_str());
   bmetrics::record_maze_render(req.host, rendered.renderer, rendered.result);
   tracing::info!(
      target: "bagel::decision",
      maze = req.runtime.name,
      poison_status = class.as_str(),
      renderer = rendered.renderer,
      renderer_result = rendered.result,
      "maze"
   );

   rendered.response
}

struct RenderedMaze {
   response: Response,
   renderer: &'static str,
   result:   &'static str,
}

struct MazeRender<'a> {
   host:          &'a str,
   source:        Option<SourceNetwork>,
   budget_source: SourceNetwork,
   authenticated: bool,
   seed_input:    &'a [u8],
   payload_path:  &'a str,
   head_only:     bool,
}

/// Render one maze page, through the maze's configured external renderer
/// with built-in fallback, or directly through the built-in engine.
async fn render_maze(
   state: &StateInner,
   runtime: &maze::MazeRuntime,
   req: &MazeRender<'_>,
) -> RenderedMaze {
   let keys = &runtime.keys;
   let seed_key = if req.authenticated {
      &keys.render_key
   } else {
      &keys.decoy_key
   };
   let seed = maze::render::page_seed(seed_key, req.seed_input);
   let budget = maze::render::RenderBudget {
      min_links: runtime.config.min_links,
      max_links: runtime.config.max_links,
      min_bytes: runtime.config.min_bytes,
      max_bytes: runtime.config.max_bytes,
   };
   let expires = unix_timestamp().cast_unsigned() + runtime.config.token_ttl.as_secs();
   let prefix = &keys.route_prefix;

   let mint = |path: &str| {
      let token = if req.authenticated {
         maze::token::mint(keys, path, req.source, expires)
      } else {
         maze::token::mint_decoy(keys, path, req.source, expires)
      };
      format!("/{prefix}/{token}/{path}")
   };

   if let Some(renderer) = state.runtime.renderers.get(&runtime.config.renderer) {
      let links: Vec<String> = maze::render::plan_links(seed, &budget)
         .iter()
         .map(|path| mint(path))
         .collect();
      let key = maze::renderer::BudgetKey {
         host:   req.host.to_owned(),
         maze:   runtime.name.clone(),
         source: Some(req.budget_source),
      };
      let payload = maze::renderer::RenderPayload {
         seed:  maze::keys::BASE32_LOWER.encode(&seed),
         host:  req.host,
         path:  req.payload_path,
         links: &links,
      };
      match renderer.render(&key, &payload, !req.authenticated).await {
         maze::renderer::RenderAttempt::Body(html) => {
            return RenderedMaze {
               response: maze_envelope(html, req.head_only),
               renderer: renderer.kind(),
               result:   "ok",
            };
         },
         maze::renderer::RenderAttempt::Fallback(label) => {
            let html = maze::render::render_page(seed, &budget, mint);
            return RenderedMaze {
               response: maze_envelope(html, req.head_only),
               renderer: renderer.kind(),
               result:   label,
            };
         },
      }
   }

   let html = maze::render::render_page(seed, &budget, mint);
   RenderedMaze {
      response: maze_envelope(html, req.head_only),
      renderer: "builtin",
      result:   "ok",
   }
}

fn maze_envelope(html: String, head_only: bool) -> Response {
   let length = html.len();
   let body = if head_only {
      Body::empty()
   } else {
      Body::from(html)
   };
   Response::builder()
      .status(StatusCode::OK)
      .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
      .header(header::CACHE_CONTROL, "no-store")
      .header(header::REFERRER_POLICY, "no-referrer")
      .header(header::CONTENT_LENGTH, length)
      .body(body)
      .expect("static maze response headers are valid")
}

/// A hidden anchor into the maze, bound to the visitor's source network so a
/// follow-up from that network reads as a poison return. Real browsers never
/// navigate a `hidden` `nofollow` link, crawlers that parse anchors do.
pub fn lure_fragment(
   state: &StateInner,
   maze_name: &str,
   host: &str,
   client_ip: Option<IpAddr>,
   page_path: &str,
) -> Option<String> {
   let runtime = state.maze_by_name(host, maze_name)?;
   let keys = &runtime.keys;
   let seed = maze::render::page_seed(&keys.render_key, page_path.as_bytes());
   let budget = maze::render::RenderBudget {
      min_links: 1,
      max_links: 1,
      min_bytes: 0,
      max_bytes: 0,
   };
   let path = maze::render::plan_links(seed, &budget).into_iter().next()?;
   let source = client_ip.map(SourceNetwork::from_ip);
   let expires = unix_timestamp().cast_unsigned() + runtime.config.token_ttl.as_secs();
   let token = maze::token::mint(keys, &path, source, expires);
   Some(format!(
      "<div hidden><a href=\"/{}/{token}/{path}\" rel=\"nofollow\" \
       tabindex=\"-1\">{path}</a></div>",
      keys.route_prefix
   ))
}

pub async fn tarpit_response(
   state: &StateInner,
   maze_name: &str,
   host: &str,
   client_ip: Option<IpAddr>,
) -> Response {
   let Some(runtime) = state.maze_by_name(host, maze_name) else {
      tracing::error!(maze = maze_name, host, "tarpit maze unavailable for host");
      return body::text(StatusCode::SERVICE_UNAVAILABLE, "service unavailable\n");
   };
   let source = client_ip.map(SourceNetwork::from_ip);
   let budget_source =
      source.unwrap_or_else(|| SourceNetwork::from_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
   let rendered = render_maze(state, &runtime, &MazeRender {
      host,
      source,
      budget_source,
      authenticated: source.is_some(),
      seed_input: b"index",
      payload_path: "",
      head_only: false,
   })
   .await;
   bmetrics::record_maze_render(host, rendered.renderer, rendered.result);
   rendered.response
}
