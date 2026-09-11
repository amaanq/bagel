//! Scripted enhancement of tarpit responses.

use std::{
   iter::repeat_with,
   path::Path,
};

use rand::RngExt;
use rhai::packages::{
   ArithmeticPackage,
   BasicArrayPackage,
   BasicIteratorPackage,
   BasicMapPackage,
   BasicStringPackage,
   LanguageCorePackage,
   LogicPackage,
   MoreStringPackage,
   Package,
};

const DEFAULT_SCRIPT: &str = r#"
fn generate_honeytoken(token) {
    let kinds = ["API_KEY", "AUTH_TOKEN", "SESSION_ID", "SECRET_KEY"];
    `${kinds[random(kinds.len())]}_${token}_${random_hex(8)}`
}

fn maze_paths() {
    [
        "/wp-admin/", "/wp-includes/", "/wp-content/uploads/", "/wp-json/wp/v2/users",
        "/.git/config", "/.svn/entries", "/.aws/credentials", "/.ssh/id_rsa",
        "/actuator/env", "/actuator/heapdump", "/adminer.php", "/phpmyadmin/index.php",
        "/containers/json", "/.kube/config", "/.docker/config.json",
        "/config.json", "/secrets.yaml", "/credentials.json", "/docker-compose.yml",
        "/cgi-bin/status", "/.bash_history", "/.npmrc",
    ]
}

fn maze_links(token, n) {
    let paths = maze_paths();
    let links = [];
    for i in 0..n {
        let p = paths[random(paths.len())];
        links += `<a href='${p}?ref=${token.sub_string(0, 8)}'>internal</a>`;
    }
    links.join(" ")
}

fn enhance_env_secrets(text, path, token) {
    let ht = generate_honeytoken(token);
    let out = text + "\n<!-- .env dump -->";
    out += `\n<pre>DB_PASSWORD=${ht}\nAPI_KEY=${ht}</pre>`;
    out += `\n<!-- ${token} -->`;
    out
}

fn enhance_response(text, kind, path, token) {
    let body = enhance_env_secrets(text, path, token);
    let out = body + `\n<nav>${maze_links(token, 3 + random(4))}</nav>`;
    out + `\n<footer style='display:none'>${maze_links(token, 5)}</footer>`
}
"#;

pub struct Enhancer {
   engine: rhai::Engine,
   ast:    Option<rhai::AST>,
}

impl Enhancer {
   pub fn new(scripts_dir: &Path) -> Self {
      let engine = build_engine();
      let text = load_scripts(scripts_dir).unwrap_or_else(|| DEFAULT_SCRIPT.to_owned());
      let ast = engine.compile(&text).or_else(|err| {
         tracing::warn!("failed to compile deception script, using the built-in one: {err}");
         engine.compile(DEFAULT_SCRIPT)
      });
      let ast = match ast {
         Ok(ast) => Some(ast),
         Err(err) => {
            tracing::warn!("built-in deception script failed to compile: {err}");
            None
         },
      };
      Self { engine, ast }
   }

   pub fn enhance(&self, text: &str, kind: &str, path: &str, token: &str) -> Option<String> {
      let ast = self.ast.as_ref()?;
      let result = self.engine.call_fn::<String>(
         &mut rhai::Scope::new(),
         ast,
         "enhance_response",
         (
            text.to_owned(),
            kind.to_owned(),
            path.to_owned(),
            token.to_owned(),
         ),
      );
      match result {
         Ok(body) => Some(body),
         Err(err) => {
            tracing::warn!("rhai enhance_response failed: {err}");
            None
         },
      }
   }
}

fn build_engine() -> rhai::Engine {
   let mut engine = rhai::Engine::new_raw();

   for package in [
      LanguageCorePackage::new().as_shared_module(),
      ArithmeticPackage::new().as_shared_module(),
      LogicPackage::new().as_shared_module(),
      BasicStringPackage::new().as_shared_module(),
      MoreStringPackage::new().as_shared_module(),
      BasicArrayPackage::new().as_shared_module(),
      BasicMapPackage::new().as_shared_module(),
      BasicIteratorPackage::new().as_shared_module(),
   ] {
      engine.register_global_module(package);
   }

   engine.set_max_operations(200_000);
   engine.set_max_string_size(1 << 20);
   engine.set_max_array_size(4096);
   engine.register_fn("random", |n: i64| -> i64 {
      if n <= 0 {
         0
      } else {
         rand::rng().random_range(0..n)
      }
   });
   engine.register_fn("random_hex", |width: i64| -> String {
      let width = usize::try_from(width).unwrap_or(0);
      let mut rng = rand::rng();
      repeat_with(|| char::from(b"0123456789abcdef"[rng.random_range(0..16usize)]))
         .take(width)
         .collect()
   });
   engine.register_fn("join", |items: rhai::Array, sep: &str| -> String {
      items
         .iter()
         .map(ToString::to_string)
         .collect::<Vec<_>>()
         .join(sep)
   });
   engine
}

fn load_scripts(dir: &Path) -> Option<String> {
   if !dir.is_dir() {
      return None;
   }
   let mut combined = String::new();
   for entry in std::fs::read_dir(dir).ok()?.flatten() {
      let path = entry.path();
      if path.extension().and_then(|e| e.to_str()) == Some("rhai")
         && let Ok(content) = std::fs::read_to_string(&path)
      {
         combined.push_str(&content);
         combined.push('\n');
      }
   }
   (!combined.trim().is_empty()).then_some(combined)
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn default_script_enhances() {
      let enhancer = Enhancer::new(Path::new("/nonexistent"));
      let out = enhancer
         .enhance("hello", "other", "/x", "BOT_123")
         .expect("enhancement");
      assert!(out.starts_with("hello"));
      assert!(out.contains("BOT_123"));
   }

   #[test]
   #[expect(
      clippy::panic,
      reason = "a broken contrib script must name the category it failed on"
   )]
   fn contrib_script_handles_all_categories() {
      let engine = build_engine();
      let ast = engine
         .compile(include_str!("../../../contrib/rhai/better_response.rhai"))
         .expect("contrib script must compile");

      let categories = [
         "cgi_rce",
         "wordpress",
         "env_secrets",
         "vcs_leak",
         "container_infra",
         "admin_panel",
         "php",
         "path_traversal",
         "other",
      ];
      for kind in categories {
         let result: Result<String, _> = engine.call_fn(
            &mut rhai::Scope::new(),
            &ast,
            "enhance_response",
            (
               "hello".to_owned(),
               kind.to_owned(),
               "/test".to_owned(),
               "BOT_X".to_owned(),
            ),
         );
         let out = result.unwrap_or_else(|err| panic!("enhance_response failed for {kind}: {err}"));
         assert!(
            out.len() > "hello".len(),
            "output for {kind} ({}) should be longer than input ({}): {out}",
            out.len(),
            "hello".len()
         );
      }
   }
}
