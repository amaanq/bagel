//! Deceptive response generation for file and application probes.

mod chain;
mod date;
mod enhance;
mod synth;

use std::{
   path::Path,
   time::{
      SystemTime,
      UNIX_EPOCH,
   },
};

use chain::Markov;
use enhance::Enhancer;
use rand::RngExt;

/// A deceptive response in parts, for callers that frame HTTP themselves.
#[derive(Clone, PartialEq, Eq)]
pub struct Page {
   /// The status line without the version, e.g. `200 OK`.
   pub status:  &'static str,
   /// Response headers excluding framing headers.
   pub headers: Vec<(&'static str, String)>,
   pub body:    String,
}

impl Page {
   /// The numeric status, falling back to 200 if the line is malformed.
   #[must_use]
   pub fn status_code(&self) -> u16 {
      self
         .status
         .split(' ')
         .next()
         .and_then(|code| code.parse().ok())
         .unwrap_or(200)
   }
}

/// Builds fake HTTP responses to feed to trapped clients.
pub struct Deceiver {
   markov:        Markov,
   enhancer:      Enhancer,
   /// The `Server` header value.
   server:        String,
   /// Share of probe paths answered with `404` or `403`.
   not_found_pct: u8,
   forbidden_pct: u8,
}

impl Deceiver {
   /// Build a generator from corpus and script directories, a server banner,
   /// and an error-page share.
   #[must_use]
   pub fn new(
      corpora_dir: &Path,
      scripts_dir: &Path,
      server: &str,
      not_found_pct: u8,
      forbidden_pct: u8,
   ) -> Self {
      Self {
         markov: Markov::new(corpora_dir),
         enhancer: Enhancer::new(scripts_dir),
         server: server.to_owned(),
         not_found_pct,
         forbidden_pct,
      }
   }

   /// `kind` should be one of the category labels from
   /// `bagel_runtime::category` so both the content type and any script
   /// enhancement can tailor the deception to the probe type.
   #[must_use]
   pub fn page(&self, path: &str, user_agent: &str, kind: &str) -> Page {
      let token = token(user_agent);
      let profile = synth::profile(kind, path, self.not_found_pct, self.forbidden_pct);

      let body = if !profile.is_bait() {
         // Serve an error page for non-bait profiles.
         synth::error_page(profile.status, &self.server)
      } else if profile.html {
         let text = self.markov.generate(kind, 30);
         self
            .enhancer
            .enhance(&text, kind, path, &token)
            .unwrap_or_else(|| format!("{text}\n<!-- {token} -->"))
      } else {
         // File leaks: content-type-accurate structured text, no HTML.
         synth::body(&profile, kind, path, &token)
      };

      Page {
         status: profile.status,
         headers: self.headers(&profile, body.len()),
         body,
      }
   }

   /// A maze page with Markov prose and the provided links.
   #[must_use]
   pub fn maze_page(&self, seed: &str, path: &str, links: &[String]) -> String {
      let words: Vec<String> = self
         .markov
         .generate("other", 40 + links.len() * 24)
         .split_whitespace()
         .map(str::to_owned)
         .collect();
      let title = words.iter().take(4).cloned().collect::<Vec<_>>().join(" ");
      let mut body = String::with_capacity(4096);
      body.push_str("<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>");
      body.push_str(&escape(&title));
      body.push_str("</title></head><body>\n<h1>");
      body.push_str(&escape(&title));
      body.push_str("</h1>\n");
      let per_link = (words.len() / links.len().max(1)).max(6);
      let mut chunks = words.chunks(per_link);
      for (index, link) in links.iter().enumerate() {
         let prose = chunks
            .next()
            .map(|chunk| chunk.join(" "))
            .unwrap_or_default();
         let anchor = words
            .get((index * 7 + seed.len()) % words.len().max(1))
            .map_or("more", String::as_str);
         body.push_str("<p>");
         body.push_str(&escape(&prose));
         body.push_str(" <a href=\"");
         body.push_str(&escape(link));
         body.push_str("\">");
         body.push_str(&escape(anchor));
         body.push_str("</a></p>\n");
      }
      for chunk in chunks {
         body.push_str("<p>");
         body.push_str(&escape(&chunk.join(" ")));
         body.push_str("</p>\n");
      }
      body.push_str("<!-- ");
      body.push_str(&escape(path));
      body.push_str(" -->\n</body></html>\n");
      body
   }

   /// Assemble the response headers the way a real server would emit them.
   fn headers(&self, profile: &synth::Profile, body_len: usize) -> Vec<(&'static str, String)> {
      let now = unix_now();
      let mut headers = vec![
         ("Server", self.server.clone()),
         ("Date", date::imf_fixdate(now)),
         ("Content-Type", profile.content_type.to_owned()),
      ];
      if profile.static_file {
         // A static file has a plausible past mtime, and nginx derives its
         // ETag from that mtime and the size, so mirror both for consistency.
         let modified = now.saturating_sub(mtime_age());
         headers.push(("Last-Modified", date::imf_fixdate(modified)));
         headers.push(("ETag", format!("\"{modified:x}-{body_len:x}\"")));
         headers.push(("Accept-Ranges", "bytes".to_owned()));
      }
      if let Some(powered_by) = profile.powered_by {
         headers.push(("X-Powered-By", powered_by.to_owned()));
      }
      headers
   }
}

fn escape(text: &str) -> String {
   let mut out = String::with_capacity(text.len());
   for ch in text.chars() {
      match ch {
         '&' => out.push_str("&amp;"),
         '<' => out.push_str("&lt;"),
         '>' => out.push_str("&gt;"),
         '"' => out.push_str("&quot;"),
         _ => out.push(ch),
      }
   }
   out
}

/// A plausible file age (1 hour to ~30 days) for `Last-Modified`.
fn mtime_age() -> u64 {
   rand::rng().random_range(3_600..=2_592_000)
}

fn unix_now() -> u64 {
   SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map(|d| d.as_secs())
      .unwrap_or_default()
}

/// A per-interaction tracking token derived from the user agent and time.
fn token(user_agent: &str) -> String {
   let clean: String = user_agent
      .chars()
      .filter(char::is_ascii_alphanumeric)
      .take(24)
      .collect();
   format!("BOT_{clean}_{}", unix_now())
}

#[cfg(test)]
mod tests {
   use super::*;

   /// A deceiver that always baits (no error dispositions), for the
   /// content-shape assertions below.
   fn deceiver() -> Deceiver {
      Deceiver::new(
         Path::new("/nonexistent"),
         Path::new("/nonexistent"),
         "nginx/1.24.0",
         0,
         0,
      )
   }

   #[test]
   fn page_carries_server_and_date() {
      let d = deceiver();
      let page = d.page("/.env", "curl/8", "env_secrets");
      assert_eq!(page.status_code(), 200);
      assert!(page.headers.iter().any(|(name, _)| *name == "Server"));
      assert!(page.headers.iter().any(|(name, _)| *name == "Date"));
      assert!(page.headers.iter().all(|(name, _)| {
         !name.eq_ignore_ascii_case("content-length") && !name.eq_ignore_ascii_case("connection")
      }));
      assert!(page.body.contains("DB_PASSWORD="));
      assert_eq!(
         Page {
            status:  "404 Not Found",
            headers: Vec::new(),
            body:    String::new(),
         }
         .status_code(),
         404
      );
   }

   #[test]
   fn page_headers_follow_the_profile() {
      let d = deceiver();
      let header = |page: &Page, name: &str| {
         page
            .headers
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.clone())
      };

      let env = d.page("/.env", "curl/8", "env_secrets");
      assert_eq!(
         header(&env, "Content-Type").as_deref(),
         Some("text/plain; charset=utf-8")
      );
      assert!(header(&env, "Last-Modified").is_some());
      assert!(header(&env, "ETag").is_some());
      assert!(header(&env, "Accept-Ranges").is_some());
      assert!(env.body.contains("DB_PASSWORD="));

      let wp = d.page("/wp-login.php", "TestBot/1.0", "wordpress");
      assert_eq!(
         header(&wp, "Content-Type").as_deref(),
         Some("text/html; charset=UTF-8")
      );
      assert!(header(&wp, "X-Powered-By").is_some_and(|v| v.starts_with("PHP/")));
      assert!(header(&wp, "ETag").is_none());
      assert!(header(&wp, "Last-Modified").is_none());

      let refused = Deceiver::new(
         Path::new("/nonexistent"),
         Path::new("/nonexistent"),
         "nginx/1.24.0",
         100,
         0,
      );
      let error = refused.page("/.env", "curl/8", "env_secrets");
      assert_eq!(error.status, "404 Not Found");
      assert!(error.body.contains("<h1>404 Not Found</h1>"));
      assert!(error.body.contains("nginx/1.24.0"));
   }

   #[test]
   fn maze_page_embeds_every_link_verbatim_and_no_others() {
      let d = deceiver();
      let links: Vec<String> = (0..7)
         .map(|i| format!("/abcdefghijklmnopqrst/tok{i}/p{i}"))
         .collect();
      let html = d.maze_page("seedseed", "/x/y", &links);
      assert!(html.starts_with("<!DOCTYPE html>"));
      assert_eq!(html.matches("href=\"").count(), links.len());
      for link in &links {
         assert!(html.contains(&format!("href=\"{link}\"")), "{link} missing");
      }
      assert!(
         !html.contains("BOT_"),
         "tracking token leaked into maze page"
      );
      let empty = d.maze_page("s", "/", &[]);
      assert_eq!(empty.matches("href=\"").count(), 0);
      assert!(empty.contains("<p>"));
   }
}
