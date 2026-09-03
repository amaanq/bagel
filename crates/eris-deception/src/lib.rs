//! Deceptive response generation.
//!
//! For probes after a leaked file (`.env`, `.git/config`, `config.json`, ...)
//! the body is synthesized to match that file's real content type, so the leak
//! looks genuine. For app-surface probes (WordPress, admin panels, PHP) the
//! body is Markov-generated HTML enhanced by Lua, including a crawler maze.
//! Either way the response carries the headers a real server would send
//! (`Server`, `Date`, and, for static files, `Last-Modified`/`ETag`), so the
//! reply is not betrayed by a suspiciously bare head.

mod chain;
mod date;
mod lua;
mod synth;

use chain::Markov;
use lua::LuaPool;
use rand::RngExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Builds fake HTTP responses to feed to trapped clients.
pub struct Deceiver {
    markov: Markov,
    lua: LuaPool,
    /// The `Server` header value, presented consistently across responses so it
    /// reads like one real server rather than a rotating fake.
    server: String,
    /// Share of probe paths answered with a `404`/`403` instead of a bait, so a
    /// hardened-looking server is not betrayed by answering everything `200`.
    not_found_pct: u8,
    forbidden_pct: u8,
}

impl Deceiver {
    /// Build the generator from a corpora directory, a scripts directory, the
    /// `Server` banner to present, and the share of probes to answer with a
    /// `404`/`403` error page rather than a bait.
    #[must_use]
    pub fn new(
        corpora_dir: &Path,
        scripts_dir: &Path,
        server: &str,
        not_found_pct: u8,
        forbidden_pct: u8,
        warm_vms: usize,
    ) -> Self {
        Self {
            markov: Markov::new(corpora_dir),
            lua: LuaPool::new(scripts_dir, warm_vms),
            server: server.to_string(),
            not_found_pct,
            forbidden_pct,
        }
    }

    /// Produce a full HTTP response (head plus body) as raw bytes, with a
    /// correct `Content-Length` so a well-behaved client waits for every byte.
    ///
    /// `kind` should be one of the category labels from `eris_runtime::category`
    /// so both the content type and any Lua enhancement can tailor the
    /// deception to the probe type.
    #[must_use]
    pub fn response(&self, path: &str, user_agent: &str, kind: &str) -> Vec<u8> {
        let token = token(user_agent);
        let profile = synth::profile(kind, path, self.not_found_pct, self.forbidden_pct);

        let body = if !profile.is_bait() {
            // A hardened server would refuse or not have this path; serve the
            // matching nginx-style error page instead of a leak.
            synth::error_page(profile.status, &self.server)
        } else if profile.html {
            // App surfaces: Markov HTML plus the Lua crawler maze.
            let text = self.markov.generate(kind, 30);
            self.lua
                .enhance(&text, kind, path, &token)
                .unwrap_or_else(|| format!("{text}\n<!-- {token} -->"))
        } else {
            // File leaks: content-type-accurate structured text, no HTML.
            synth::body(&profile, kind, path, &token)
        };

        let mut response = self.head(&profile, body.len()).into_bytes();
        response.extend_from_slice(body.as_bytes());
        response
    }

    /// Assemble the response head the way a real server would frame it.
    fn head(&self, profile: &synth::Profile, body_len: usize) -> String {
        let now = unix_now();
        let mut head = String::with_capacity(256);
        head.push_str(&format!("HTTP/1.1 {}\r\n", profile.status));
        head.push_str(&format!("Server: {}\r\n", self.server));
        head.push_str(&format!("Date: {}\r\n", date::imf_fixdate(now)));
        head.push_str(&format!("Content-Type: {}\r\n", profile.content_type));
        head.push_str(&format!("Content-Length: {body_len}\r\n"));
        if profile.static_file {
            // A static file has a plausible past mtime; nginx derives its ETag
            // from that mtime and the size, so mirror both for consistency.
            let modified = now.saturating_sub(mtime_age());
            head.push_str(&format!(
                "Last-Modified: {}\r\n",
                date::imf_fixdate(modified)
            ));
            head.push_str(&format!("ETag: \"{modified:x}-{body_len:x}\"\r\n"));
            head.push_str("Accept-Ranges: bytes\r\n");
        }
        if let Some(powered_by) = profile.powered_by {
            head.push_str(&format!("X-Powered-By: {powered_by}\r\n"));
        }
        head.push_str("Connection: close\r\n\r\n");
        head
    }
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
            1,
        )
    }

    /// Split a response into its head lines and body, asserting a valid frame
    /// and a `Content-Length` that matches the body byte length.
    fn parse(bytes: &[u8]) -> (String, String) {
        let text = String::from_utf8_lossy(bytes).into_owned();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "bad status line");
        let (head, body) = text.split_once("\r\n\r\n").expect("header terminator");
        let declared: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .and_then(|v| v.trim().parse().ok())
            .expect("content-length");
        assert_eq!(declared, body.len(), "Content-Length must match body");
        (head.to_string(), body.to_string())
    }

    #[test]
    fn every_response_carries_server_and_date() {
        let d = deceiver();
        for (path, kind) in [
            ("/wp-admin", "wordpress"),
            ("/.env", "env_secrets"),
            ("/.git/config", "vcs_leak"),
            ("/config.json", "env_secrets"),
        ] {
            let (head, _) = parse(&d.response(path, "TestBot/1.0", kind));
            assert!(
                head.contains("Server: nginx/1.24.0"),
                "no Server for {path}"
            );
            assert!(head.contains("\r\nDate: "), "no Date for {path}");
        }
    }

    #[test]
    fn env_leak_is_plaintext_not_html() {
        let d = deceiver();
        let (head, body) = parse(&d.response("/.env", "curl/8", "env_secrets"));
        assert!(
            head.contains("Content-Type: text/plain"),
            "env not text/plain"
        );
        assert!(
            head.contains("Last-Modified: "),
            "static file lacks Last-Modified"
        );
        assert!(head.contains("ETag: "), "static file lacks ETag");
        assert!(body.contains("DB_PASSWORD="), "env body not env-shaped");
        assert!(!body.contains('<'), "env body contains HTML");
    }

    #[test]
    fn html_app_pages_declare_html_and_no_static_headers() {
        let d = deceiver();
        let (head, _) = parse(&d.response("/wp-login.php", "TestBot/1.0", "wordpress"));
        assert!(head.contains("Content-Type: text/html"));
        assert!(
            head.contains("X-Powered-By: PHP/"),
            "wordpress lacks X-Powered-By"
        );
        assert!(
            !head.contains("Last-Modified"),
            "dynamic page has Last-Modified"
        );
    }

    #[test]
    fn error_disposition_serves_nginx_error_page() {
        // Force every probe to 404.
        let d = Deceiver::new(
            Path::new("/nonexistent"),
            Path::new("/nonexistent"),
            "nginx/1.24.0",
            100,
            0,
            1,
        );
        let bytes = d.response("/.env", "curl/8", "env_secrets");
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"), "not a 404");
        let (head, body) = text.split_once("\r\n\r\n").expect("header terminator");
        // A real error page is still framed correctly and carries Server/Date...
        assert!(head.contains("Server: nginx/1.24.0"));
        assert!(head.contains("\r\nDate: "));
        assert!(head.contains("Content-Type: text/html"));
        // ...but is dynamic, so no static-file headers, and it leaks no secrets.
        assert!(!head.contains("Last-Modified"), "error page looks static");
        assert!(body.contains("<h1>404 Not Found</h1>"), "not an nginx page");
        assert!(!body.contains("DB_PASSWORD"), "error page leaked a secret");
        let declared: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .and_then(|v| v.trim().parse().ok())
            .expect("content-length");
        assert_eq!(declared, body.len(), "Content-Length must match body");
    }
}
