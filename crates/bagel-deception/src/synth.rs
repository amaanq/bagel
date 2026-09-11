//! Content-type-accurate fake bodies for file-leak probes.

use std::iter::repeat_with;

use rand::RngExt;

/// The `200 OK` status line, i.e. a successful bait response.
pub const OK: &str = "200 OK";

/// How a trapped request should be dressed up as a response.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Profile {
   /// The status line, e.g. `200 OK`, `404 Not Found`, `403 Forbidden`.
   pub status:       &'static str,
   /// The `Content-Type` header value.
   pub content_type: &'static str,
   /// Whether the body is an HTML document.
   pub html:         bool,
   /// Whether to include static-file headers.
   pub static_file:  bool,
   /// `X-Powered-By` value, for the app kinds where a real stack would set it.
   pub powered_by:   Option<&'static str>,
}

impl Profile {
   /// Whether this profile serves a `200 OK` bait rather than an error page.
   #[must_use]
   pub fn is_bait(&self) -> bool {
      self.status == OK
   }
}

/// Choose the response kind and deterministic status for a `(kind, path)` pair.
#[must_use]
pub fn profile(kind: &str, path: &str, not_found_pct: u8, forbidden_pct: u8) -> Profile {
   match disposition(path, not_found_pct, forbidden_pct) {
      OK => content_profile(kind, path),
      status => {
         Profile {
            status,
            content_type: "text/html",
            html: false,
            static_file: false,
            powered_by: None,
         }
      },
   }
}

/// The bait profile for a `(kind, path)` once it is known to be answered `200`.
fn content_profile(kind: &str, path: &str) -> Profile {
   let lower = path.to_ascii_lowercase();
   let ext = |suffixes: &[&str]| suffixes.iter().any(|s| lower.ends_with(s));

   // Extension-driven, structured file leaks.
   if ext(&[".json"]) || lower.ends_with("/containers/json") {
      return Profile {
         status:       OK,
         content_type: "application/json",
         html:         false,
         static_file:  true,
         powered_by:   None,
      };
   }
   if ext(&[".yml", ".yaml"]) || lower.contains("docker-compose") {
      return Profile {
         status:       OK,
         content_type: "text/yaml",
         html:         false,
         static_file:  true,
         powered_by:   None,
      };
   }
   if ext(&[".xml"]) || lower.contains("web.config") {
      return Profile {
         status:       OK,
         content_type: "text/xml; charset=utf-8",
         html:         false,
         static_file:  true,
         powered_by:   None,
      };
   }

   // Category-driven leaks that are plain text.
   match kind {
      "env_secrets" | "vcs_leak" | "path_traversal" => {
         Profile {
            status:       OK,
            content_type: "text/plain; charset=utf-8",
            html:         false,
            static_file:  true,
            powered_by:   None,
         }
      },
      "container_infra" => {
         Profile {
            status:       OK,
            content_type: "application/json",
            html:         false,
            static_file:  true,
            powered_by:   None,
         }
      },
      // WordPress and bare PHP are served by a PHP stack that sets
      // X-Powered-By, so keeping it here is correct rather than a tell.
      "wordpress" | "php" => {
         Profile {
            status:       OK,
            content_type: "text/html; charset=UTF-8",
            html:         true,
            static_file:  false,
            powered_by:   Some("PHP/8.2.12"),
         }
      },
      // Admin panels, CGI/RCE error pages, and the generic bucket are HTML.
      _ => {
         Profile {
            status:       OK,
            content_type: "text/html; charset=UTF-8",
            html:         true,
            static_file:  false,
            powered_by:   None,
         }
      },
   }
}

/// Map a path to a status line given the error proportions. Forbidden is
/// checked before not-found so the two bands never overlap.
fn disposition(path: &str, not_found_pct: u8, forbidden_pct: u8) -> &'static str {
   let bucket = path_bucket(path);
   let forbidden = forbidden_pct.min(100);
   let not_found = not_found_pct.min(100 - forbidden);
   if bucket < forbidden {
      "403 Forbidden"
   } else if bucket < forbidden + not_found {
      "404 Not Found"
   } else {
      OK
   }
}

/// A stable `[0, 100)` bucket for a path, using the fixed-key `DefaultHasher`
/// (not `RandomState`) so the mapping is identical across restarts and hosts.
fn path_bucket(path: &str) -> u8 {
   use std::hash::{
      Hash,
      Hasher,
   };
   let mut hasher = std::collections::hash_map::DefaultHasher::new();
   path.hash(&mut hasher);
   (hasher.finish() % 100) as u8
}

/// The body of an nginx-style error page for `status`, matching what a real
/// nginx emits byte-for-byte down to the server footer.
#[must_use]
pub fn error_page(status: &str, server: &str) -> String {
   format!(
      "<html>\r\n<head><title>{status}</title></head>\r\n<body>\r\n<center><h1>{status}</h1></\
       center>\r\n<hr><center>{server}</center>\r\n</body>\r\n</html>\r\n"
   )
}

const BASE62: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const BASE36: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const HEX: &[u8] = b"0123456789abcdef";

/// A random string of `n` characters drawn from `alphabet`.
fn rand_str(alphabet: &[u8], n: usize) -> String {
   let mut rng = rand::rng();
   repeat_with(|| alphabet[rng.random_range(0..alphabet.len())] as char)
      .take(n)
      .collect()
}

/// Derive a six-character base36 tag from the interaction token.
fn trace_tag(token: &str) -> String {
   let tag: String = token
      .chars()
      .filter(char::is_ascii_alphanumeric)
      .map(|c| c.to_ascii_uppercase())
      .filter(|c| BASE36.contains(&(*c as u8)))
      .take(6)
      .collect();
   // Pad if the token was too short to yield six usable characters.
   format!("{tag:0>6}")
}

/// Generate a traceable secret value that still looks random.
#[must_use]
pub fn honeytoken(token: &str) -> String {
   format!(
      "{}{}{}",
      rand_str(BASE62, 12),
      trace_tag(token),
      rand_str(BASE62, 12)
   )
}

/// Build a structured, content-type-appropriate fake body for a non-HTML leak.
#[must_use]
pub fn body(profile: &Profile, kind: &str, path: &str, token: &str) -> String {
   match profile.content_type {
      "application/json" => json_leak(path, token),
      "text/yaml" => yaml_leak(token),
      "text/xml; charset=utf-8" => xml_leak(token),
      _ => text_leak(kind, path, token),
   }
}

/// Plain-text leaks: `.env`, `.git/config`, `/etc/passwd`, generic dotfiles.
fn text_leak(kind: &str, path: &str, token: &str) -> String {
   let lower = path.to_ascii_lowercase();
   if kind == "vcs_leak" || lower.contains("/.git") {
      return git_config();
   }
   if kind == "path_traversal" || lower.contains("passwd") {
      return passwd();
   }
   // Default: an `.env` dump with correctly-shaped fake credentials.
   let app_key = rand_str(BASE62, 43);
   let db = honeytoken(token);
   let redis = honeytoken(token);
   let aws_id = format!("AKIA{}", rand_str(BASE36, 16));
   let aws_secret = rand_str(BASE62, 40);
   let jwt = rand_str(HEX, 64);
   let stripe = format!("sk_live_{}", honeytoken(token));
   let mail = honeytoken(token);
   format!(
      "APP_ENV=production\nAPP_DEBUG=false\nAPP_KEY=base64:{app_key}=\nDB_CONNECTION=mysql\\
       nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=app_production\nDB_USERNAME=app\\
       nDB_PASSWORD={db}\nREDIS_HOST=127.0.0.1\nREDIS_PASSWORD={redis}\\
       nAWS_ACCESS_KEY_ID={aws_id}\nAWS_SECRET_ACCESS_KEY={aws_secret}\\
       nAWS_DEFAULT_REGION=us-east-1\nJWT_SECRET={jwt}\nSTRIPE_SECRET={stripe}\nMAIL_HOST=smtp.\
       mailgun.org\nMAIL_USERNAME=postmaster@app.example\nMAIL_PASSWORD={mail}\n"
   )
}

fn git_config() -> String {
   let pat = rand_str(BASE62, 20);
   format!(
        "[core]\n\
         \trepositoryformatversion = 0\n\
         \tfilemode = true\n\
         \tbare = false\n\
         \tlogallrefupdates = true\n\
         [remote \"origin\"]\n\
         \turl = https://deploy:glpat-{pat}@gitlab.example.com/ops/app.git\n\
         \tfetch = +refs/heads/*:refs/remotes/origin/*\n\
         [branch \"main\"]\n\
         \tremote = origin\n\
         \tmerge = refs/heads/main\n"
    )
}

fn passwd() -> String {
   "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:\
    bin:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:112:\
    118:MySQL Server,,,:/nonexistent:/bin/false\ndeploy:x:1000:1000:Deploy \
    User:/home/deploy:/bin/bash\npostgres:x:114:120:PostgreSQL \
    administrator,,,:/var/lib/postgresql:/bin/bash\n"
      .to_owned()
}

fn json_leak(path: &str, token: &str) -> String {
   if path.to_ascii_lowercase().contains("containers/json") {
      let id = rand_str(HEX, 64);
      return format!(
         "[{{\"Id\":\"{id}\",\"Names\":[\"/app_web_1\"],\"Image\":\"app:latest\",\"Command\":\"\
          docker-entrypoint.sh\",\"State\":\"running\",\"Status\":\"Up 6 \
          days\",\"Ports\":[{{\"PrivatePort\":8080,\"Type\":\"tcp\"}}]}}]"
      );
   }
   let secret = honeytoken(token);
   let api = honeytoken(token);
   let jwt = rand_str(HEX, 64);
   format!(
      "{{\n  \"env\": \"production\",\n  \"database\": {{\n    \"host\": \"127.0.0.1\",\n    \
       \"user\": \"app\",\n    \"password\": \"{secret}\"\n  }},\n  \"api_key\": \"{api}\",\n  \
       \"jwt_secret\": \"{jwt}\",\n  \"debug\": false\n}}\n"
   )
}

fn yaml_leak(token: &str) -> String {
   let pw = honeytoken(token);
   let key = rand_str(BASE62, 48);
   format!(
      "version: \"3.8\"\nservices:\n  web:\n    image: app:latest\n    environment:\n      - \
       DATABASE_URL=postgres://app:{pw}@db:5432/app\n      - SECRET_KEY_BASE={key}\n  db:\n    \
       image: postgres:15\n    environment:\n      - POSTGRES_PASSWORD={pw}\n"
   )
}

fn xml_leak(token: &str) -> String {
   let pw = honeytoken(token);
   let key = rand_str(BASE62, 48);
   format!(
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n  <connectionStrings>\n    \
       <add name=\"Default\" connectionString=\"Server=127.0.0.1;Database=app;User \
       Id=sa;Password={pw};\" />\n  </connectionStrings>\n  <appSettings>\n    <add \
       key=\"MachineKey\" value=\"{key}\" />\n  </appSettings>\n</configuration>\n"
   )
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn file_leaks_are_typed_and_never_html() {
      for (kind, path, ct, needle) in [
         (
            "env_secrets",
            "/.env",
            "text/plain; charset=utf-8",
            "DB_PASSWORD=",
         ),
         (
            "vcs_leak",
            "/.git/config",
            "text/plain; charset=utf-8",
            "[remote \"origin\"]",
         ),
         (
            "path_traversal",
            "/../../etc/passwd",
            "text/plain; charset=utf-8",
            "root:x:0:0:",
         ),
         (
            "env_secrets",
            "/config.json",
            "application/json",
            "\"api_key\"",
         ),
         (
            "container_infra",
            "/docker-compose.yml",
            "text/yaml",
            "services:",
         ),
      ] {
         // Force bait (no error dispositions) to exercise the content path.
         let p = profile(kind, path, 0, 0);
         assert!(p.is_bait());
         assert_eq!(p.content_type, ct, "wrong content-type for {path}");
         assert!(!p.html, "{path} must not be HTML");
         let b = body(&p, kind, path, "TOKEN123");
         assert!(b.contains(needle), "body for {path} missing {needle}: {b}");
         assert!(!b.contains("<a href"), "{path} leaked HTML maze links");
      }
   }

   #[test]
   fn disposition_is_stable_and_proportioned() {
      // Same path, same answer, every time.
      let a = profile("env_secrets", "/.env", 30, 10).status;
      let b = profile("env_secrets", "/.env", 30, 10).status;
      assert_eq!(a, b, "disposition must be deterministic per path");

      // Zero percentages mean everything is bait.
      for path in ["/.env", "/wp-admin", "/.git/config", "/x/y/z"] {
         assert!(profile("other", path, 0, 0).is_bait());
      }

      // 100% not-found turns every probe into a 404 error page.
      let p = profile("env_secrets", "/.env", 100, 0);
      assert_eq!(p.status, "404 Not Found");
      assert!(!p.is_bait());

      // Roughly the configured share of a large path set errors out.
      let errored = (0..1000)
         .filter(|i| !profile("other", &format!("/p/{i}"), 40, 10).is_bait())
         .count();
      assert!(
         (400..=600).contains(&errored),
         "unexpected error share: {errored}"
      );
   }
}
