//! Human-facing categories for trapped requests.

use std::sync::LazyLock;

use regex::RegexSet;

/// A coarse bucket a trapped request falls into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
   /// Directory-traversal and local-file-inclusion probes.
   PathTraversal,
   /// CGI / interpreter remote-code-execution attempts.
   CgiRce,
   /// Exposed version-control metadata (`.git`, `.svn`, ...).
   VcsLeak,
   /// Container and infrastructure exposure (Docker API, kube, terraform).
   ContainerInfra,
   /// WordPress-specific endpoints.
   Wordpress,
   /// Environment, credential, and secret files.
   EnvSecrets,
   /// Admin panels and framework actuators.
   AdminPanel,
   /// Bare PHP probes (dropped webshells, random `*.php`).
   Php,
   /// Trapped, but matching no known signature.
   Other,
   /// SSH connections accepted by an SSH tarpit endpoint.
   Ssh,
   /// Abusive user agents: AI-training scrapers and spoofed/impossible UAs
   /// trapped on the user-agent signature rather than the path.
   Scraper,
}

impl Category {
   /// Categories in reporting order, most specific first.
   pub const ALL: [Self; 11] = [
      Self::PathTraversal,
      Self::CgiRce,
      Self::VcsLeak,
      Self::ContainerInfra,
      Self::Wordpress,
      Self::EnvSecrets,
      Self::AdminPanel,
      Self::Php,
      Self::Other,
      Self::Ssh,
      Self::Scraper,
   ];

   /// Stable machine/report label.
   #[must_use]
   pub const fn label(self) -> &'static str {
      match self {
         Self::PathTraversal => "path_traversal",
         Self::CgiRce => "cgi_rce",
         Self::VcsLeak => "vcs_leak",
         Self::ContainerInfra => "container_infra",
         Self::Wordpress => "wordpress",
         Self::EnvSecrets => "env_secrets",
         Self::AdminPanel => "admin_panel",
         Self::Php => "php",
         Self::Other => "other",
         Self::Ssh => "ssh",
         Self::Scraper => "scraper",
      }
   }

   /// Position of this category in [`Category::ALL`], used to index the
   /// per-IP and global count arrays.
   #[must_use]
   pub const fn index(self) -> usize {
      self as usize
   }

   /// The category for a given array index, or [`Category::Other`] if out of
   /// range (e.g. a persisted file from a newer build).
   #[must_use]
   pub fn from_index(idx: usize) -> Self {
      Self::ALL.get(idx).copied().unwrap_or(Self::Other)
   }
}

/// Number of distinct categories, the width of every per-category count array.
pub const COUNT: usize = Category::ALL.len();

/// Regexes follow [`Category::ALL`] order, with specific categories first.
static PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
   RegexSet::new([
        r"(?i)\.\./|%2e%2e|/etc/passwd|/proc/self|/windows/win\.ini",
        r"(?i)/cgi-bin/|vendor/phpunit|eval-stdin|/thinkphp|/struts|ognl|nashorn|jndi:|\$\{|\$\(",
        r"(?i)/\.git|/\.svn|/\.hg|/\.bzr",
        r"(?i):2375|/containers/json|docker-compose|/\.kube|/\.docker|terraform|\.tfstate|\.tfvars",
        r"(?i)/wp-admin|/wp-login|/wp-config|/wp-content|/wp-includes|/wp-json|xmlrpc\.php",
        r"(?i)\.env|/config\.|/settings\.|/secrets\.|/credentials\.|/\.aws|appsettings|application[.-]|/\.ssh|id_rsa|id_ed25519|\.pem|/\.npmrc|/\.yarnrc|/\.htpasswd",
        r"(?i)phpmyadmin|/adminer|/solr/|/actuator|/manager/html|/phpinfo",
        r"(?i)\.php",
    ])
    .expect("built-in category patterns must compile")
});

/// Bucket a request path into a [`Category`].
#[must_use]
pub fn categorize(path: &str) -> Category {
   PATTERNS
      .matches(path)
      .iter()
      .next()
      .map_or(Category::Other, |idx| Category::ALL[idx])
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn buckets_common_probes() {
      assert_eq!(categorize("/.env.production"), Category::EnvSecrets);
      assert_eq!(categorize("/.git/config"), Category::VcsLeak);
      assert_eq!(categorize("/wp-login.php"), Category::Wordpress);
      assert_eq!(categorize("/wp-json/wp/v2/users"), Category::Wordpress);
      assert_eq!(categorize("/1.php"), Category::Php);
      assert_eq!(categorize("/containers/json"), Category::ContainerInfra);
      assert_eq!(categorize("/../../etc/passwd"), Category::PathTraversal);
      assert_eq!(categorize("/cgi-bin/luci"), Category::CgiRce);
      assert_eq!(categorize("/phpmyadmin/index.php"), Category::AdminPanel);
      assert_eq!(categorize("/totally-unknown"), Category::Other);
   }
}
