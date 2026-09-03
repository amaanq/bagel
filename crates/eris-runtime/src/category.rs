//! Human-facing grouping of trapped requests for reporting.
//!
//! Trap patterns decide *whether* a request is trapped; categories decide *how
//! it is reported*. They are deliberately separate: the trap set is
//! operator-tunable, but the report categories stay fixed so a report reads the
//! same across configurations. Categorisation runs only on the trap path (a
//! request already destined to sleep for seconds), so a handful of regexes here
//! never touch the legitimate hot path.

use regex::RegexSet;
use std::sync::LazyLock;

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
    /// Trapped for exceeding the per-IP request-rate budget (volume floods).
    Flood,
    /// Trapped for enumerating git history (deep blob/blame/archive crawling)
    /// past the casual-browsing budget.
    GitScan,
}

impl Category {
    /// Every category in reporting/priority order, most specific first.
    ///
    /// New categories are appended so the numeric [`Category::index`] of the
    /// existing ones stays stable across persisted state; see
    /// [`Category::from_index`].
    pub const ALL: [Category; 13] = [
        Category::PathTraversal,
        Category::CgiRce,
        Category::VcsLeak,
        Category::ContainerInfra,
        Category::Wordpress,
        Category::EnvSecrets,
        Category::AdminPanel,
        Category::Php,
        Category::Other,
        Category::Ssh,
        Category::Scraper,
        Category::Flood,
        Category::GitScan,
    ];

    /// Stable machine/report label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Category::PathTraversal => "path_traversal",
            Category::CgiRce => "cgi_rce",
            Category::VcsLeak => "vcs_leak",
            Category::ContainerInfra => "container_infra",
            Category::Wordpress => "wordpress",
            Category::EnvSecrets => "env_secrets",
            Category::AdminPanel => "admin_panel",
            Category::Php => "php",
            Category::Other => "other",
            Category::Ssh => "ssh",
            Category::Scraper => "scraper",
            Category::Flood => "flood",
            Category::GitScan => "git_scan",
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
    pub fn from_index(idx: usize) -> Category {
        Category::ALL.get(idx).copied().unwrap_or(Category::Other)
    }
}

/// Number of distinct categories; the width of every per-category count array.
pub const COUNT: usize = Category::ALL.len();

/// One regex per non-`Other` category, in the same order as
/// [`Category::ALL`]. The first match wins, so more specific buckets are
/// listed before broader ones (e.g. WordPress before bare PHP).
static PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        // PathTraversal
        r"(?i)\.\./|%2e%2e|/etc/passwd|/proc/self|/windows/win\.ini",
        // CgiRce
        r"(?i)/cgi-bin/|vendor/phpunit|eval-stdin|/thinkphp|/struts|ognl|nashorn|jndi:|\$\{|\$\(",
        // VcsLeak
        r"(?i)/\.git|/\.svn|/\.hg|/\.bzr",
        // ContainerInfra
        r"(?i):2375|/containers/json|docker-compose|/\.kube|/\.docker|terraform|\.tfstate|\.tfvars",
        // Wordpress
        r"(?i)/wp-admin|/wp-login|/wp-config|/wp-content|/wp-includes|/wp-json|xmlrpc\.php",
        // EnvSecrets
        r"(?i)\.env|/config\.|/settings\.|/secrets\.|/credentials\.|/\.aws|appsettings|application[.-]|/\.ssh|id_rsa|id_ed25519|\.pem|/\.npmrc|/\.yarnrc|/\.htpasswd",
        // AdminPanel
        r"(?i)phpmyadmin|/adminer|/solr/|/actuator|/manager/html|/phpinfo",
        // Php
        r"(?i)\.php",
    ])
    .expect("built-in category patterns must compile")
});

/// Bucket a (already percent-decoded) request path into a [`Category`].
#[must_use]
pub fn categorize(path: &str) -> Category {
    // `matches` walks the set once; take the lowest index, which is the
    // highest-priority category by construction.
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

    #[test]
    fn wordpress_beats_bare_php() {
        // Both the WordPress and PHP regexes match; the more specific bucket
        // must win because it is listed first.
        assert_eq!(categorize("/wp-login.php"), Category::Wordpress);
    }

    #[test]
    fn index_round_trips() {
        for c in Category::ALL {
            assert_eq!(Category::from_index(c.index()), c);
        }
        assert_eq!(Category::from_index(9999), Category::Other);
    }
}
