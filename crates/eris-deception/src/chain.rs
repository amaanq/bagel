//! Markov-chain text generation, backed by the `markov` crate. Chains are built
//! once and generate immutably, so no locking is needed on the hot path.

use markov::Chain;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const ORDER: usize = 2;

/// The response kinds Eris knows how to fake, matching the category labels
/// from `eris_runtime::category`. A corpus file named `<kind>.txt` in the
/// corpora directory overrides the built-in seed for that kind.
pub const KINDS: [&str; 9] = [
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

/// A set of Markov chains, one per response kind.
pub struct Markov {
    chains: HashMap<String, Chain<String>>,
}

impl Markov {
    /// Build chains from corpus files, falling back to built-in seeds.
    #[must_use]
    pub fn new(corpus_dir: &Path) -> Self {
        let mut chains: HashMap<String, Chain<String>> = KINDS
            .iter()
            .map(|k| ((*k).to_string(), Chain::of_order(ORDER)))
            .collect();

        for kind in KINDS {
            let chain = chains.get_mut(kind).unwrap();
            if let Ok(content) = fs::read_to_string(corpus_dir.join(format!("{kind}.txt"))) {
                for line in content.lines() {
                    chain.feed_str(line);
                }
            }
            if chain.is_empty() {
                for line in seed_for(kind) {
                    chain.feed_str(line);
                }
            }
        }

        Self { chains }
    }

    /// Generate roughly `max_words` words for `kind`, falling back to `other`.
    #[must_use]
    pub fn generate(&self, kind: &str, max_words: usize) -> String {
        let Some(chain) = self.chains.get(kind).or_else(|| self.chains.get("other")) else {
            return String::new();
        };
        let mut words = Vec::new();
        while words.len() < max_words {
            let sentence = chain.generate();
            if sentence.is_empty() {
                break;
            }
            words.extend(sentence);
        }
        words.truncate(max_words);
        words.join(" ")
    }
}

/// Built-in filler so a kind with no corpus still generates plausible text.
fn seed_for(kind: &str) -> &'static [&'static str] {
    match kind {
        "cgi_rce" => &[
            "PHP Fatal error Uncaught Error Call to undefined function shell_exec",
            "PHP Warning file_get_contents failed to open stream on line 42",
            "PHP Notice Undefined index password in /var/www/html/config.php",
            "java.lang.NullPointerException at com.app.controller.AdminServlet",
        ],
        "wordpress" => &[
            "WordPress database error Table wp_users doesnt exist for query SELECT",
            "Warning Cannot modify header information headers already sent by",
            "Fatal error Allowed memory size of 41943040 bytes exhausted",
            "define DB_PASSWORD changeme123 admin secret key salt nonce",
        ],
        "env_secrets" => &[
            "DB_HOST 127.0.0.1 DB_NAME production DB_USER admin DB_PASSWORD secret",
            "AWS_ACCESS_KEY_ID AKIA123456 AWS_SECRET_ACCESS_KEY abcdef region us-east-1",
            "REDIS_URL redis://user:password@redis.internal:6379 DATABASE_URL postgres://",
            "JWT_SECRET supersecretkey STRIPE_API_KEY sk_live_12345 SMTP_PASSWORD changeme",
        ],
        "vcs_leak" => &[
            "HEAD refs/heads/master remote origin url git@github.com:org/private.git",
            "config filemode true bare false symlinks true",
            "index blob 123456 initial commit author deployer email deploy@company.com",
            "packed-refs refs/heads/develop feature/payment-integration",
        ],
        "container_infra" => &[
            "docker container inspect postgres redis nginx network bridge port",
            "apiVersion v1 kind Secret metadata name db-credentials namespace default",
            "terraform tfstate version 4 resources aws_instance kubernetes_pod",
            "docker-compose services web db cache volumes networks",
        ],
        "admin_panel" => &[
            "login username admin password authentication token session cookie",
            "dashboard metrics uptime requests errors memory cpu connections",
            "phpMyAdmin MySQL localhost database server status variables",
            "Spring Boot actuator health info env mappings beans configprops",
        ],
        "php" => &[
            "PHP Version 7.4.3 System Linux build configure command api",
            "phpinfo error_reporting display_errors On allow_url_fopen On",
            "eval base64_decode shell_exec system passthru exec cmd",
            "upload tmp file_uploads On upload_max_filesize 2M max_execution_time 30",
        ],
        "path_traversal" => &[
            "root x 0 0 root /root /bin/bash daemon /sbin /sbin/nologin",
            "etc/passwd shadow hosts resolv.conf apache2 nginx php.ini my.cnf",
            "proc self environ cmdline status maps cwd root exe fd",
            "home user .ssh id_rsa authorized_keys known_hosts config .bash_history",
        ],
        _ => &[
            "index of parent directory backup old config sql dump archive",
            "root password admin login secret private key database credential",
            "server error internal exception stack trace debug enabled true",
            "welcome to nginx default page it works apache test server",
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_nonempty_for_all_kinds() {
        let markov = Markov::new(Path::new("/nonexistent"));
        for kind in KINDS {
            assert!(!markov.generate(kind, 20).is_empty(), "empty for {kind}");
        }
    }

    #[test]
    fn unknown_kind_falls_back() {
        let markov = Markov::new(Path::new("/nonexistent"));
        assert!(!markov.generate("does-not-exist", 20).is_empty());
    }
}
