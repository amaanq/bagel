//! Optional Lua enhancement of tarpit responses.
//!
//! Scripts are compiled once at startup. A pool of ready Lua VMs is reused
//! across requests instead of building a fresh VM per request.

use mlua::Lua;
use parking_lot::Mutex;

/// The built-in script used when no `.lua` files are found. It appends a fake
/// honeytoken and a hidden server id to the generated body.
const DEFAULT_SCRIPT: &str = r#"
function generate_honeytoken(token)
    local kinds = {"API_KEY", "AUTH_TOKEN", "SESSION_ID", "SECRET_KEY"}
    local prefix = kinds[math.random(#kinds)]
    local suffix = string.format("%08x", math.random(0xffffff))
    return prefix .. "_" .. token .. "_" .. suffix
end

-- Iocaine-style maze: every page links onward to more trap paths so a
-- link-following crawler never escapes the tarpit.
local maze_paths = {
    "/wp-admin/", "/wp-includes/", "/wp-content/uploads/", "/wp-json/wp/v2/users",
    "/.git/config", "/.svn/entries", "/.aws/credentials", "/.ssh/id_rsa",
    "/actuator/env", "/actuator/heapdump", "/adminer.php", "/phpmyadmin/index.php",
    "/containers/json", "/.kube/config", "/.docker/config.json",
    "/config.json", "/secrets.yaml", "/credentials.json", "/docker-compose.yml",
    "/cgi-bin/status", "/.bash_history", "/.npmrc",
}
local function maze_links(token, n)
    local links = {}
    for _ = 1, n do
        local p = maze_paths[math.random(#maze_paths)]
        local href = string.format("%s?ref=%s", p, string.sub(token, 1, 8))
        links[#links + 1] = string.format("<a href='%s'>internal</a>", href)
    end
    return table.concat(links, " ")
end

-- Per-category enhancements keyed by the category label Rust passes in.
local enhancers = {}

enhancers.env_secrets = function(text, path, token)
    local ht = generate_honeytoken(token)
    return text
        .. "\n<!-- .env dump -->"
        .. string.format("\n<pre>DB_PASSWORD=%s\nAPI_KEY=%s</pre>", ht, ht)
        .. string.format("\n<!-- %s -->", token)
end

enhancers.wordpress    = enhancers.env_secrets
enhancers.admin_panel  = enhancers.env_secrets
enhancers.vcs_leak     = enhancers.env_secrets
enhancers.cgi_rce      = enhancers.env_secrets
enhancers.php          = enhancers.env_secrets
enhancers.path_traversal = enhancers.env_secrets
enhancers.container_infra = enhancers.env_secrets
enhancers.other        = enhancers.env_secrets
enhancers.generic      = enhancers.env_secrets

function enhance_response(text, kind, path, token)
    local enhancer = enhancers[kind] or enhancers.other
    return enhancer(text, path, token)
        .. "\n<nav>" .. maze_links(token, math.random(3, 6)) .. "</nav>"
        .. "\n<footer style='display:none'>" .. maze_links(token, 5) .. "</footer>"
end
"#;

/// A pool of pre-compiled Lua VMs.
pub struct LuaPool {
    script: String,
    pool: Mutex<Vec<Lua>>,
    max_idle: usize,
}

impl LuaPool {
    /// Load scripts from `scripts_dir` (concatenating all `.lua` files), or use
    /// the built-in default, and warm `warm` VMs.
    pub fn new(scripts_dir: &std::path::Path, warm: usize) -> Self {
        let script = load_scripts(scripts_dir).unwrap_or_else(|| DEFAULT_SCRIPT.to_string());
        let pool = Self {
            script,
            pool: Mutex::new(Vec::new()),
            max_idle: warm.max(1),
        };

        let mut vms = Vec::new();
        for _ in 0..pool.max_idle {
            if let Some(vm) = pool.build() {
                vms.push(vm);
            }
        }
        if vms.is_empty() {
            log::warn!("no usable Lua VM; tarpit responses will skip enhancement");
        }
        *pool.pool.lock() = vms;
        pool
    }

    fn build(&self) -> Option<Lua> {
        let lua = Lua::new();
        if let Err(e) = lua.load(&self.script).exec() {
            log::warn!("failed to load Lua script: {e}");
            return None;
        }
        Some(lua)
    }

    /// Enhance `text`. Returns `None` if no VM is available or the call fails,
    /// leaving the caller to use the unenhanced body.
    pub fn enhance(&self, text: &str, kind: &str, path: &str, token: &str) -> Option<String> {
        let lua = self.pool.lock().pop().or_else(|| self.build())?;

        let result = (|| -> mlua::Result<String> {
            let func: mlua::Function = lua.globals().get("enhance_response")?;
            func.call((
                text.to_string(),
                kind.to_string(),
                path.to_string(),
                token.to_string(),
            ))
        })();

        {
            let mut pool = self.pool.lock();
            if pool.len() < self.max_idle {
                pool.push(lua);
            }
        }

        match result {
            Ok(body) => Some(body),
            Err(e) => {
                log::warn!("Lua enhance_response failed: {e}");
                None
            }
        }
    }
}

fn load_scripts(dir: &std::path::Path) -> Option<String> {
    if !dir.is_dir() {
        return None;
    }
    let mut combined = String::new();
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("lua")
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
    use std::path::Path;

    #[test]
    fn default_script_enhances() {
        let pool = LuaPool::new(Path::new("/nonexistent"), 2);
        let out = pool
            .enhance("hello", "other", "/x", "BOT_123")
            .expect("enhancement");
        assert!(out.starts_with("hello"));
        assert!(out.contains("BOT_123"));
    }

    #[test]
    fn contrib_script_handles_all_categories() {
        let script = include_str!("../../../contrib/lua/better_response.lua");
        let lua = Lua::new();
        lua.load(script)
            .exec()
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
            let func: mlua::Function = lua.globals().get("enhance_response").unwrap();
            let out: String = func
                .call(("hello", kind, "/test", "BOT_X"))
                .unwrap_or_else(|_| panic!("enhance_response failed for {kind}"));
            assert!(
                out.len() > "hello".len(),
                "output for {kind} ({}) should be longer than input ({}): {out}",
                out.len(),
                "hello".len()
            );
        }
    }
}
