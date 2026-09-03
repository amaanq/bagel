-- Adds realistic-looking, but fake content to responses based on the type of the request being
-- made by the bots. This is a demo implementation to demonstrate how scripting works for Eris.

-- Random honeytoken generation
function generate_honeytoken(token)
  local token_types = {
    "API_KEY",
    "AUTH_TOKEN",
    "SESSION_ID",
    "SECRET_KEY",
    "DB_PASSWORD",
    "ADMIN_TOKEN",
    "SSH_KEY",
  }

  local prefix = token_types[math.random(#token_types)]
  local suffix =
    string.format("%08x%08x", math.random(0xffffffff), math.random(0xffffffff))

  return prefix .. "_" .. token .. "_" .. suffix
end

-- Generates a "believable" (but fake) error stack trace
function generate_stack_trace()
  local files = {
    "/var/www/html/index.php",
    "/var/www/html/wp-content/plugins/contact-form-7/includes/submission.php",
    "/var/www/vendor/symfony/http-kernel/HttpKernel.php",
    "/var/www/vendor/laravel/framework/src/Illuminate/Foundation/Http/Kernel.php",
    "/var/www/html/app/Controllers/AdminController.php",
  }

  local functions = {
    "execute",
    "handle",
    "processRequest",
    "loadModel",
    "authenticate",
    "validateInput",
    "renderTemplate",
  }

  local trace = {}
  local depth = math.random(3, 8)

  for i = 1, depth do
    local file = files[math.random(#files)]
    local func = functions[math.random(#functions)]
    local line = math.random(10, 400)

    table.insert(trace, string.format("#%d %s(%d): %s()", i, file, line, func))
  end

  return table.concat(trace, "\n")
end

-- Table of response enhancements by type
-- Helper: insert a list of enhancements at random positions into text.
local function sprinkle(text, enhancements)
  local result = text
  for _, e in ipairs(enhancements) do
    local pos = math.random(1, #result)
    result = string.sub(result, 1, pos) .. e .. string.sub(result, pos + 1)
  end
  return result
end

-- Helper: generate a JSON-ish string from a Lua table.
local function to_json(obj, indent)
  indent = indent or ""
  local s = "{\n"
  for k, v in pairs(obj) do
    s = s .. indent .. '  "' .. k .. '": '
    if type(v) == "table" then
      s = s .. to_json(v, indent .. "  ")
    elseif type(v) == "string" then
      s = s .. '"' .. v .. '"'
    elseif type(v) == "number" or type(v) == "boolean" then
      s = s .. tostring(v)
    else
      s = s .. "null"
    end
    s = s .. ",\n"
  end
  -- Trim trailing comma.
  return string.sub(s, 1, -3) .. "\n" .. indent .. "}"
end

-- Helper: build a fake error response body (JSON or plain text).
local function fake_error(prefix, payload)
  local r = {
    error = { code = "ERR_AUTH_REQUIRED", message = "Authentication required" },
  }
  for k, v in pairs(payload) do
    r[k] = v
  end
  return text .. "\n<pre class='api-response'>" .. to_json(r) .. "</pre>"
end

-- ── Iocaine-style link maze ─────────────────────────────────────────────
-- Every fake page links to a handful of other trap paths, so a crawler that
-- follows links never escapes the tarpit: each hit generates a fresh set of
-- edges in an endless graph. Paths deliberately avoid `.php` and bare `.env`
-- (those are answered elsewhere) and point at routes Eris itself traps.
local maze_paths = {
  "/wp-admin/",
  "/wp-admin/js/",
  "/wp-admin/css/",
  "/wp-includes/",
  "/wp-content/uploads/",
  "/wp-json/wp/v2/users",
  "/wp-json/gravitysmtp/v1/tests/mock-data",
  "/.git/config",
  "/.git/HEAD",
  "/.git/refs/heads/main",
  "/.svn/entries",
  "/.hg/store/00manifest.i",
  "/.aws/credentials",
  "/.ssh/id_rsa",
  "/.ssh/id_ed25519",
  "/.npmrc",
  "/.netrc",
  "/actuator/env",
  "/actuator/heapdump",
  "/actuator/configprops",
  "/actuator/mappings",
  "/adminer.php",
  "/phpmyadmin/index.php",
  "/solr/admin/info/system",
  "/manager/html",
  "/containers/json",
  "/.kube/config",
  "/.docker/config.json",
  "/.terraform/terraform.tfstate",
  "/config.json",
  "/settings.yml",
  "/secrets.yaml",
  "/credentials.json",
  "/application-prod.yml",
  "/appsettings.Production.json",
  "/docker-compose.yml",
  "/web.config.bak",
  "/cgi-bin/status",
  "/cgi-bin/admin.cgi",
  "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
  "/_next/data/9a1b2c3d/index.json",
  "/_next/static/chunks/pages/admin.js",
  "/WEB-INF/web.xml",
  "/WEB-INF/classes/application.yml",
  "/.bash_history",
  "/.mysql_history",
  "/.vscode/sftp.json",
  "/backup/db-dump.sql.gz",
  "/old/wp-config.php.save",
  "/tmp/debug.log",
}

local maze_anchor_words = {
  "download",
  "backup",
  "admin",
  "config",
  "internal",
  "dashboard",
  "export",
  "settings",
  "private",
  "legacy",
  "staging",
  "debug",
}

-- Build `n` maze links with plausible anchor text.
local function maze_links(token, n)
  local links = {}
  for _ = 1, n do
    local p = maze_paths[math.random(#maze_paths)]
    local word = maze_anchor_words[math.random(#maze_anchor_words)]
    -- Randomize query params per link so every edge looks distinct.
    local href = string.format(
      "%s?ref=%s&v=%s",
      p,
      string.sub(token, 1, 6),
      string.sub(token, -6)
    )
    links[#links + 1] = string.format("<a href='%s'>%s</a>", href, word)
  end
  return table.concat(links, " ")
end

local enhancers = {}

--  PHP / CGI remote-code-execution probes
enhancers.cgi_rce = function(text, path, token)
  local ht = generate_honeytoken(token)
  local stack = generate_stack_trace()
  return sprinkle(text, {
    string.format(
      "<!-- PHP Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate %d bytes) -->",
      math.random(4096, 65536)
    ),
    string.format(
      "<div style='display:none'><b>Warning</b>: include(/var/www/html/%s): failed to open stream in <b>/var/www/html/index.php</b></div>",
      string.sub(token, 1, 8)
    ),
    string.format("<!-- SQLSTATE[HY000]: %s -->", ht),
    string.format("<pre>%s</pre>", stack),
    string.format("<input type='hidden' name='token' value='%s'>", ht),
    "<script>console.error('Uncaught TypeError: Cannot read properties of undefined')</script>",
  })
end

-- WordPress-specific probes
enhancers.wordpress = function(text, path, token)
  local ht = generate_honeytoken(token)
  return sprinkle(text, {
    string.format(
      "<meta name='generator' content='WordPress 5.9.6; host=%s'>",
      token
    ),
    string.format("<!-- WP DEBUG: nonce verification failed for '%s' -->", ht),
    string.format(
      "<script>var ajaxurl = '/wp-admin/admin-ajax.php'; var wpApiSettings = {nonce:'%s'};</script>",
      ht
    ),
    "<!-- wp-includes/plugin.php: security-master load failed -->",
    string.format(
      "<!-- wpdb->get_results(): Table 'wp_%s.wp_options' doesn't exist -->",
      string.sub(token, 1, 8)
    ),
    string.format(
      "<link rel='EditURI' type='application/rsd+xml' title='RSD' href='/xmlrpc.php?rsd&token=%s'>",
      ht
    ),
  })
end

-- .env / credential / config file probes
enhancers.env_secrets = function(text, path, token)
  local ht = generate_honeytoken(token)
  return text
    .. "\n<!-- Environment dump for request "
    .. string.sub(token, 1, 12)
    .. " -->"
    .. "\n<pre>"
    .. string.format(
      "\nDB_HOST=10.0.%d.%d",
      math.random(1, 254),
      math.random(1, 254)
    )
    .. string.format("\nDB_NAME=app_%s", string.sub(token, 1, 8))
    .. string.format("\nDB_USER=webapp_%s", string.sub(token, 1, 8))
    .. string.format("\nDB_PASSWORD=%s", ht)
    .. string.format("\nREDIS_URL=redis://:%s@redis.internal:6379/0", ht)
    .. string.format("\nSTRIPE_SECRET_KEY=sk_live_%s", ht)
    .. string.format("\nJWT_SECRET=%s", ht)
    .. string.format("\nSMTP_PASSWORD=%s", ht)
    .. string.format("\nAWS_ACCESS_KEY_ID=AKIA%s", string.sub(ht, -16))
    .. string.format("\nAWS_SECRET_ACCESS_KEY=%s", ht)
    .. "\n</pre>"
    .. string.format(
      "\n<!-- %s loaded from .env.production -->",
      string.sub(token, 1, 8)
    )
end

-- .git / .svn leaks
enhancers.vcs_leak = function(text, path, token)
  local ht = generate_honeytoken(token)
  local refs = {
    "refs/heads/main",
    "refs/heads/master",
    "refs/heads/develop",
    "refs/heads/feature/secret-integration",
  }
  local users = { "admin", "deploy", "devops", "root" }
  return text
    .. string.format(
      '\n<pre>[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote "origin"]\n\turl = https://%s:%s@git.internal/%s/repo.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n</pre>',
      users[math.random(#users)],
      ht,
      string.sub(token, 1, 8)
    )
    .. string.format(
      "\n<!-- HEAD: %s at %s -->",
      refs[math.random(#refs)],
      string.sub(token, -8)
    )
    .. string.format(
      "\n<!-- commit %s Author: deploy <deploy@internal> Date: %s -->",
      math.random(100000, 999999),
      string.sub(ht, -8)
    )
    .. "<script>console.debug('[git] credential helper active: ' + navigator.userAgent)</script>"
end

-- Docker / K8s / Terraform / infrastructure probes ───
enhancers.container_infra = function(text, path, token)
  local ht = generate_honeytoken(token)
  local containers = {
    { "postgres_1", "Up 3 weeks" },
    { "redis_1", "Up 5 days" },
    { "web_1", "Up 2 hours" },
    { "sidekiq_1", "Up 1 week" },
  }
  local c = containers[math.random(#containers)]
  return text
    .. string.format("\n<!-- Docker API v1.41 -->")
    .. string.format(
      '\n<pre>[{"Id":"%s","Image":"%s","Created":%d,"State":"%s","Status":"%s"}]</pre>',
      string.sub(ht, -12),
      c[1],
      os.time() - math.random(86400, 604800),
      "running",
      c[2]
    )
    .. string.format("\n<script>console.log('KUBECONFIG=%s')</script>", ht)
    .. string.format(
      "\n<!-- terraform.tfstate: version=4, serial=%d, lineage=%s -->",
      math.random(1, 100),
      ht
    )
    .. string.format(
      "<div style='display:none'>%s</div>",
      generate_stack_trace()
    )
end

-- Admin dashboards (phpMyAdmin, Solr, actuator, ...)
enhancers.admin_panel = function(text, path, token)
  local ht = generate_honeytoken(token)
  local panels = {
    { "/phpmyadmin", "mysqli", "root@localhost", "MySQL 5.7.38" },
    { "/solr", "solr-spec 8.11.1", "core: collection1", "Docs: 1,420" },
    {
      "/actuator",
      "Spring Boot 2.7.3",
      "Uptime: 12d 4h",
      "Heap: 142MB / 512MB",
    },
    { "/adminer", "Adminer 4.8.1", "MySQL: localhost", "Charset: utf8mb4" },
  }
  local p = panels[math.random(#panels)]
  return sprinkle(text, {
    string.format("<input type='hidden' name='csrf_token' value='%s'>", ht),
    string.format(
      "<!-- %s session: %s, login: admin, password: %s -->",
      p[1],
      ht,
      ht
    ),
    string.format("<div id='debug'>%s: %s [OK]</div>", p[1], p[3]),
    string.format("<meta name='app-version' content='%s'>", p[2]),
    string.format("<!-- DB: %s, connection pool: 8/20 -->", p[4]),
  })
end

-- Bare PHP file probes (dropped webshell filenames)
enhancers.php = function(text, path, token)
  local ht = generate_honeytoken(token)
  return sprinkle(text, {
    string.format(
      "<pre>Array\n(\n    [SCRIPT_FILENAME] => %s\n    [DOCUMENT_ROOT] => /var/www/html\n    [REMOTE_ADDR] => %s\n)</pre>",
      path,
      string.sub(ht, 1, 15)
    ),
    string.format(
      "<!-- PHP %d.%d.%d compiled with Zend Engine v%d.%d.%d -->",
      math.random(7, 8),
      math.random(0, 4),
      math.random(0, 30),
      math.random(3, 4),
      math.random(0, 4),
      math.random(0, 30)
    ),
    string.format("<script>var php_errors = ['%s'];</script>", ht),
    generate_stack_trace(),
  })
end

--  Directory traversal / LFI probes
enhancers.path_traversal = function(text, path, token)
  local ht = generate_honeytoken(token)
  local files = {
    "/etc/passwd:root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\ndaemon:x:2:2:daemon:/sbin:/sbin/nologin",
    "/proc/self/environ:HOME=/root\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\nLANG=en_US.UTF-8",
  }
  return text
    .. "\n<!-- File content for: "
    .. path
    .. " -->"
    .. string.format("\n<pre>%s</pre>", files[math.random(#files)])
    .. string.format("\n<!-- Accessed via: %s -->", ht)
    .. string.format(
      "\n<script>console.log('include_path=.::/usr/share/php:/var/www/vendor:/tmp/backup_%s')</script>",
      string.sub(token, -6)
    )
end

-- Fallback for unrecognized probes
enhancers.other = function(text, path, token)
  local ht = generate_honeytoken(token)
  return text
    .. "\n<!-- Server: Apache/2.4.41 (Ubuntu), PHP 7.4.3, "
    .. string.sub(token, 1, 12)
    .. " -->"
    .. string.format(
      "\n<div style='display:none' id='_%s'>session=%s</div>",
      string.sub(token, 1, 8),
      ht
    )
    .. string.format(
      "\n<script>console.debug('req:%s','%s')</script>",
      string.sub(token, 1, 12),
      path
    )
end

--  generic maps to `other` for backwards compat
enhancers.generic = enhancers.other

-- Main entry point. Rust calls this with the category label as `response_type`.
function enhance_response(text, response_type, path, token)
  local enhancer = enhancers[response_type] or enhancers.other
  local body = enhancer(text, path, token)
  -- Iocaine-style: every page links onward to more trap paths, so a
  -- link-following crawler stays inside the tarpit forever. The nav block
  -- looks like an ordinary footer/menu and regenerates per request.
  local nav = string.format(
    "\n<nav class='site-nav' style='margin-top:2em'>%s</nav>"
      .. "\n<footer style='display:none'>%s</footer>",
    maze_links(token, math.random(3, 6)),
    maze_links(token, math.random(4, 8))
  )
  return body .. nav
end
