fn rand_range(lo, hi) {
    lo + random(hi - lo + 1)
}

fn pick(arr) {
    arr[random(arr.len())]
}

fn head(s, n) {
    s.sub_string(0, n)
}

fn tail(s, n) {
    if s.len() <= n {
        s
    } else {
        s.sub_string(s.len() - n, n)
    }
}

fn generate_honeytoken(token) {
    let token_types = [
        "API_KEY",
        "AUTH_TOKEN",
        "SESSION_ID",
        "SECRET_KEY",
        "DB_PASSWORD",
        "ADMIN_TOKEN",
        "SSH_KEY",
    ];
    `${pick(token_types)}_${token}_${random_hex(16)}`
}

fn generate_stack_trace() {
    let files = [
        "/var/www/html/index.php",
        "/var/www/html/wp-content/plugins/contact-form-7/includes/submission.php",
        "/var/www/vendor/symfony/http-kernel/HttpKernel.php",
        "/var/www/vendor/laravel/framework/src/Illuminate/Foundation/Http/Kernel.php",
        "/var/www/html/app/Controllers/AdminController.php",
    ];
    let functions = [
        "execute",
        "handle",
        "processRequest",
        "loadModel",
        "authenticate",
        "validateInput",
        "renderTemplate",
    ];
    let trace = [];
    let depth = rand_range(3, 8);
    for i in 0..depth {
        trace += `#${i + 1} ${pick(files)}(${rand_range(10, 400)}): ${pick(functions)}()`;
    }
    trace.join("\n")
}

fn sprinkle(text, enhancements) {
    let result = text;
    for e in enhancements {
        let pos = random(result.len() + 1);
        result = result.sub_string(0, pos) + e + result.sub_string(pos, result.len() - pos);
    }
    result
}

fn maze_paths() {
    [
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
    ]
}

fn maze_anchor_words() {
    [
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
    ]
}

fn maze_links(token, n) {
    let paths = maze_paths();
    let words = maze_anchor_words();
    let links = [];
    for i in 0..n {
        links += `<a href='${pick(paths)}?ref=${head(token, 6)}&v=${tail(token, 6)}'>${pick(words)}</a>`;
    }
    links.join(" ")
}

fn enhance_cgi_rce(text, path, token) {
    let ht = generate_honeytoken(token);
    let stack = generate_stack_trace();
    sprinkle(text, [
        `<!-- PHP Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate ${rand_range(4096, 65536)} bytes) -->`,
        `<div style='display:none'><b>Warning</b>: include(/var/www/html/${head(token, 8)}): failed to open stream in <b>/var/www/html/index.php</b></div>`,
        `<!-- SQLSTATE[HY000]: ${ht} -->`,
        `<pre>${stack}</pre>`,
        `<input type='hidden' name='token' value='${ht}'>`,
        "<script>console.error('Uncaught TypeError: Cannot read properties of undefined')</script>",
    ])
}

fn enhance_wordpress(text, path, token) {
    let ht = generate_honeytoken(token);
    sprinkle(text, [
        `<meta name='generator' content='WordPress 5.9.6; host=${token}'>`,
        `<!-- WP DEBUG: nonce verification failed for '${ht}' -->`,
        `<script>var ajaxurl = '/wp-admin/admin-ajax.php'; var wpApiSettings = {nonce:'${ht}'};</script>`,
        "<!-- wp-includes/plugin.php: security-master load failed -->",
        `<!-- wpdb->get_results(): Table 'wp_${head(token, 8)}.wp_options' doesn't exist -->`,
        `<link rel='EditURI' type='application/rsd+xml' title='RSD' href='/xmlrpc.php?rsd&token=${ht}'>`,
    ])
}

fn enhance_env_secrets(text, path, token) {
    let ht = generate_honeytoken(token);
    let out = text + `\n<!-- Environment dump for request ${head(token, 12)} -->`;
    out += "\n<pre>";
    out += `\nDB_HOST=10.0.${rand_range(1, 254)}.${rand_range(1, 254)}`;
    out += `\nDB_NAME=app_${head(token, 8)}`;
    out += `\nDB_USER=webapp_${head(token, 8)}`;
    out += `\nDB_PASSWORD=${ht}`;
    out += `\nREDIS_URL=redis://:${ht}@redis.internal:6379/0`;
    out += `\nSTRIPE_SECRET_KEY=sk_live_${ht}`;
    out += `\nJWT_SECRET=${ht}`;
    out += `\nSMTP_PASSWORD=${ht}`;
    out += `\nAWS_ACCESS_KEY_ID=AKIA${tail(ht, 16)}`;
    out += `\nAWS_SECRET_ACCESS_KEY=${ht}`;
    out += "\n</pre>";
    out += `\n<!-- ${head(token, 8)} loaded from .env.production -->`;
    out
}

fn enhance_vcs_leak(text, path, token) {
    let ht = generate_honeytoken(token);
    let refs = [
        "refs/heads/main",
        "refs/heads/master",
        "refs/heads/develop",
        "refs/heads/feature/secret-integration",
    ];
    let users = ["admin", "deploy", "devops", "root"];
    let out = text + `\n<pre>[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote "origin"]\n\turl = https://${pick(users)}:${ht}@git.internal/${head(token, 8)}/repo.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n</pre>`;
    out += `\n<!-- HEAD: ${pick(refs)} at ${tail(token, 8)} -->`;
    out += `\n<!-- commit ${rand_range(100000, 999999)} Author: deploy <deploy@internal> Date: ${tail(ht, 8)} -->`;
    out += "<script>console.debug('[git] credential helper active: ' + navigator.userAgent)</script>";
    out
}

fn enhance_container_infra(text, path, token) {
    let ht = generate_honeytoken(token);
    let containers = [
        ["postgres_1", "Up 3 weeks"],
        ["redis_1", "Up 5 days"],
        ["web_1", "Up 2 hours"],
        ["sidekiq_1", "Up 1 week"],
    ];
    let c = pick(containers);
    let out = text + "\n<!-- Docker API v1.41 -->";
    out += `\n<pre>[{"Id":"${tail(ht, 12)}","Image":"${c[0]}","Created":${1700000000 + random(100000000)},"State":"running","Status":"${c[1]}"}]</pre>`;
    out += `\n<script>console.log('KUBECONFIG=${ht}')</script>`;
    out += `\n<!-- terraform.tfstate: version=4, serial=${rand_range(1, 100)}, lineage=${ht} -->`;
    out += `<div style='display:none'>${generate_stack_trace()}</div>`;
    out
}

fn enhance_admin_panel(text, path, token) {
    let ht = generate_honeytoken(token);
    let panels = [
        ["/phpmyadmin", "mysqli", "root@localhost", "MySQL 5.7.38"],
        ["/solr", "solr-spec 8.11.1", "core: collection1", "Docs: 1,420"],
        ["/actuator", "Spring Boot 2.7.3", "Uptime: 12d 4h", "Heap: 142MB / 512MB"],
        ["/adminer", "Adminer 4.8.1", "MySQL: localhost", "Charset: utf8mb4"],
    ];
    let p = pick(panels);
    sprinkle(text, [
        `<input type='hidden' name='csrf_token' value='${ht}'>`,
        `<!-- ${p[0]} session: ${ht}, login: admin, password: ${ht} -->`,
        `<div id='debug'>${p[0]}: ${p[2]} [OK]</div>`,
        `<meta name='app-version' content='${p[1]}'>`,
        `<!-- DB: ${p[3]}, connection pool: 8/20 -->`,
    ])
}

fn enhance_php(text, path, token) {
    let ht = generate_honeytoken(token);
    sprinkle(text, [
        `<pre>Array\n(\n    [SCRIPT_FILENAME] => ${path}\n    [DOCUMENT_ROOT] => /var/www/html\n    [REMOTE_ADDR] => ${head(ht, 15)}\n)</pre>`,
        `<!-- PHP ${rand_range(7, 8)}.${rand_range(0, 4)}.${rand_range(0, 30)} compiled with Zend Engine v${rand_range(3, 4)}.${rand_range(0, 4)}.${rand_range(0, 30)} -->`,
        `<script>var php_errors = ['${ht}'];</script>`,
        generate_stack_trace(),
    ])
}

fn enhance_path_traversal(text, path, token) {
    let ht = generate_honeytoken(token);
    let files = [
        "/etc/passwd:root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\ndaemon:x:2:2:daemon:/sbin:/sbin/nologin",
        "/proc/self/environ:HOME=/root\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\nLANG=en_US.UTF-8",
    ];
    let out = text + `\n<!-- File content for: ${path} -->`;
    out += `\n<pre>${pick(files)}</pre>`;
    out += `\n<!-- Accessed via: ${ht} -->`;
    out += `\n<script>console.log('include_path=.::/usr/share/php:/var/www/vendor:/tmp/backup_${tail(token, 6)}')</script>`;
    out
}

fn enhance_other(text, path, token) {
    let ht = generate_honeytoken(token);
    let out = text + `\n<!-- Server: Apache/2.4.41 (Ubuntu), PHP 7.4.3, ${head(token, 12)} -->`;
    out += `\n<div style='display:none' id='_${head(token, 8)}'>session=${ht}</div>`;
    out += `\n<script>console.debug('req:${head(token, 12)}','${path}')</script>`;
    out
}

fn enhance_response(text, kind, path, token) {
    let body = switch kind {
        "cgi_rce" => enhance_cgi_rce(text, path, token),
        "wordpress" => enhance_wordpress(text, path, token),
        "env_secrets" => enhance_env_secrets(text, path, token),
        "vcs_leak" => enhance_vcs_leak(text, path, token),
        "container_infra" => enhance_container_infra(text, path, token),
        "admin_panel" => enhance_admin_panel(text, path, token),
        "php" => enhance_php(text, path, token),
        "path_traversal" => enhance_path_traversal(text, path, token),
        _ => enhance_other(text, path, token),
    };
    body + `\n<nav class='site-nav' style='margin-top:2em'>${maze_links(token, 3 + random(4))}</nav>` + `\n<footer style='display:none'>${maze_links(token, 4 + random(5))}</footer>`
}
