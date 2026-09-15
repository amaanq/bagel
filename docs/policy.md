# Policy

This is the operator's view of the web plane. It covers what a request goes
through, what a rule or signal can look at, how scoring picks an action, and
what the config loader refuses. The cryptographic side of mazes, meaning keys,
route prefixes, tokens and poison memory, lives in [maze.md](maze.md) and is
only summarized here where a policy author needs to know it.

## Request authority

Bagel has one idea of which host a request is for, and it uses that everywhere.
A `CanonicalHost` is built once near request entry and then carried through
backend selection, challenges, scoring, rate tracking, maze keys, cookies, logs
and metrics, so there's no second normalizer hiding in the challenge code that
could disagree with the first.

The URI authority supplies the host when it's present and the Host header
supplies it otherwise. When both exist, each is canonicalized and the request
is rejected with a 400 if they disagree. A request with no usable authority is
rejected too. Canonicalization is total, so anything it doesn't accept becomes
a rejected request rather than a fallback spelling.

- Reject user information and malformed authority syntax
- Parse and validate the optional port, then discard it
- Parse bracketed IPv6 literals
- Reject scoped IPv6 zone identifiers
- Normalize IP addresses to their canonical binary form
- Apply the IDNA lookup profile to DNS names
- Convert DNS output to lowercase ASCII
- Remove one terminal dot
- Reject an empty result or invalid DNS output

Backend names, exact and wildcard, are canonicalized the same way at load time,
and the Rhai `host` binding carries the canonical value. Cookies follow it as
well. A DNS host uses the canonical name as the cookie Domain, while an IP
literal omits Domain and produces host-only cookies.

## Source network

Anything that needs to identify where a client is coming from, which means
challenge cookies, maze token binding and poison memory, uses the containing
/24 for IPv4 and the containing /64 for IPv6 rather than the raw address. That
way an IPv6 privacy address rotating inside its /64 still looks like the same
client, and a `SourceNetwork` holds the binary form with the string form
derived from it so every consumer sees one representation.

Client IP resolution follows the configured trusted proxy and PROXY protocol
rules. An untrusted forwarding header never supplies an identity, which is why
`client-ip-header` and `bind { proxy-protocol }` both require a
`trusted-proxies` list and only listed peers may supply an address.

## Request pipeline

The handler runs these steps in order for every request. Maze routes are
recognized before the rate tracker moves, which is what keeps maze traffic out
of the normal rate namespace.

1. Load one immutable state snapshot
2. Canonicalize request authority
3. Select the ordinary backend
4. Resolve client IP and source network
5. Compare the first path segment with configured maze routes for that host
6. Handle a recognized maze route without touching normal rates or rules
7. Apply passthrough when configured
8. Increment the normal rate tracker
9. Take immutable rate and poison snapshots
10. Build the ingress ConditionContext
11. Select and evaluate one scorecard
12. Produce an optional candidate action
13. Evaluate the existing rule tree
14. Apply the candidate only when no terminal rule handled the request
15. Proxy to the selected backend when neither rules nor scorecards handled it

Scoring always sees the ingress request, so a later Context action can't
retroactively change what the signals evaluated.

## Condition bindings

Rule conditions and scorecard signals evaluate against one Rhai scope, and
every binding is pushed as a constant, so a condition can't mutate what a later
one sees.

| Binding          | Value                                                                    |
| ---------------- | ------------------------------------------------------------------------ |
| `host`           | The canonical host                                                       |
| `method`         | Request method in uppercase                                              |
| `path`           | Raw URI path, never percent-decoded                                      |
| `query`          | Query string without the leading `?`, empty when absent                  |
| `user_agent`     | The `user-agent` header, empty when absent                               |
| `remote_address` | Resolved client IP as a string, or the transport peer when none resolves |
| `http_version`   | `HTTP/0.9`, `HTTP/1.0`, `HTTP/1.1`, `HTTP/2.0`, `HTTP/3.0` or `unknown`  |

The rest are maps.

| Binding    | Keys                            | Value                                                                      |
| ---------- | ------------------------------- | -------------------------------------------------------------------------- |
| `headers`  | Lowercase header name           | Header value, empty when the value is not valid UTF-8                      |
| `fp`       | Listed below                    | TLS fingerprints, capture status and source                    |
| `networks` | Configured network name         | True when the client IP falls inside that network                          |
| `rate`     | `available`, `1s`, `10s`, `60s` | Normal request counts for this host and source network                     |
| `poison`   | `returned`                      | True when a maze on this host holds an active entry for the source network |
| `lease`    | `active`                        | True while the client address sits inside an active defense lease          |
| `crawler`  | `verified`                      | True when forward-confirmed reverse DNS matched a configured provider      |
| `trap`     | Six keys, listed below          | What bagel's signature classifier said about the request                   |

`networks` is only populated when a client IP resolves, so a condition indexing
a network name finds no entry rather than false when the address is missing.

`fp` always includes `source`, `tls_status` and `proxied_status` as strings. `source` is one of `none`, `native`, `proxy` or
`native+proxy`. Each status is one of `unavailable`, `incomplete`, `invalid`,
`limited`, `untrusted` or `complete`, and `proxied_status` can also be
`partial`. All `fp` values are strings. Native detail keys require a complete
capture, while a partial proxy report exposes the metadata it supplied.

`fp["ja4"]` needs bagel to terminate TLS itself and it holds the canonical
FoxIO JA4 for a complete native handshake. Native detail keys `tls_version`,
`ciphers`, `extensions`, `groups`, `signature_algorithms` and `alpn` appear
with it. `tls_version` uses the JA4 version code such as `13` for TLS 1.3 and
`12` for TLS 1.2. `ciphers`, `extensions`, `groups` and
`signature_algorithms` hold comma-separated four-digit lowercase hex in
handshake order, with GREASE excluded. `alpn` holds comma-separated hex of each full
protocol name in handshake order.

Capture limits keep each policy string within Rhai's 4096-byte limit. Oversized
metadata reports `limited` and supplies no fingerprint.

Behind a TLS-terminating proxy, `client-tls-header` names a header that
trusted proxies fill with
`$ssl_protocol;$ssl_ciphers;$ssl_curves;$ssl_alpn_protocol;$ssl_session_reused`
and bagel requires all five fields.
Session reuse is `r` for resumed and `.` otherwise. Parsed metadata appears as
`proxied_version`, `proxied_ciphers`, `proxied_curves`, `proxied_alpn` and
`proxied_resumed` with `true` or `false` as strings. Cipher and curve order
follows the client's advertised preference order. The coarse `p` digest in `proxied` appears
only when curves are nonempty, otherwise `proxied_status` is `partial` with no
`proxied` digest while the raw metadata stays available. Nginx only supplies
curves on new sessions. The fingerprint changes with preference order and
negotiated ALPN, so compare it across equivalent capture contexts. It is a
coarser signal than JA4 because the header carries no extension list.

Like `client-ip-header`, this needs `trusted-proxies`. The original transport
peer gates the TLS header even when PROXY rewrites the client source, and
PROXY source takes precedence over the client IP header for that source. Unix
connections without a transport address use the localhost trust policy. It only
describes the client when the proxy terminates the client TLS session itself.
Behind a CDN such as Cloudflare the header describes its origin-pull client,
so leave it unset when scoring visitors.

Decision logs include `fp_source`, `fp_tls_status`, `fp_proxied_status`,
`fp_ja4` and `fp_proxied`. A familiar browser
fingerprint does not prove a visitor is human. Use it as a scoring signal
alongside request rates, challenge results and header consistency.

`lease["active"]` is false unless the daemon has attached its defense plane. It
matches the whole lease network rather than one address, and leases whose
action is observe never appear in it, nor do protected networks. A rule placed
first can deny or tarpit an address the defense plane has already leased, and
that's what makes the escalation ladder useful behind a CDN where kernel drops
never see the client.

Every `trap` entry is false until the daemon attaches a classifier, so a rule
that should only fire when the classifier is present gates on
`trap["available"]` first, for example `trap["available"] && !trap["any"]`.

| Key                    | Meaning                           |
| ---------------------- | --------------------------------- |
| `trap["available"]`    | A classifier is attached          |
| `trap["any"]`          | The request matched a trap        |
| `trap["path"]`         | The path signature fired          |
| `trap["user_agent"]`   | The user-agent signature fired    |
| `trap["impersonator"]` | The impersonator signature fired  |
| `trap["category"]`     | Report bucket, or an empty string |

Categories are report buckets such as `env_secrets`, `wordpress`, `vcs_leak`
and `scraper`. Path traps match the percent-decoded path while the request is
forwarded untouched, exactly as the retired bagel HTTP listener did.

## Rate tracking

The `rate` map comes from a tracker keyed on canonical host and source network
that counts only requests entering ordinary policy evaluation. Requests under a
recognized maze route never touch it regardless of token classification or
renderer result, and passthrough requests don't either because they never
enter policy evaluation. The one normal request that triggers a tarpit does
count, while everything the client does inside the maze afterwards goes to a
separate bounded tracker used for renderer budgets and maze metrics, and that
namespace is never exposed to Rhai.

```
rate["available"]
rate["1s"]
rate["10s"]
rate["60s"]
```

The values are unsigned request counts including the current request, so the
first request for a new key sees 1 in every window. A request without a
resolved client network sees false and zeroes. The tracker uses monotonic time
with sixty one-second buckets per key, and updates saturate instead of
wrapping.

`rate["1s"]` is sensitive to bucket position, since a request near the start of
a bucket sees a different sample shape from one near its end. Enforcement
belongs on `10s` and `60s`, and the one-second value is for diagnostics or as a
burst hint corroborated by another signal.

The default is 64 shards and an LRU capacity of 65,536 keys. The configured
capacity must fall between 1,024 and 1,048,576, and changing it on reload
rebuilds the tracker.

## Scoring

Scoring lives inside `policy` next to the rules.

```kdl
policy {
    renderers {
        renderer "local-iocaine" kind="iocaine" {
            endpoint "http://127.0.0.1:8081/render"
            timeout "2s"
            max-body 262144
            max-concurrency 128
            rate 50
            burst 200
            decoy-rate 10
            decoy-burst 40
            cooldown "60s"
        }
        renderer "prose" kind="markov" {
            rate 200
            burst 400
        }
    }

    mazes {
        maze "default" renderer="local-iocaine" {
            token-ttl "24h"
            memory-ttl "1h"
            min-links 8
            max-links 16
            min-bytes 8192
            max-bytes 32768
        }
    }

    scoring rate-capacity=65536 {
        scorecard "default" mode="observe" {
            signal "rate-spike" condition=#"rate["available"] && rate["10s"] > 120"# weight=40
            signal "known-network" condition=#"networks["hosting"]"# weight=25
            signal "poison-return" condition=#"poison["returned"]"# weight=100

            threshold 50 action="challenge" {
                challenges "cookie"
            }

            threshold 90 action="tarpit" maze="default"
            threshold 130 action="drop"
        }
    }

    rules {
        rule "allow-static" condition=#"path.starts_with("/assets/")"# action="pass"
    }
}
```

A scorecard may carry a condition, and omitting it makes the scorecard
unconditional. The first matching scorecard wins, so config loading rejects any
scorecard that follows an unconditional one because it could never be reached.
`mode` is `observe` or `enforce` and defaults to `observe`.

Signals are separate nodes, each with a unique name, one Rhai condition and a
positive u32 weight, and zero weights are rejected. Every signal in the
selected scorecard is evaluated and the matching weights are added with
saturating arithmetic. A signal whose expression errors contributes zero,
records the error in the decision trace and bumps an error metric, but it never
aborts the request. There are no negative weights, so a verified-crawler
exclusion belongs in the scorecard condition or in a terminal allow rule rather
than in a subtracted forged-UA score.

Thresholds are unique positive u32 values, and the eligible one with the
highest value not exceeding the score becomes the candidate. Eight actions are
allowed at a threshold, `challenge`, `deny`, `block`, `code`, `drop`, `proxy`,
`tarpit` and `smear`, while `none`, `context`, `check` and `pass` are rejected
there. A tarpit action must name an existing maze. A smear action serves a
deception page paced like a tarpit and holds a slot from
`smear { max-concurrent }`, degrading to drop when the slots are gone. A proxy
threshold takes the same backend, match and rewrite fields as an ordinary proxy
rule. A challenge threshold uses the existing challenge action parser and
inherits the usual defaults when pass-action, fail-action or the HTTP code are
omitted, so pass falls back to `pass`, fail falls back to `deny` with a 403,
the code falls back to the global `challenge-http-code`, and at least one
configured challenge is required.

## Rules and the candidate

Existing rules keep priority over a scorecard candidate. Scoring happens first
so that observation logs include requests a rule later handled, but enforcement
only happens after rule evaluation returns Continue.

A terminal rule suppresses the candidate. Terminal actions are pass, deny,
block, code, drop, proxy, a handled challenge, and any child result that
produces a response or a connection drop, which means a broad pass rule is an
allowlist that disables scorecard enforcement for whatever it matches. Context,
Check, Report and Lure keep their continuation behavior through explicit
`RuleOutcome` values.

Observation mode calculates the same candidate and then never applies it.
Existing rules, direct maze requests and direct tarpit rules stay live in that
mode.

### Proxy

`Action::Proxy` resolves the named backend, applies the configured `match_re`
and `rewrite`, forwards the request and returns the upstream response. The
regular expression is compiled during config loading, so an invalid one is a
startup error rather than a silent `None`, and an unknown or empty backend is a
startup error as well. If `match_re` is present but doesn't match, the path is
left alone. When it does, capture expansion runs through `rewrite`, and the
query survives unless the rewrite explicitly supplies a replacement. The proxy
path uses the same hop-by-hop header filtering and client-IP forwarding rules
as ordinary backend proxying.

### Context

`Action::Context` applies request headers before evaluating its children, and
those mutations are scoped to the subtree, so sibling rules outside it see the
original request. When a child returns a response, the configured response
headers are applied on the way out, and when the subtree returns Continue no
response headers are emitted. Invalid header names and values are config errors
rather than being silently discarded.

### Lure

`action="lure" maze="default"` continues to the next rule and, when the
request ends up proxied and the origin answers with uncompressed HTML, appends
a `hidden` `nofollow` anchor into the named maze. The link carries a token
bound to the visitor's source network, so following it later counts as a valid
return and sets `poison["returned"]` for that network, the same as walking in
from a tarpit page. Browsers never navigate a hidden link and verified crawlers
honor `nofollow`, so place the rule after the pass rules for search engines
and previews. A request with a pending lure or check widget is proxied without
`Accept-Encoding`, since compressed bodies can't be appended to. Lure is not
allowed as a threshold action.

### Drop

`RuleOutcome::Drop` resets the connection without writing a response. Every
application connection carries a connection-scoped DropHandle, and a handler
that selects drop signals that handle and then awaits
`std::future::pending::<Response>()`. The connection task cancels that future
once it sees the signal, so nothing is left detached.

The serve loop races Hyper against the drop receiver, and on a signal it tears
the connection down by configuring zero-duration SO_LINGER where the transport
supports it, cancelling and dropping the Hyper future, dropping the transport
without an HTTP response, and skipping TLS close_notify. For TCP the intended
result is an RST where the platform permits it. Unix sockets simply close
without a response. On HTTP/2 a drop terminates the whole connection and every
multiplexed stream on it, so dropping one stream takes unrelated streams with
it.

This is also why the application listener owns accepted sockets directly, so
the connection task keeps transport control. The metrics listener parses
requests with `bagel_proto::http` instead, since it serves one fixed endpoint
and never needs to drop a connection mid-response.

## Mazes and renderers

A maze is a generated page tree that a `tarpit` action or threshold sends a
client into. Its URLs are minted under a per-host route prefix and carry a
signed token, and a client that comes back with a valid token from the same
source network sets poison memory, which is what `poison["returned"]` reads.
The token, prefix and memory details are in [maze.md](maze.md).

Maze names are operator-supplied identifiers matching `[a-z][a-z0-9_-]{0,63}`
and must be unique, and renderer names follow the same grammar. A maze names
one renderer. The reserved name `builtin` selects the in-process renderer and
needs no renderer block, so `builtin` is rejected as the name of a configured
one.

A configured renderer declares a `kind`, and exactly two are accepted.

| Kind      | Transport                              | Endpoint                                    |
| --------- | -------------------------------------- | ------------------------------------------- |
| `iocaine` | HTTP POST to an external service       | Required, HTTP or HTTPS without credentials |
| `markov`  | In-process, backed by bagel's Deceiver | Rejected if present                         |

Both share the same budget, cooldown, concurrency and body limits, and both
fall back to the built-in renderer on failure. A `markov` page that exceeds
`max-body` falls back and starts the source cooldown exactly as an oversized
Iocaine response does. A `markov` renderer receives the seed, the normalized
maze path and the generated links, but never the canonical host, which only the
Iocaine payload carries.

### Iocaine

Iocaine is an optional low-rate presentation renderer. It isn't the sustained
crawler engine and it isn't a security boundary. Bagel owns routing, token
validation, link creation, poison memory, status codes, headers and fallback,
and Iocaine receives no key material, so it can't mint a maze URL.

The adapter sends a sanitized POST containing only these fields.

```json
{
  "mode": "maze",
  "seed": "lowercase base32 seed",
  "host": "canonical.example",
  "path": "normalized-maze-path",
  "links": ["/route/token/path"]
}
```

`mode` is always `"maze"`, and the renderer isn't told whether the request is
authenticated or a decoy. Nothing else leaves Bagel, not the client IP, source
network, user agent, JA4, request headers, cookies, query strings, challenge
state, token keys, poison state or original request body.

The renderer must return a successful UTF-8 body within the size limit. Bagel
ignores its status choice and all of its response headers, and redirects are
never followed. Every limit has a default and each is configurable per
renderer.

- General source budget of 50 requests per second
- General burst of 200
- Additional decoy budget of 10 requests per second
- Additional decoy burst of 40
- Global external-renderer concurrency of 128
- Two-second timeout
- Maximum response body of 256 KiB
- Built-in cooldown of 60 seconds

The source budget is keyed on canonical host, maze name and source network.
When client-network resolution is unavailable, the transport peer network
stands in for renderer budgeting only, and if neither is available one bounded
unknown-source bucket absorbs the traffic. Authenticated requests consume the
general bucket and decoys consume both.

Exhausting either applicable bucket moves that source key into built-in mode
for 60 seconds, and so do timeouts, connection failures, non-success responses,
invalid UTF-8 and oversized bodies. Global concurrency exhaustion falls back for
the current request alone without blaming the source. A trapped crawler
sustaining more than the external budget therefore sees built-in output, and
since the adapter serves low-rate traversal while the built-in renderer carries
the volume, Bagel makes no claim that the two are statistically
indistinguishable after a tier change.

## Crawler verification

A user-agent string never establishes crawler identity, so verification is
forward-confirmed reverse DNS against explicitly configured providers. It needs
the `fcrdns` build feature, on by default. Building without it drops the DNS
resolver, and a `crawlers` block in such a build fails validation, so no
deployment silently treats a claimed crawler as verified.

1. Resolve PTR records for the client IP
2. Match a configured DNS suffix at a label boundary
3. Resolve the selected hostname forward
4. Confirm that the original client IP appears in the result

Positive results are cached for an hour and negative ones for five minutes, and
a DNS failure or timeout means unverified. The result is exposed as
`crawler["verified"]`, so an operator can exclude verified crawlers from a
scorecard condition or give them a terminal pass rule.

Web Bot Auth support is waiting on a stable HTTP Message Signatures profile and
interoperable deployments. It's not inferred from a header-shaped claim.

## Decision trace and metrics

Every normal policy request emits one structured decision trace with these
fields.

- policy_revision
- scorecard
- score_mode
- score
- matched_signals
- signal_errors
- rate_available
- rate_1s
- rate_10s
- rate_60s
- poison_returned
- candidate_threshold
- candidate_action
- candidate_status
- terminal_rule
- terminal_action
- effective_action

Maze traces add `maze`, `poison_status`, `renderer` and `renderer_result`.

`candidate_status` is one of `no_scorecard`, `no_candidate`, `observed`,
`applied` or `suppressed_by_rule`. When a candidate exists and a terminal rule
handles the request, `suppressed_by_rule` is used in both modes and `score_mode`
tells you whether the candidate could otherwise have acted. Traces never
contain token bytes, binding values, memory identifiers, full query strings or
key material.

Six bounded metrics are exported.

```
bagel_scoring_signal_total
bagel_scoring_signal_error_total
bagel_scoring_decision_total
bagel_scoring_score
bagel_poison_requests_total
bagel_maze_renderer_requests_total
```

`bagel_scoring_score` is a histogram with buckets at 0, 10, 20, 40, 60, 80,
100, 150, 200, 300 and 500, and the numeric score is the histogram value, never
a label. Labels only come from finite configuration or fixed enums, meaning
scorecard name, signal name, mode, candidate status, action kind, maze name,
poison classification, renderer kind and renderer result. Raw host, IP, source
network, path, user agent, score, query and token are never labels.

## Config surface

A direct rule may select a maze, and a score threshold uses the same action
shape.

```kdl
rule "trap-scraper" condition=#"user_agent.contains("ExampleBot")"# action="tarpit" maze="default"
threshold 90 action="tarpit" maze="default"
```

A challenge threshold or rule may raise a proof-of-work challenge's difficulty
for the requests it matches, so one challenge serves several suspicion levels.

```kdl
threshold 40 action="challenge" { challenges "pow" }
threshold 80 action="challenge" difficulty=7 { challenges "pow" }
```

Duration fields take explicit units such as `"60s"`, `"1h"` and `"24h"`.
Policy-directory merging keeps source order, and duplicate renderer, maze,
scorecard, signal and rule identifiers are errors rather than last-write-wins
overrides.

Any configuration containing a maze, a direct tarpit rule or a tarpit threshold
requires a stable key seed, and startup fails without one because restarting
must never silently change live maze routes. Challenge-only deployments may
generate an ephemeral key at startup instead. Exactly one of three inputs
supplies the seed, `--key-seed` and `BAGEL_KEY_SEED`, `--key-seed-file` and
`BAGEL_KEY_SEED_FILE`, or `--generate-key`, and conflicting CLI or environment
inputs are a startup failure. The file holds trimmed ASCII hex in the same
format as `--key-seed`.

## Startup validation

The configuration is rejected when any of these holds.

- Maze support is configured without a stable key seed
- More than one key-seed input is active
- The PKCS8 value is malformed
- Global passthrough and maze support are both enabled
- A maze or renderer name is invalid or duplicated
- A maze references an unknown renderer
- A tarpit action references an unknown maze
- An external endpoint is malformed or contains credentials
- A duration, body limit, link limit, rate, burst, capacity, or concurrency
  value is outside its accepted range
- Minimum values exceed corresponding maximum values
- Token lifetime falls outside 60 seconds through seven days
- Memory lifetime is zero
- Exact-host route prefixes collide
- A scorecard mode is unknown
- A scorecard is unreachable after an unconditional scorecard
- A signal weight is zero
- Signal names or threshold values are duplicated
- A threshold action is forbidden
- A challenge threshold has no challenges
- A proxy action has an unknown backend
- A proxy regular expression is invalid
- A context header is invalid
- Reserved token flags or versions are configured
- A wildcard host produces a maze-prefix collision during per-host table
  construction
- An action string is unrecognized, which is a config error rather than a
  degradation to `Action::None`

## Nix module

`services.bagel.keySeedFile` is the one secret option. The module passes the
file through systemd credentials and invokes Bagel with the credential path, so
the seed never enters generated Nix configuration or the Nix store. The
remaining options, `enable`, `package`, `configFile`, `enforcementMode`,
`enforcementTable`, `logLevel`, `user`, `group`, `supplementaryGroups`,
`readOnlyPaths` and `stateDir`, are nonsecret.

`enforcementMode` and `enforcementTable` have to match the enforcement node in
the KDL file, because the module can't read KDL and only uses them to grant
CAP_NET_ADMIN and to delete the nft table on stop.
