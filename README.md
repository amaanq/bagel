# bagel

Bagel is an HTTP proxy and SSH tarpit daemon that delays malicious scanners. It
reads configured evidence sources, applies durable escalation policies, and can
enforce bans through nftables. Its HTTP data plane adds a KDL rule engine with
rhai conditions, scorecards, challenges, mazes, crawler verification and paced
deception pages, and every hostile verdict it makes feeds the same escalation
policies.

## Why bagel

The project can be thought of as individual components that make up a bagel.

To start off, the HTTP plane is the counter. It sizes up each request and either
serves it, stalls it, or turns it away. Verified crawlers and allowlisted ranges
go through the hole and reach the backend untouched.

- The **schmear** is `smear`, a deceptive body written out slowly. It's spread
  thin, so `max-concurrent` runs out under load and the rest degrade to a drop.
- The **lox** is `tarpit`, sliced thin and served one piece at a time until
  `max-secs` expires.
- The **dough** is `deception`. Point `corpora` at some text and the markov
  generator produces as much filler as the maze asks for.
- The **seeds** are the trap paths, scattered over the surface and sticking to
  whatever touches them. Rules reach them through `trap["path"]`.
- The **kettle** is `maze`. Bagels are boiled before they're baked, and a crawler
  that walks into a generated page tree goes round in hot water for about as long.

`enforcement mode="required"` is an everything bagel. `mode="observe"` is a plain
one that only watches.

## Configuration

One KDL file configures both planes. The web nodes sit at the top level and the
defense plane lives under `defense { }`, so a small deployment fits on one
screen, see `examples/bagel.kdl`. `bagel config example` prints a starting
point, `bagel-daemon --config bagel.kdl` starts the daemon, and adding
`--check-config` validates the file without starting anything. The policy
surface itself, meaning rules, scoring, condition bindings, mazes and
renderers, is described in [docs/policy.md](docs/policy.md), and the key and
token design underneath mazes in [docs/maze.md](docs/maze.md).

Every section is typed, so an unknown field, an extra argument, a repeated
singleton child or a wrongly typed scalar is a load error rather than something
quietly ignored. Web rules keep their ordered child overrides while defense
singleton children reject duplicates, and `policy-dir` merges KDL snippets in
filename order with the same strictness, so an unreadable directory, a
malformed snippet or an unknown policy entry stops loading. Backend header
names and values are validated before a single request is served.

Durations are written `"60s"`, `"30m"`, `"24h"` or `"7d"`. Network filters are
`filter="jq" jq=".."` or `filter="regex" regex=".."`, and a named condition is
`condition "name" expr=".."`. Rhai goes in a KDL raw string,
`condition=#"path == "/x""#`, or in the multi-line `#"""` form with one `||`
per line, which the parser dedents to the closing line. The optional `(rhai)`
annotation says what the payload is and rejects misspellings.

Mazes need a persistent key. Generate it once with `bagel-daemon
--generate-key`, then supply it through `--key-seed-file`, or
`services.bagel.keySeedFile` on NixOS. Keep the file private and keep it across
restarts, because rotating it invalidates every outstanding maze URL and
challenge cookie.

Two rule features tie the planes together. `action="report" kind="tarball"`
emits a web offense whose `/kind` is the configured label and then continues to
the next rule, so a defense policy with a `json` detector on
`equals "/kind" "tarball"` can count those per address inside its
`findtime-secs` and put the client on the escalation ladder, and
`group-key-pointer="/group_key"` keeps a separate window for each repository a
rule reports. In the other direction, `lease["active"]` is true while the
client address holds an active non-observe lease, so a rule placed first can
`deny` or `tarpit` it at the web layer. That's what makes the ladder useful
behind a CDN, where a kernel drop never reaches the client.

A `check` rule proves a client without an interstitial, by splicing the
challenge into the proxied page instead of replacing it. `embed="hidden"`, the
default, delivers only the solver, and `embed="card"` also draws the usual
card. An embedded card ships inside a shadow root carrying its own stylesheet,
so neither the origin's CSS nor bagel's can reach the other, and every custom
property is prefixed because those do inherit across the boundary. bagel
appends the widget to the end of the response, so an origin that wants to place
it somewhere specific can put an empty `<div id="bagel-challenge">` in its own
markup and the widget moves there. Either way the page stays usable while the
proof runs and settles in place rather than reloading. The stylesheet is also
served on its own at `/__bagel/static/widget.css`.

The proof itself runs in a wasm module built from the `bagel-solver` crate,
served at `/__bagel/static/solver.wasm` and driven by a short shim at
`/__bagel/static/runtime.mjs`. The page carries only an opaque handoff blob
and the verify URL, and the module unpacks the key and difficulty, searches
nonces, and seals the solution it posts back, so nothing readable on the wire
describes the scheme. Building bagel builds the module too, which needs `lld`
for the `wasm32v1-none` target and shrinks it with `wasm-opt` when binaryen is
available. `BAGEL_SOLVER_WASM` substitutes a prebuilt module instead. An origin
whose Content-Security-Policy lacks `wasm-unsafe-eval` can't run the embedded
`check` widget, and those clients meet the blocking wall on the next gated
request instead.

Bagel runs the pinned Vela checkout after shrinking with a deterministic seed of
zero. Code rewriting starts at `unpack` and `seal` and follows direct calls,
excluding every function reachable from `solve`. The selected functions receive
control-flow flattening, constant rewriting and full direct-call promotion.
In the current module, all their helpers are shared with `solve`, so only the
two entry points are selected. Data encryption still covers the module. The
profile lives in
[crates/bagel-web/solver.rs](crates/bagel-web/solver.rs).

Every build checks the original and rewritten modules against the native solver
through handoff decoding, SHA and scratchpad searches, repeated calls, malformed
lengths and sealed output bytes. Each module gets 20 billion fuel units across
the scenario, 4 MiB of linear memory, 4096 table elements and 4096 captured
memory bytes. Verification runs in a fresh process with a 30-second deadline
and a 1 GiB address-space cap covering parsing, compilation and execution.
A mismatch, trap, failed worker or exhausted budget fails the build, including
when `BAGEL_SOLVER_WASM` supplies the input. The regression check also validates
the served artifact and repeats the workload across four rewrite seeds with
the selected profile and an aggressive profile covering every function.

```sh
nix develop --command cargo test -p bagel-web solver::
```

Two proofs are available. `runtime="pow-sha256"` hashes once per attempt and
`difficulty` defaults to 14. `runtime="pow-scratch"` seeds a scratchpad of
`memory` KiB, a power of two from 64 to 1024 defaulting to 256, walks it in a
data-dependent order and defaults `difficulty` to 10. Every attempt touches the
whole pad, so a batch solver gains little over a browser.

`difficulty` counts leading zero bits of the result for both proofs, so each
extra bit doubles the expected attempts. The two are not comparable at equal
settings, because one scratchpad attempt costs thousands of hashes. Raise either
one against a real browser rather than by arithmetic, since an unsolvable
setting locks every visitor out and looks identical to a slow one.

A `challenge` or `check` rule, or a scorecard threshold, may add
`difficulty=N` to demand more than the challenge's own setting, which is how a
suspicious score buys a harder proof without a second challenge. A pass is
sealed with the difficulty it was verified at, and a gate accepts any pass at
or above the level it asks for.

ACME needs a build with the `bagel-daemon` crate's `acme` feature and a TCP
listener, and an ACME configuration the build can't honor fails validation
rather than falling back to plaintext. Crawler verification by
forward-confirmed reverse DNS needs the `fcrdns` feature, which is on by
default. Turning it off drops the DNS resolver and about 1.3 MB with it, and a
`crawlers` block in such a build fails validation rather than waving every
claimed crawler through as verified. The static `verified-crawlers` ranges work
in either build and need no DNS. Upstream proxy connections are HTTP only for
now, and both binaries parse their command line with Pound rather than Clap.

## Reload and shutdown

SIGHUP reloads the web policy and carries signing keys, rate counters and
poison memory across the reload. Defense configuration and bound
listener or TLS settings need a restart, and a rejected configuration leaves
the running one in place.

Shutdown closes defense record intake first and drains whatever was already
accepted into the queue, with `drain-timeout-secs` still bounding the whole
thing. Records emitted after intake closes are rejected. The queue stays
bounded in normal operation, and any web records it had to drop show up in
`bagel_offenses_total{result="dropped"}`.

## Development

```sh
# Enter the development shell.
$ nix develop

# Run the workspace tests.
$ cargo test --locked --workspace --all-features
$ cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
$ nix flake check
```

The Nix checks build the package and validate the installed example. They also
exercise the NixOS module's maze config check both with and without a
configured key seed. None of them start a service or touch the host firewall.

Formatting needs a nightly `rustfmt`, since `.rustfmt.toml` sets nightly-only
options. The Nix devshell supplies one.

## License

EUPL-1.2, see [LICENSE](LICENSE).
