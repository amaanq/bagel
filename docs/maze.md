# Maze design

This is the cryptographic side of mazes, meaning how keys are derived, how a
maze URL is built and checked, and what poison memory records. The operator
view, including renderers, scoring and the config surface, is in
[policy.md](policy.md).

The HKDF domain-separation strings below are frozen constants. Changing any one
of them rotates every derived key, which invalidates all outstanding maze URLs
and challenge cookies and clears poison memory, so bump the `v1` suffix only
when that reset is the intent.

## Root key

The poison master derives from the stable Ed25519 PKCS8 key seed rather than
from an independent secret, so operators manage one secret and rotating it
resets challenge state and maze state together. The input is the decoded PKCS8
DER passed to `StateInner::build_with_seed`, and the construction is
HKDF-SHA256.

```
root_prk = HKDF-Extract(
    salt = "bagel poison root v1",
    ikm = pkcs8_der
)

poison_master = HKDF-Expand(
    root_prk,
    info = frame("master"),
    length = 32
)
```

`frame(value)` means a four-byte unsigned big-endian length followed by the
exact bytes, and every variable-length cryptographic field below uses it.

Reloads keep the already parsed PKCS8 bytes, and a failed reload can't replace
key state. Rotation
invalidates challenge cookies, changes every maze route prefix, invalidates all
outstanding tokens and clears poison memory in one go.

## Key schedule

There's no `site_id`. Deployment separation comes from `poison_master` and
virtual-host separation comes from the canonical host, so two deployments both
using backend `"*"` stay distinct as long as their key seeds differ, and two
that share a seed and a host intentionally share maze identity.

The maze context frames the host and the maze name, and six 32-byte keys come
out of it, one per purpose, none reused for another.

```
maze_context =
    frame(canonical_host) ||
    frame(maze_name)

maze_prk = HKDF-Extract(
    salt = "bagel maze v1",
    ikm = poison_master
)

mac_key     = HKDF-Expand(maze_prk, frame("mac")     || maze_context, 32)
binding_key = HKDF-Expand(maze_prk, frame("binding") || maze_context, 32)
route_key   = HKDF-Expand(maze_prk, frame("route")   || maze_context, 32)
render_key  = HKDF-Expand(maze_prk, frame("render")  || maze_context, 32)
decoy_key   = HKDF-Expand(maze_prk, frame("decoy")   || maze_context, 32)
memory_key  = HKDF-Expand(maze_prk, frame("memory")  || maze_context, 32)
```

## Route prefix

The route prefix is the first 96 bits of `route_key` in lowercase Base32,
which comes to exactly 20 characters over `a-z2-7`. Every letter in a minted
maze URL is lowercase by construction, so a case-folding intermediary can't
break one.

```
route_prefix = base32lower_no_pad(route_key[0..12])
```

A maze URL path looks like this.

```
/<route_prefix>/<token>/<maze_path>
```

The route occupies the derived root path for that host, and a recognized route
wins over an origin path that happens to match it. An unknown first segment
falls into the ordinary request pipeline.

Route collisions among configured mazes are checked at load time for exact
backend hosts. Hosts accepted through wildcard backends are checked when their
per-host maze table is first built, and a colliding host is refused and logged
rather than having one maze picked for it arbitrarily.

## Source binding

Token binding and poison memory identify a client by its source network, the
containing /24 for IPv4 and /64 for IPv6, rather than by raw address, so an
IPv6 privacy address rotating inside one /64 doesn't turn a normal return into
a transfer.

```
ipv4_prefix = 0x04 || 0x18 || four_masked_address_bytes
ipv6_prefix = 0x06 || 0x40 || sixteen_masked_address_bytes
```

Which address counts as the client follows the trusted proxy and PROXY protocol
rules, and an untrusted forwarding header never supplies token identity.

## Token format

A token is a fixed 58-byte structure.

| Field   | Size     |
| ------- | -------- |
| version | 1 byte   |
| flags   | 1 byte   |
| expires | 8 bytes  |
| nonce   | 16 bytes |
| binding | 16 bytes |
| tag     | 16 bytes |

`version` is 1. Bit zero of `flags` means a source binding is present and every
other bit must be zero. `expires` is an unsigned big-endian Unix timestamp in
seconds, and `nonce` comes from a cryptographically secure source and is fresh
for every minted link.

When a source network resolved, the binding covers it and flag bit zero is set.

```
binding = HMAC-SHA256(
    binding_key,
    frame("bagel maze binding v1") ||
    frame(source_network_binary)
)[0..16]
```

Without one, flag bit zero is clear and `binding` is sixteen zero bytes, and
such a token can never produce `poison["returned"]`.

The tag covers the header before `tag` together with the normalized maze path,
so one token can't authorize attacker-chosen path content.

```
tag = HMAC-SHA256(
    mac_key,
    frame("bagel maze token v1") ||
    header_without_tag ||
    frame(maze_path)
)[0..16]
```

All 58 bytes are encoded as canonical lowercase RFC 4648 Base32 without
padding, which makes the token exactly 93 characters over `a-z2-7`. Decoding is
strict, because a token that round-trips through a lenient decoder is a second
valid spelling of the same token.

- Exact length of 93 characters
- Lowercase alphabet only
- No padding
- Exactly 58 decoded bytes
- Zero unused bits in the final Base32 symbol
- Re-encoding produces the exact input

The default lifetime is 24 hours, and a configured lifetime has to fall between
60 seconds and seven days. Tokens are stateless, so exact replay is allowed
until expiry.

## Path grammar

Validation runs on the raw URI path and never percent-decodes it. The path
after the token is bounded on every axis.

- Between 1 and 192 ASCII bytes
- Between 1 and 8 segments
- Each segment between 1 and 32 bytes
- Only lowercase letters, digits, and hyphens within a segment
- No empty segments
- No `.` or `..`
- No percent signs
- No backslashes
- No control bytes

One trailing slash is stripped before verification, the minter never emits
one, and two or more are malformed. Query strings are ignored entirely, so they
never enter the MAC, render seed, generated links, cache keys, poison memory or
scorecard context for maze handling, and the minter never emits one. Logs may
record only that a query was present and how long it was.

## Validation

Validation runs in a fixed order, and expiry is decided before binding.

1. Recognize the route prefix
2. Parse and normalize the maze path
3. Decode canonical lowercase Base32
4. Check the exact token length, version, and flags
5. Recalculate and compare the tag in constant time
6. Check expiry
7. Check the source binding
8. Classify the request

The classification is one of six outcomes. `valid_return` means a valid tag,
unexpired, bound, and matching the current source network. `transfer` means a
valid tag and active lifetime but a binding that doesn't match. `unbound` means
a valid tag and active lifetime with no binding at all. `expired` means the tag
is valid but the lifetime has passed. `invalid` means the structure was good
enough to authenticate but the tag is wrong, and `malformed` means path
parsing, Base32 decoding, length, version or flag validation failed before it
got that far. None of the last five ever receives a newly valid token.

## Response behavior

| Input                                 | Renderer mode | Generated links        | Poison memory |
| ------------------------------------- | ------------- | ---------------------- | ------------- |
| Initial tarpit with source network    | Authenticated | Valid and source-bound | Unchanged     |
| Initial tarpit without source network | Decoy         | Deliberately invalid   | Unchanged     |
| valid_return                          | Authenticated | Valid and source-bound | Set           |
| transfer                              | Decoy         | Deliberately invalid   | Unchanged     |
| unbound                               | Decoy         | Deliberately invalid   | Unchanged     |
| expired                               | Decoy         | Deliberately invalid   | Unchanged     |
| invalid                               | Decoy         | Deliberately invalid   | Unchanged     |
| malformed                             | Decoy         | Deliberately invalid   | Unchanged     |

A recognized route prefix with a missing token or path segment is malformed and
renders a decoy. It never returns 404 and never falls through to the ordinary
pipeline. Maze routes accept GET and HEAD only, any other method renders a
decoy rather than a distinguishable error, and HEAD sends the same headers as
GET with no body.

Decoy links use structurally canonical lowercase tokens with a deliberately
wrong MAC. The minter computes the correct tag, flips one bit of it, then
encodes, so rejection doesn't rest on a probabilistic collision argument. A
decoy response also never binds itself to the current requester, because
otherwise the next hop would become a `valid_return` and poison evidence would
be self-fulfilling.

All maze responses use HTTP 200 and the same envelope, which means
`text/html; charset=utf-8`, `Cache-Control: no-store`,
`Referrer-Policy: no-referrer`, no cookies, no redirects, no origin content,
and no reflected query values or client headers.

## Built-in renderer

The built-in renderer is the sustained-traffic engine and the default. Each
page is bounded on size and content, with between 8 and 16 links, between 8
KiB and 32 KiB of HTML, deterministically generated prose from a bundled word
corpus, escaped text and attributes, only Bagel-generated maze links, and
nothing from request headers, cookies, query content or the origin response.

A deterministic cryptographic PRNG drives generation, seeded from `render_key`
for authenticated pages and `decoy_key` for decoys. Both seeds are uniformly
distributed and feed the same algorithm, so authenticated and decoy pages share
one distribution for body size, word count, link count, link placement and
markup shape, and authentication state only changes whether the generated links
carry valid tags. CPU and allocation stay bounded by the configured maximum
body and link counts.

## Poison memory

Poison memory records a cryptographically valid maze return from the same
source network. The memory key contains only these values, so JA4 and user
agent are deliberately excluded and rotating either doesn't evade memory after
a valid bound return.

```
memory_input =
    frame(canonical_host) ||
    frame(maze_name) ||
    frame(source_network_binary)

memory_id = HMAC-SHA256(
    memory_key,
    frame("bagel poison memory v1") ||
    memory_input
)
```

Memory is set only for `valid_return`. The default TTL is one hour and is
configurable per maze, and storage is process-local with bounded decay. It
survives a config reload when the key seed, canonical host, maze name and
relevant maze settings remain unchanged, and resets on restart, key rotation,
maze rename or a changed TTL.

Normal scorecard evaluation sees one boolean, `poison["returned"]`, which is
true when any configured maze for the current canonical host holds an active
entry for the current source network. Since the binding identifies a source
network rather than an individual, Bagel applies no automatic action on it and
leaves the weight and thresholds to the operator.
