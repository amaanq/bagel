# eris

Eris is an HTTP proxy and SSH tarpit daemon that delays malicious scanners. It
reads configured evidence sources, applies durable escalation policies, and can
enforce bans through nftables.

## Development

```sh
# Enter the development shell.
$ nix develop

# Run the workspace tests.
$ cargo test --workspace
```
