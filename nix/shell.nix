# SPDX-License-Identifier: EUPL-1.2

{
  mkShell,
  rustc,
  cargo,
  pkg-config,
  rust-analyzer,
  rustfmt,
  clippy,
  openssl,
  sqlite,
  rustPlatform,
  extraPackages ? [ ],
}:
mkShell {
  name = "bagel";

  strictDeps = true;

  nativeBuildInputs = [
    rustc
    cargo
    pkg-config
    rust-analyzer
    rustfmt
    clippy
  ]
  ++ extraPackages;

  buildInputs = [
    openssl.dev
    sqlite.dev
  ];

  env.RUST_SRC_PATH = "${rustPlatform.rustLibSrc}";
}
