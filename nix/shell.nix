{
  mkShell,
  rustc,
  cargo,
  pkg-config,
  rust-analyzer,
  rustfmt,
  clippy,
  openssl,
}: mkShell {
  name = "eris";

  strictDeps = true;
  nativeBuildInputs = [
    rustc
    cargo
    pkg-config
    rust-analyzer
    rustfmt
    clippy
  ];
  buildInputs = [openssl.dev];
}
