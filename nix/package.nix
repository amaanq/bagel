# SPDX-License-Identifier: EUPL-1.2

{
  lib,
  rustPlatform,
  stdenv,
  pkg-config,
  openssl,
  cacert,
  sqlite,
  clang,
  wild ? null,
}:
let
  cargoTOML = (lib.importTOML ../Cargo.toml).workspace.package;

  # wild + clang are only used on Linux tier-1 arches
  hasWild =
    stdenv.hostPlatform.isLinux && (stdenv.hostPlatform.isx86_64 || stdenv.hostPlatform.isAarch64);
in
rustPlatform.buildRustPackage (finalAttrs: {
  pname = "bagel";
  inherit (cargoTOML) version;

  src =
    let
      fs = lib.fileset;
      s = ../.;
    in
    fs.toSource {
      root = s;
      fileset = fs.unions [
        (s + /crates)
        (s + /contrib)
        (s + /examples/bagel.kdl)
        (s + /Cargo.lock)
        (s + /Cargo.toml)
      ];
    };

  cargoLock.lockFile = ../Cargo.lock;
  cargoTestFlags = [ "--workspace" ];

  strictDeps = true;
  nativeBuildInputs = [
    pkg-config
  ]
  ++ lib.optionals hasWild [
    wild
    clang
  ];
  buildInputs = [
    openssl.dev
    sqlite.dev
  ];

  env = {
    SSL_CERT_FILE = "${cacert}/etc/ssl/certs/ca-bundle.crt";
  }
  // lib.optionalAttrs hasWild {
    RUSTFLAGS = "-Clinker=${clang}/bin/clang -Clink-arg=--ld-path=wild";
  };

  enableParallelBuilding = true;

  postInstall =
    let
      contrib = "${finalAttrs.src}/contrib";
    in
    ''
      install -Dm644 -t $out/share/bagel/corpus ${contrib}/corpus/*.txt
      install -Dm644 -t $out/share/bagel/scripts ${contrib}/rhai/*.rhai
    '';

  meta = {
    description = "Proxy daemon and SSH tarpit for delaying malicious scanners";
    license = lib.licenses.eupl12;
    maintainers = with lib.maintainers; [
      amaanq
      NotAShelf
    ];
    mainProgram = "bagel-daemon";
    platforms = lib.platforms.linux;
  };
})
