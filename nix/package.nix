{
  lib,
  rustPlatform,
  pkg-config,
  openssl,
}: let
  cargoTOML = (lib.importTOML ../Cargo.toml).workspace.package;
in
  rustPlatform.buildRustPackage (finalAttrs: {
    pname = "eris";
    version = cargoTOML.version;

    src = let
      fs = lib.fileset;
      s = ../.;
    in
      fs.toSource {
        root = s;
        fileset = fs.unions [
          (s + /crates)
          (s + /contrib)
          (s + /Cargo.lock)
          (s + /Cargo.toml)
        ];
      };

    cargoLock.lockFile = "${finalAttrs.src}/Cargo.lock";
    cargoTestFlags = ["--workspace"];

    strictDeps = true;
    nativeBuildInputs = [pkg-config];
    buildInputs = [openssl.dev];

    enableParallelBuilding = true;

    postInstall = let
      contrib = "${finalAttrs.src}/contrib";
    in ''
      install -Dm644 -t $out/share/eris/corpus ${contrib}/corpus/*.txt
      install -Dm644 -t $out/share/eris/scripts ${contrib}/lua/*.lua
    '';

    meta = {
      description = "Proxy daemon and SSH tarpit for delaying malicious scanners";
      license = lib.licenses.mit;
      maintainers = [lib.maintainers.NotAShelf];
      mainProgram = "eris-daemon";
      platforms = lib.platforms.linux;
    };
  })
