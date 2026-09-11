# SPDX-License-Identifier: EUPL-1.2

{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs?ref=nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, ... }@inputs:
    let
      inherit (inputs) nixpkgs fenix;
      inherit (nixpkgs) lib;
      forAllSystems = lib.genAttrs (lib.systems.doubles.linux ++ lib.systems.doubles.darwin);
      pkgsFor = system: nixpkgs.legacyPackages.${system} or (import nixpkgs { inherit system; });

      rustfmtFor = pkgs: system: fenix.packages.${system}.latest.rustfmt or pkgs.rustfmt;

      # wild + clang are only used on Linux tier-1 arches
      hasWild = plat: plat.isLinux && (plat.isx86_64 || plat.isAarch64);

      nativeDeps =
        pkgs:
        lib.optionals (hasWild pkgs.stdenv.hostPlatform) [
          pkgs.wild
          pkgs.clang
        ];
    in
    {
      nixosModules = {
        bagel = ./nix/module.nix;
        default = self.nixosModules.bagel;
      };

      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          bagel = pkgs.callPackage ./nix/package.nix { };
        in
        {
          inherit bagel;
          default = bagel;
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.callPackage ./nix/shell.nix {
            rustfmt = rustfmtFor pkgs system;
            extraPackages = nativeDeps pkgs;
          };
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          package = self.packages.${system}.bagel;
        in
        { bagel = package; } // import ./nix/checks.nix { inherit pkgs package; }
      );
    };
}
