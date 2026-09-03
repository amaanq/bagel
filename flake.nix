{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs?ref=nixos-unstable";

  outputs = {
    self,
    nixpkgs,
  }: let
    systems = ["x86_64-linux" "aarch64-linux"];
    forEachSystem = nixpkgs.lib.genAttrs systems;
    pkgsForEach = nixpkgs.legacyPackages;
  in {
    nixosModules = {
      eris = ./nix/module.nix;
      default = self.nixosModules.eris;
    };

    packages = forEachSystem (system: {
      eris = pkgsForEach.${system}.callPackage ./nix/package.nix {};
      default = self.packages.${system}.eris;
    });

    devShells = forEachSystem (system: {
      default = pkgsForEach.${system}.callPackage ./nix/shell.nix {};
    });

    checks = forEachSystem (system: {
      eris = self.packages.${system}.eris;
    });

    hydraJobs = self.checks;
  };
}
