# SPDX-License-Identifier: EUPL-1.2

{
  pkgs,
  package,
}:
let
  mazeConfig = pkgs.writeText "bagel-maze.kdl" /* kdl */ ''
    backends { backend "example.test" { url "http://127.0.0.1:8081" } }
    policy { mazes { maze "default" { } } }
    defense { enforcement mode="observe" }
  '';
  checkedConfig =
    keySeedFile:
    let
      evaluated = import (pkgs.path + /nixos/lib/eval-config.nix) {
        inherit (pkgs.stdenv.hostPlatform) system;
        modules = [
          ./module.nix
          {
            services.bagel = {
              enable = true;
              inherit package keySeedFile;
              configFile = mazeConfig;
              enforcementMode = "observe";
            };
            system.stateVersion = "26.05";
          }
        ];
      };
    in
    builtins.head evaluated.config.systemd.services.bagel.restartTriggers;
in
{
  config-maze = checkedConfig "/run/keys/bagel";
  config-maze-without-seed = pkgs.testers.testBuildFailure' {
    drv = checkedConfig null;
    expectedBuilderLogEntries = [ "maze support requires a persistent key seed" ];
  };
  config-example =
    pkgs.runCommand "bagel-config-example"
      {
        nativeBuildInputs = [ package ];
      }
      ''
        bagel config example > "$out"
        cmp ${../examples/bagel.kdl} "$out"
        bagel-daemon --config "$out" --check-config
      '';
}
