# SPDX-License-Identifier: EUPL-1.2

{
  config,
  pkgs,
  lib,
  ...
}:
let
  inherit (lib.lists) optionals;
  inherit (lib.modules) mkDefault mkIf;
  inherit (lib.options) mkEnableOption mkOption mkPackageOption;
  inherit (lib.types)
    enum
    listOf
    nullOr
    path
    str
    ;

  cfg = config.services.bagel;
  checkedConfig = pkgs.runCommand "bagel-config-check" { nativeBuildInputs = [ cfg.package ]; } ''
    bagel-daemon --config ${cfg.configFile} --check-config ${
      lib.optionalString (cfg.keySeedFile != null) "--key-seed placeholder"
    }
    cp ${cfg.configFile} $out
  '';
  enforceRequired = cfg.enforcementMode == "required";
in
{
  options.services.bagel = {
    enable = mkEnableOption "Bagel defense agent";
    package = mkPackageOption pkgs "bagel" { };

    configFile = mkOption {
      type = path;
      description = "Unified KDL file holding the web plane and the defense block";
    };

    keySeedFile = mkOption {
      type = nullOr path;
      default = null;
      description = "File holding the hex PKCS8 key seed, loaded through systemd credentials so it never enters the store";
    };

    enforcementMode = mkOption {
      type = enum [
        "required"
        "observe"
      ];
      default = "required";
      description = "Must match the enforcement node in the defense block of the KDL file, since the module cannot read KDL and only uses this to grant CAP NET ADMIN";
    };

    enforcementTable = mkOption {
      type = str;
      default = "bagel";
      description = "Must match the enforcement node in the defense block of the KDL file, since the module cannot read KDL and only uses this to clean up the nft table on stop";
    };

    logLevel = mkOption {
      type = enum [
        "error"
        "warn"
        "info"
        "debug"
        "trace"
      ];
      default = "info";
      description = "Logging level for the Bagel service.";
    };

    user = mkOption {
      type = str;
      default = "bagel";
      description = "User account under which Bagel runs.";
    };

    group = mkOption {
      type = str;
      default = "bagel";
      description = "Group under which Bagel runs.";
    };

    supplementaryGroups = mkOption {
      type = listOf str;
      default = [ ];
      description = "Groups granting Bagel access to configured event sources.";
    };

    readOnlyPaths = mkOption {
      type = listOf str;
      default = [ ];
      description = "Source paths explicitly exposed through the systemd sandbox.";
    };

    stateDir = mkOption {
      type = path;
      default = "/var/lib/bagel";
      description = "Persistent Bagel state directory.";
    };
  };

  config = mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];
    networking.nftables.enable = mkDefault true;
    users = {
      users = mkIf (cfg.user == "bagel") {
        bagel = {
          isSystemUser = true;
          inherit (cfg) group;
          home = cfg.stateDir;
        };
      };
      groups = mkIf (cfg.group == "bagel") {
        bagel = { };
      };
    };

    systemd.services.bagel = {
      description = "Bagel defense agent";
      wantedBy = [ "multi-user.target" ];
      after = [
        "network.target"
        "nftables.service"
      ];
      wants = [ "nftables.service" ];
      path = [
        pkgs.nftables
        pkgs.systemd
      ];
      restartTriggers = [ checkedConfig ];
      environment = mkIf (cfg.keySeedFile != null) {
        BAGEL_KEY_SEED_FILE = "%d/key-seed";
      };
      serviceConfig = {
        User = cfg.user;
        Group = cfg.group;
        SupplementaryGroups = [ "systemd-journal" ] ++ cfg.supplementaryGroups;
        ExecStart = lib.escapeShellArgs [
          (lib.getExe' cfg.package "bagel-daemon")
          "--config"
          checkedConfig
          "--log-level"
          cfg.logLevel
          "--base-dir"
          cfg.stateDir
        ];
        LoadCredential = optionals (cfg.keySeedFile != null) [ "key-seed:${cfg.keySeedFile}" ];
        ExecStopPost = optionals enforceRequired [
          "-nft delete table inet ${cfg.enforcementTable}"
        ];
        Restart = "on-failure";
        RestartSec = "5s";
        WorkingDirectory = cfg.stateDir;
        LimitNOFILE = 65536;
        LimitNPROC = 1024;
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ReadOnlyPaths = cfg.readOnlyPaths;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectHostname = true;
        ProtectClock = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
          "AF_NETLINK"
        ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ] ++ optionals enforceRequired [ "CAP_NET_ADMIN" ];
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ] ++ optionals enforceRequired [ "CAP_NET_ADMIN" ];
        SystemCallFilter = [
          "@system-service"
          "@network-io"
          "@file-system"
        ];
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RemoveIPC = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        StateDirectory = "bagel";
        CacheDirectory = "bagel";
        RuntimeDirectory = "bagel";
        StateDirectoryMode = "0750";
        CacheDirectoryMode = "0750";
        RuntimeDirectoryMode = "0750";
        StandardOutput = "journal";
        StandardError = "journal";
      };
    };

    assertions = [
      {
        assertion = builtins.match "[A-Za-z0-9_]+" cfg.enforcementTable != null;
        message = "services.bagel.enforcementTable must contain only letters, digits, and underscores";
      }
    ];
  };
}
