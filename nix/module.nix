{
  config,
  pkgs,
  lib,
  ...
}: let
  inherit (lib.attrsets) filterAttrs mapAttrs mapAttrsToList;
  inherit (lib.lists) all any optionals;
  inherit (lib.modules) mkDefault mkIf;
  inherit (lib.options) literalExpression mkEnableOption mkOption mkPackageOption;
  inherit (lib.strings) hasInfix;
  inherit (lib.types) attrsOf bool enum int listOf nullOr path port str submodule;

  cfg = config.services.eris;
  jsonFormat = pkgs.formats.json {};
  inherit (lib.types.ints) positive unsigned;
  compact = filterAttrs (_: value: value != null);

  listenerType = submodule {
    options = {
      name = mkOption {
        type = str;
        description = "Stable listener name.";
      };

      protocol = mkOption {
        type = enum ["http" "ssh"];
        description = "Protocol spoken by this listener.";
      };

      listenAddress = mkOption {
        type = str;
        description = "Address and port on which the listener accepts connections.";
      };

      enforcementPorts = mkOption {
        type = listOf port;
        default = [];
        description = "Ports blocked by the listener policy after repeated offenses.";
      };

      backendAddress = mkOption {
        type = nullOr str;
        default = null;
        description = "Backend for accepted HTTP traffic.";
      };

      policy = mkOption {
        type = nullOr str;
        default = null;
        description = "Policy which receives offenses when this listener traps a client.";
      };

      maxTarpitConnections = mkOption {
        type = nullOr positive;
        default = null;
        description = "Maximum concurrent tarpits admitted by this listener.";
      };

      minDelayMs = mkOption {
        type = nullOr unsigned;
        default = null;
        description = "Minimum SSH tarpit write delay in milliseconds.";
      };

      maxDelayMs = mkOption {
        type = nullOr unsigned;
        default = null;
        description = "Maximum SSH tarpit write delay in milliseconds.";
      };

      maxTarpitSeconds = mkOption {
        type = nullOr positive;
        default = null;
        description = "Maximum lifetime of one SSH tarpit connection in seconds.";
      };

      lineLength = mkOption {
        type = nullOr positive;
        default = null;
        description = "Length of the synthetic SSH lines sent to a trapped client.";
      };
    };
  };

  sourceType = submodule {
    options = {
      kind = mkOption {
        type = enum ["journal" "file" "address_set" "listener"];
        description = "Input transport for this source.";
      };

      matchGroups = mkOption {
        type = listOf (attrsOf str);
        default = [];
        description = "Journal selectors: objects are ORed and fields in each object are ANDed.";
      };

      path = mkOption {
        type = nullOr path;
        default = null;
        description = "Path read by a file or address-set source.";
      };

      listener = mkOption {
        type = nullOr str;
        default = null;
        description = "Listener represented by a listener source.";
      };

      start = mkOption {
        type = enum ["beginning" "end"];
        default = "end";
        description = "Initial position when no durable checkpoint exists.";
      };

      pollIntervalMs = mkOption {
        type = positive;
        default = 250;
        description = "File polling interval in milliseconds.";
      };

      maxEntryBytes = mkOption {
        type = positive;
        default = 1048576;
        description = "Maximum accepted journal entry size.";
      };

      maxLineBytes = mkOption {
        type = positive;
        default = 1048576;
        description = "Maximum accepted file line size.";
      };
    };
  };

  detectorType = submodule {
    options = {
      kind = mkOption {
        type = enum ["regex" "json"];
        default = "regex";
        description = "Detector implementation.";
      };

      prefilter = mkOption {
        type = nullOr str;
        default = null;
        description = "Regex containing a named `content` capture passed to pattern evaluation.";
      };

      patterns = mkOption {
        type = listOf str;
        default = [];
        description = ''
          Rust regex patterns containing the address capture. An optional
          `attempt_key` capture makes the policy threshold count distinct
          evidence inside its rolling window.
        '';
      };

      contextPatterns = mkOption {
        type = listOf str;
        default = [];
        description = "Keyed multiline regex patterns for correlated journal records.";
      };

      maxContextLines = mkOption {
        type = lib.types.ints.between 0 64;
        default = 0;
        description = "Previous records retained per journal process for context patterns.";
      };

      contextWindowSeconds = mkOption {
        type = positive;
        default = 120;
        description = "Maximum age of keyed multiline detector context.";
      };

      ignorePatterns = mkOption {
        type = listOf str;
        default = [];
        description = "Rust regex patterns which suppress an otherwise matching record.";
      };

      addressCapture = mkOption {
        type = str;
        default = "address";
        description = "Named regex capture containing a literal client address or CIDR.";
      };

      timestampCapture = mkOption {
        type = nullOr str;
        default = null;
        description = "Named regex capture containing the event timestamp.";
      };

      timestampFormat = mkOption {
        type = nullOr str;
        default = null;
        description = ''
          Timestamp format used by the regex or JSON detector: `rfc3339`,
          `unix`, or `strptime:` followed by a Jiff strptime format.
        '';
      };

      equals = mkOption {
        type = attrsOf str;
        default = {};
        description = "JSON pointer to literal-value predicates which must all match.";
      };

      addressPointer = mkOption {
        type = nullOr str;
        default = null;
        description = "JSON pointer containing a literal client address or CIDR.";
      };

      timestampPointer = mkOption {
        type = nullOr str;
        default = null;
        description = "JSON pointer containing the event timestamp.";
      };
    };
  };

  banType = submodule {
    options = {
      durationSeconds = mkOption {
        type = nullOr positive;
        default = 600;
        description = "Base ban duration in seconds; null creates permanent bans.";
      };

      factor = mkOption {
        type = positive;
        default = 4;
        description = "Escalation factor applied after the multiplier sequence.";
      };

      multipliers = mkOption {
        type = listOf positive;
        default = [4 8 16 32 64 128 256 512 1024 2048];
        description = "Multiplier used for each successive ban.";
      };

      jitterSeconds = mkOption {
        type = unsigned;
        default = 720;
        description = "Maximum random duration added to a ban, in seconds.";
      };

      maxDurationSeconds = mkOption {
        type = positive;
        default = 18000000;
        description = "Hard upper bound for the final ban duration.";
      };

      overall = mkOption {
        type = bool;
        default = true;
        description = "Use ban history from every policy when escalating.";
      };
    };
  };

  actionType = submodule {
    options = {
      kind = mkOption {
        type = enum [
          "observe"
          "drop"
          "drop_protocol"
          "drop_all"
          "reject"
          "reject_protocol"
          "reject_all"
          "tarpit_redirect"
        ];
        default = "drop";
        description = "Enforcement applied when the policy bans an address.";
      };

      protocol = mkOption {
        type = enum ["tcp" "udp"];
        default = "tcp";
        description = "Transport protocol constrained by a scoped action.";
      };

      ports = mkOption {
        type = listOf port;
        default = [];
        description = "Ports constrained by a scoped action.";
      };

      listener = mkOption {
        type = nullOr str;
        default = null;
        description = "Tarpit listener receiving redirected connections.";
      };
    };
  };

  policyType = submodule {
    options = {
      source = mkOption {
        type = str;
        description = "Name of the source supplying records to this policy.";
      };

      detector = mkOption {
        type = detectorType;
        description = "Record detector and address extractor.";
      };

      ignoreNetworks = mkOption {
        type = nullOr (listOf str);
        default = null;
        description = "Networks ignored by this policy, or the global default when null.";
      };

      maxAttempts = mkOption {
        type = positive;
        default = 7;
        description = "Matching events required within the rolling window.";
      };

      findtimeSeconds = mkOption {
        type = positive;
        default = 600;
        description = "Exact rolling offense window in seconds.";
      };

      ban = mkOption {
        type = banType;
        default = {};
        description = "Ban duration and escalation policy.";
      };

      action = mkOption {
        type = actionType;
        default = {};
        description = "Network enforcement action.";
      };
    };
  };

  enforcementType = submodule {
    options = {
      mode = mkOption {
        type = enum ["required" "observe"];
        default = "required";
        description = "Whether nftables enforcement is mandatory or disabled.";
      };

      table = mkOption {
        type = str;
        default = "eris";
        description = "Name of the inet nftables table owned by Eris.";
      };

      chainPriority = mkOption {
        type = int;
        default = -10;
        description = "Priority of the Eris input chain.";
      };

      reconcileIntervalSeconds = mkOption {
        type = positive;
        default = 15;
        description = "Interval between desired-state nftables reconciliations.";
      };
    };
  };

  serializeListener = listener:
    compact {
      inherit (listener) name protocol;
      listen_addr = listener.listenAddress;
      backend_addr = listener.backendAddress;
      policy = listener.policy;
      max_tarpit_conns = listener.maxTarpitConnections;
      min_delay_ms = listener.minDelayMs;
      max_delay_ms = listener.maxDelayMs;
      max_tarpit_secs = listener.maxTarpitSeconds;
      line_length = listener.lineLength;
    };

  serializeSource = source:
    if source.kind == "journal"
    then {
      kind = "journal";
      match_groups = source.matchGroups;
      inherit (source) start;
      max_entry_bytes = source.maxEntryBytes;
    }
    else if source.kind == "file"
    then {
      kind = "file";
      inherit (source) path start;
      poll_interval_ms = source.pollIntervalMs;
      max_line_bytes = source.maxLineBytes;
    }
    else if source.kind == "address_set"
    then {
      kind = "address_set";
      inherit (source) path;
    }
    else {
      kind = "listener";
      inherit (source) listener;
    };

  serializeDetector = detector:
    if detector.kind == "regex"
    then
      compact {
        kind = "regex";
        inherit (detector) prefilter patterns;
        context_patterns = detector.contextPatterns;
        max_context_lines = detector.maxContextLines;
        context_window_secs = detector.contextWindowSeconds;
        ignore_patterns = detector.ignorePatterns;
        address_capture = detector.addressCapture;
        timestamp_capture = detector.timestampCapture;
        timestamp_format = detector.timestampFormat;
      }
    else
      compact {
        kind = "json";
        inherit (detector) equals;
        address_pointer = detector.addressPointer;
        timestamp_pointer = detector.timestampPointer;
        timestamp_format = detector.timestampFormat;
      };

  serializeAction = action:
    if builtins.elem action.kind ["observe" "drop_all" "reject_all"]
    then {inherit (action) kind;}
    else if builtins.elem action.kind ["drop_protocol" "reject_protocol"]
    then {inherit (action) kind protocol;}
    else
      compact {
        inherit (action) kind protocol ports listener;
      };

  serializePolicy = policy: {
    inherit (policy) source;
    detector = serializeDetector policy.detector;
    ignore_networks =
      if policy.ignoreNetworks == null
      then cfg.ignoreNetworks
      else policy.ignoreNetworks;
    max_attempts = policy.maxAttempts;
    findtime_secs = policy.findtimeSeconds;
    ban = {
      duration_secs = policy.ban.durationSeconds;
      inherit (policy.ban) factor multipliers overall;
      jitter_secs = policy.ban.jitterSeconds;
      max_duration_secs = policy.ban.maxDurationSeconds;
    };
    action = serializeAction policy.action;
  };

  corporaDir =
    if cfg.corpora == {}
    then "${cfg.package}/share/eris/corpus"
    else "${pkgs.linkFarm "eris-corpora" (mapAttrsToList (name: path: {inherit name path;}) cfg.corpora)}";
  scriptsDir =
    if cfg.luaScripts == {}
    then "${cfg.package}/share/eris/scripts"
    else "${pkgs.linkFarm "eris-scripts" (mapAttrsToList (name: path: {inherit name path;}) cfg.luaScripts)}";

  generatedSettings =
    cfg.settings
    // {
      listeners = map serializeListener cfg.listeners;
      sources = mapAttrs (_: serializeSource) cfg.sources;
      policies = mapAttrs (_: serializePolicy) cfg.policies;
      enforcement = {
        inherit (cfg.enforcement) mode table;
        chain_priority = cfg.enforcement.chainPriority;
        reconcile_interval_secs = cfg.enforcement.reconcileIntervalSeconds;
      };
      database_path = cfg.databasePath;
      history_retention_secs = cfg.historyRetentionSeconds;
      journalctl_path = cfg.journalctlPath;
      nft_path = cfg.nftPath;
      protected_networks = cfg.protectedNetworks;
      admin_socket = "/run/eris/admin.sock";
      corpora_dir = corporaDir;
      scripts_dir = scriptsDir;
      data_dir = cfg.dataDir;
      cache_dir = cfg.cacheDir;
    };

  erisConfigFile = jsonFormat.generate "eris-config.json" generatedSettings;
  listenerNames = map (listener: listener.name) cfg.listeners;
  sourceNames = builtins.attrNames cfg.sources;
  policyNames = builtins.attrNames cfg.policies;
in {
  options.services.eris = {
    enable = mkEnableOption "Eris defense agent";
    package = mkPackageOption pkgs "eris" {};

    listeners = mkOption {
      type = listOf listenerType;
      default = [];
      description = "Typed HTTP and SSH tarpit listeners.";
    };

    sources = mkOption {
      type = attrsOf sourceType;
      default = {};
      description = "Named journal, file, address-set, and listener offense sources.";
    };

    policies = mkOption {
      type = attrsOf policyType;
      default = {};
      description = "Named detection, rolling-window, escalation, and enforcement policies.";
    };

    enforcement = mkOption {
      type = enforcementType;
      default = {};
      description = "nftables ownership and reconciliation policy.";
    };

    ignoreNetworks = mkOption {
      type = listOf str;
      default = [];
      description = "Default automatic-offense exclusions inherited by policies.";
    };

    protectedNetworks = mkOption {
      type = listOf str;
      default = ["127.0.0.0/8" "::1/128"];
      description = "Networks which Eris may never block, including manual forced bans.";
    };

    databasePath = mkOption {
      type = path;
      default = "/var/lib/eris/eris.sqlite3";
      description = "SQLite decision and checkpoint database.";
    };

    historyRetentionSeconds = mkOption {
      type = positive;
      default = 86400;
      description = "Retention window for expired automatic-ban escalation history.";
    };

    journalctlPath = mkOption {
      type = path;
      default = "${pkgs.systemd}/bin/journalctl";
      defaultText = literalExpression ''"$${pkgs.systemd}/bin/journalctl"'';
      description = "Absolute journalctl path used by journal sources.";
    };

    nftPath = mkOption {
      type = path;
      default = "${pkgs.nftables}/bin/nft";
      defaultText = literalExpression ''"$${pkgs.nftables}/bin/nft"'';
      description = "Absolute nft path used by required enforcement.";
    };

    settings = mkOption {
      type = jsonFormat.type;
      default = {};
      description = ''
        Existing HTTP deception, admission, metrics, and rate-limit tunables.
        Sources, policies, enforcement, listeners, and module-owned paths must
        use their typed options instead.
      '';
    };

    logLevel = mkOption {
      type = enum ["error" "warn" "info" "debug" "trace"];
      default = "info";
      description = "Logging level for the Eris service.";
    };

    user = mkOption {
      type = str;
      default = "eris";
      description = "User account under which Eris runs.";
    };

    group = mkOption {
      type = str;
      default = "eris";
      description = "Group under which Eris runs.";
    };

    supplementaryGroups = mkOption {
      type = listOf str;
      default = [];
      description = "Groups granting Eris access to configured event sources.";
    };

    readOnlyPaths = mkOption {
      type = listOf str;
      default = [];
      description = "Source paths explicitly exposed through the systemd sandbox.";
    };

    stateDir = mkOption {
      type = path;
      default = "/var/lib/eris";
      description = "Persistent Eris state directory.";
    };

    cacheDir = mkOption {
      type = path;
      default = "/var/cache/eris";
      description = "Eris cache directory.";
    };

    dataDir = mkOption {
      type = path;
      default = "/var/lib/eris/data";
      description = "Directory containing Eris runtime data.";
    };

    corpora = mkOption {
      type = attrsOf path;
      default = {};
      example = literalExpression ''{"other.txt" = ./my-generic-corpus.txt;}'';
      description = "Tarpit corpus files keyed by packaged filename.";
    };

    luaScripts = mkOption {
      type = attrsOf path;
      default = {};
      example = literalExpression ''{"custom_tokens.lua" = ./custom_tokens.lua;}'';
      description = "Tarpit Lua scripts keyed by filename.";
    };
  };

  config = mkIf cfg.enable {
    environment.systemPackages = [cfg.package];
    networking.nftables.enable = mkDefault true;
    users = {
      users = mkIf (cfg.user == "eris") {
        eris = {
          isSystemUser = true;
          group = cfg.group;
          home = cfg.stateDir;
        };
      };
      groups = mkIf (cfg.group == "eris") {
        eris = {};
      };
    };

    systemd.services.eris = {
      description = "Eris defense agent";
      wantedBy = ["multi-user.target"];
      after = ["network.target" "nftables.service"];
      wants = ["nftables.service"];
      restartTriggers = [erisConfigFile];
      serviceConfig = {
        User = cfg.user;
        Group = cfg.group;
        SupplementaryGroups = ["systemd-journal"] ++ cfg.supplementaryGroups;
        ExecStart = ''
          ${lib.getExe' cfg.package "eris-daemon"} \
            --config-file ${erisConfigFile} \
            --log-level ${cfg.logLevel}
        '';
        ExecStopPost = "-${lib.getExe' pkgs.nftables "nft"} delete table inet ${cfg.enforcement.table}";
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
        RestrictAddressFamilies = ["AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK"];
        CapabilityBoundingSet =
          optionals (cfg.listeners != []) ["CAP_NET_BIND_SERVICE"] ++ ["CAP_NET_ADMIN"];
        AmbientCapabilities =
          optionals (cfg.listeners != []) ["CAP_NET_BIND_SERVICE"] ++ ["CAP_NET_ADMIN"];
        SystemCallFilter = ["@system-service" "@network-io" "@file-system"];
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RemoveIPC = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        StateDirectory = "eris";
        CacheDirectory = "eris";
        RuntimeDirectory = "eris";
        StateDirectoryMode = "0750";
        CacheDirectoryMode = "0750";
        RuntimeDirectoryMode = "0750";
        StandardOutput = "journal";
        StandardError = "journal";
      };
    };

    assertions = [
      {
        assertion = builtins.length listenerNames == builtins.length (lib.lists.unique listenerNames);
        message = "services.eris.listeners must have unique names";
      }
      {
        assertion = builtins.match "[A-Za-z0-9_]+" cfg.enforcement.table != null;
        message = "services.eris.enforcement.table must contain only letters, digits, and underscores";
      }
      {
        assertion = all (policy: builtins.elem policy.source sourceNames) (builtins.attrValues cfg.policies);
        message = "Every services.eris policy must name an existing source";
      }
      {
        assertion =
          all (
            listener: listener.policy == null || builtins.elem listener.policy policyNames
          )
          cfg.listeners;
        message = "Every Eris listener policy must name an existing policy";
      }
      {
        assertion = all (listener: listener.policy == null || listener.enforcementPorts != []) cfg.listeners;
        message = "Every Eris listener policy must define enforcement ports";
      }
      {
        assertion = all (listener:
          listener.policy
          == null
          || (builtins.hasAttr listener.policy cfg.policies
            && (let
              policy = cfg.policies.${listener.policy};
            in
              builtins.hasAttr policy.source cfg.sources
              && (let
                source = cfg.sources.${policy.source};
              in
                source.kind == "listener" && source.listener == listener.name))))
        cfg.listeners;
        message = "Every Eris listener policy must use the source for that listener";
      }
      {
        assertion = all (source:
          source.kind
          == "journal"
          || ((source.kind == "file" || source.kind == "address_set") && source.path != null)
          || (source.kind
            == "listener"
            && source.listener != null
            && builtins.elem source.listener listenerNames)) (builtins.attrValues cfg.sources);
        message = "Eris file/address-set sources require paths and listener sources require existing listeners";
      }
      {
        assertion = all (policy:
          policy.detector.kind
          != "regex"
          || (policy.detector.patterns
            != []
            && all (hasInfix "(?P<${policy.detector.addressCapture}>") policy.detector.patterns))
        (builtins.attrValues cfg.policies);
        message = "Every Eris regex detector pattern must contain its named address capture";
      }
      {
        assertion = all (policy:
          policy.detector.kind
          != "regex"
          || (policy.detector.contextPatterns
            == []
            && policy.detector.maxContextLines == 0)
          || (policy.detector.contextPatterns
            != []
            && policy.detector.maxContextLines > 0
            && all
            (hasInfix "(?P<${policy.detector.addressCapture}>")
            policy.detector.contextPatterns)) (builtins.attrValues cfg.policies);
        message = "Eris context patterns require context lines and the named address capture";
      }
      {
        assertion = all (policy:
          policy.detector.prefilter
          == null
          || hasInfix "(?P<content>" policy.detector.prefilter) (builtins.attrValues cfg.policies);
        message = "Every Eris regex prefilter must contain a named content capture";
      }
      {
        assertion = all (
          policy: policy.detector.kind != "json" || policy.detector.addressPointer != null
        ) (builtins.attrValues cfg.policies);
        message = "Every Eris JSON detector requires addressPointer";
      }
      {
        assertion = all (policy:
          policy.action.kind
          != "tarpit_redirect"
          || (policy.action.listener
            != null
            && policy.action.protocol == "tcp"
            && builtins.elem policy.action.listener listenerNames)) (builtins.attrValues cfg.policies);
        message = "Eris tarpit redirects require an existing TCP listener";
      }
      {
        assertion = all (
          policy: !builtins.elem policy.action.kind ["drop" "reject"] || policy.action.ports != []
        ) (builtins.attrValues cfg.policies);
        message = "Eris scoped drop and reject actions require at least one port";
      }
      {
        assertion =
          !(any (name: builtins.hasAttr name cfg.settings) [
            "listeners"
            "sources"
            "policies"
            "enforcement"
            "database_path"
            "history_retention_secs"
            "journalctl_path"
            "nft_path"
            "protected_networks"
            "enable_firewall"
          ]);
        message = "Use typed services.eris options for listeners, sources, policies, enforcement, and paths";
      }
    ];
  };
}
