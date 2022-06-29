{ lib, pkgs, config, ... }:

with lib;

let

  options = {

    enable = mkEnableOption "diridp";

    # The default package is provided via the overlay in `nixpkgs.overlays`.
    package = mkPackageOption pkgs "diridp" { };

    verbose = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Whether to enable verbose logging.
      '';
    };

    sandbox = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Restrict token paths to `/run/diridp`.

        This option is enabled by default, because it is the recommended
        location for tokens. With this option enabled, diridp will run as a
        separate user `diridp` and have filesystem access restricted.

        Disabling this option can be useful when tokens need to be placed in
        other filesystem locations for compatibility.
      '';
    };

    dirs = mkOption {
      type = types.listOf (types.submodule {
        options = dirOptions;
      });
      default = { };
      description = ''
        Directories to create on service startup.

        This is a simple utility to create directories for containing tokens
        with all the correct permissions. Directories should ideally be
        writable by diridp, and readable by the consuming process only.

        By default, directories are owned by `diridp:root` with `0750`
        permissions. It is recommended to only change the group from these
        defaults.
      '';
    };

    providers = mkOption {
      type = types.attrsOf (types.submodule {
        options = providerOptions;
      });
      default = { };
      description = ''
        Provider configurations.

        Each provider entry defines a unique issuer with its own keys. The name
        of the entry is for logging purposes only.
      '';
    };

  };

  providerOptions = {

    issuer = mkOption {
      type = types.str;
      description = ''
        Issuer for the token `iss` claim and the discovery document.
      '';
      example = "https://example.com";
    };

    vhost.nginx = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Whether to configure an Nginx virtual host.

        Nginx must still be enabled separately via the `services.nginx.enable`
        option.

        The virtual host is configured to automatically request HTTPS
        certificates via Let's Encrypt. See the `security.acme` for settings
        related to this process.

        If special HTTPS configuration is required, or if the virtual host is
        to be shared with other content, use the `vhost.locationsOnly` provider
        option.
      '';
    };

    vhost.locationsOnly = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Whether to configure only locations for the virtual host.

        This option is useful if special HTTPS configuration is required for
        the virtual host, or if sharing the virtual host with other
        configuration. When enabled, only specific locations are defined for
        the diridp files, and nothing else.
      '';
    };

    claims = mkOption {
      type = types.attrs;
      default = { };
      description = ''
        Any additional claims added to all tokens of this provider.

        Note that `iss`, `iat`, `exp` and `nbf` are automatically set.
      '';
      example = literalExpression ''
        {
          # Just an example. It's often more useful to add claims per-token.
          locale = "nl-NL";
        }
      '';
    };

    keys = mkOption {
      type = types.attrsOf (types.submodule {
        options = keyOptions;
      });
      default = { };
      description = ''
        One or more configurations for signing keys.
      '';
    };

    tokens = mkOption {
      type = types.listOf (types.submodule {
        options = tokenOptions;
      });
      default = [ ];
      description = ''
        One or more tokens issued by this provider.
      '';
    };

  };

  keyOptions = {

    alg = mkOption {
      type = types.str;
      description = ''
        Signing algorithm for this key.
      '';
    };

    crv = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        For EdDSA, the curve to use.
      '';
    };

    keySize = mkOption {
      type = types.nullOr types.ints.positive;
      default = null;
      description = ''
        For RSA, the size of the generated keys.
      '';
    };

    dir = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Optional custom path to store keys.
      '';
    };

    lifespan = mkOption {
      type = types.nullOr types.ints.positive;
      default = null;
      description = ''
        Duration in seconds a key is used, before being rotated.
      '';
    };

    publishMargin = mkOption {
      type = types.nullOr types.ints.positive;
      default = null;
      description = ''
        Duration in seconds before and after key lifespan during which the key
        is still announced.
      '';
    };

  };

  tokenOptions = {

    path = mkOption {
      type = types.path;
      description = ''
        Path where to write the token.

        The parent directory MUST already exist. This is a requirement because
        setting correct permissions on the directory is essential for security.
        File permissions on the token itself are NOT preserved when the token
        is rotated.

        Use the `services.diridp.dirs` option to create directories with the
        correct permissions on service start.
      '';
      example = "/run/diridp/my-application/token";
    };

    keyName = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        If multiple keys are configured, which one to use for this token.
      '';
    };

    claims = mkOption {
      type = types.attrs;
      default = { };
      description = ''
        Any additional claims to add to this token.

        Note that `iss`, `iat`, `exp` and `nbf` are automatically set.
      '';
      example = literalExpression ''
        {
          # RECOMMENDED: Clients typically require `sub` and `aud` claims.
          sub = "my-application";
          aud = "some-cloud-service.example.com";
        }
      '';
    };

  };

  dirOptions = {

    path = mkOption {
      type = types.path;
      description = ''
        Path of the directory to create.
      '';
    };

    owner = mkOption {
      type = types.str;
      default = "diridp";
      description = ''
        Sets the owner of the directory.
      '';
    };

    group = mkOption {
      type = types.str;
      default = "root";
      description = ''
        Sets the group of the directory.
      '';
    };

    mode = mkOption {
      type = types.str;
      default = "0750";
      description = ''
        Sets the mode of the directory.
      '';
    };

  };

  cfg = config.services.diridp;

  supportedAlgorithms = [
    "EdDSA"
    "ES256" "ES384"
    "PS256" "PS384" "PS512"
    "RS256" "RS384" "RS512"
  ];

  # Convert a string to snake case.
  # This only covers some of the known inputs in this module.
  toSnakeCase = input: pipe input [
    (builtins.split "([[:upper:]]+)")
    (concatMapStrings (s: if isList s then "_${toLower (head s)}" else s))
  ];

  # Common transformations on an attribute set for our YAML config output.
  prepareConfigSection = attrs: pipe attrs [
    (filterAttrs (name: value: value != null))
    (mapAttrs' (name: nameValuePair (toSnakeCase name)))
  ];

  # Prepare the configuration file and perform checks.
  configFile = (pkgs.formats.yaml { }).generate "diridp.yaml" {
    providers = mapAttrs (name: provider:
      let
        numKeys = length (attrNames provider.keys);
      in prepareConfigSection ({
        inherit (provider) issuer claims;
        keys = mapAttrs (name: key:
          # 'alg' must be one of the supported algorithms.
          assert elem key.alg supportedAlgorithms;
          # 'crv' is required for EdDSA.
          assert key.alg == "EdDSA" -> key.crv != null;
          # 'crv' can only be used with EdDSA.
          assert key.crv != null -> key.alg == "EdDSA";
          # 'keySize' can only be used with the RSA family.
          assert key.keySize != null -> (hasPrefix "RS" key.alg) || (hasPrefix "PS" key.alg);
          prepareConfigSection key
        ) provider.keys;
        tokens = map (token:
          # 'keyName' is required if there are multiple keys.
          assert token.keyName == null -> numKeys == 1;
          # 'keyName' must match a configured key.
          assert token.keyName != null -> hasAttr token.keyName provider.keys;
          prepareConfigSection token
        ) provider.tokens;
      })
    ) cfg.providers;
  };

  # Prepare the startup script that creates directories.
  preStartScript = pkgs.writeShellScript "diridp-dirs" (concatStringsSep "\n" (map (dir: ''
    install -d \
      -o ${escapeShellArg dir.owner} \
      -g ${escapeShellArg dir.group} \
      -m ${escapeShellArg dir.mode} \
      ${escapeShellArg dir.path}
  '') cfg.dirs));

  vhostFromIssuer = issuer:
    let
      vhost = removePrefix "https://" issuer;
    in
      assert hasPrefix "https://" issuer;
      assert !(hasInfix "/" vhost);
      vhost;

in {

  options.services.diridp = options;

  config = {

    nixpkgs.overlays = [
      (import ./overlay.nix)
    ];

    users = mkIf (cfg.enable && cfg.sandbox) {
      groups.diridp = { };
      users.diridp = {
        isSystemUser = true;
        group = "diridp";
      };
    };

    systemd.services.diridp = mkIf cfg.enable {
      description = "diridp";
      after = [ "fs.target" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStartPre = "+${preStartScript}";
        ExecStart = "${cfg.package}/bin/diridp -s"
          + (optionalString cfg.verbose " -v")
          + " ${configFile}";
        Restart = "always";
        RestartSec = 10;

        # Creates `/var/lib/diridp`.
        # This matches the default storage location for keys and web files.
        StateDirectory = "diridp";

        # These all enable additional sandboxing for functionality diridp
        # doesn't use. Notably, it doesn't require any network access at all.
        CapabilityBoundingSet = "";
        IPAddressDeny = "any";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateNetwork = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "noaccess";
        RemoveIPC = true;
        RestrictAddressFamilies = "none";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
        SystemCallErrorNumber = "EPERM";
        SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
      }
        // optionalAttrs cfg.sandbox {
          User = "diridp";
          ProtectHome = true;
          PrivateTmp = true;
          ProtectSystem = "strict";
          RuntimeDirectory = "diridp";
          RuntimeDirectoryPreserve = true;
        };
    };

    services.nginx.virtualHosts = mkIf cfg.enable (
      let
        mkVhost = name: provider:
          let
            locationConfig = {
              root = "/var/lib/diridp/${name}/webroot";
              extraConfig = ''
                types { }
                default_type application/json;
                add_header cache-control "public, max-age=3600, s-maxage=600";
              '';
            };
          in {
            name = vhostFromIssuer provider.issuer;
            value = mkMerge [
              {
                locations."= /.well-known/openid-configuration" = locationConfig;
                locations."= /jwks.json" = locationConfig;
              }
              (mkIf (!provider.vhost.locationsOnly) {
                enableACME = true;
                forceSSL = true;
                locations."/".return = "404";
              })
            ];
        };
        providersWithVhost = filterAttrs
          (name: provider: provider.vhost.nginx)
          cfg.providers;
      in
        mapAttrs' mkVhost providersWithVhost
    );

  };

}
