# diridp on NixOS

Diridp includes a NixOS module that can be imported in e.g. `configuration.nix`
as follows:

```nix
{
  imports =
    let
      diridp = fetchTarball {
        # Modify the version as needed.
        url = "https://github.com/stephank/diridp/archive/v0.2.0.tar.gz";
        # Obtain with: `nix-prefetch-url --unpack <url>`
        sha256 = "008mvkzwbwbqk96fbyy658728i28jgxxmpsbmv2rvbbidznqx2f7";
      };
    in [
      "${diridp}/nix/nixosModule.nix"
    ];
}
```

Or using flakes:

```nix
{
  inputs = {
    diridp.url = "github:stephank/diridp";
  };
  outputs = { self, nixpkgs, diridp }: {
    nixosConfigurations.mymachine = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./mymachine/configuration.nix
        diridp.nixosModules.default
      ];
    };
  };
}
```

NOTE: Binary cache is currently not available. Using this module will build
diridp from source.

## Configuration

An example service configuration:

```nix
{

  services.diridp = {
    enable = true;
    dirs = [
      { path = "/run/diridp/my-application"; group = "myapp"; }
    ];
    providers.main = {
      issuer = "https://example.com";
      vhost.nginx = true;
      keys.main = {
        alg = "EdDSA";
        crv = "Ed25519";
      ];
      tokens = [
        {
          path = "/run/diridp/my-application/token";
          claims = {
            sub = "my-application";
            aud = "some-cloud-service.example.com";
          };
        }
      ];
    };
  };

}
```

Most of the `providers` section matches the regular configuration format.

The `vhost.nginx` option for providers allows configuring a virtual host in
Nginx. The Nginx service must still be enabled by setting
`services.nginx.enable = true`. By default, the vhost is configured to
automatically request certificates via Let's Encrypt. If a custom setup is
required, or if you'd like to serve other content from the same vhost, you may
set `vhost.locationsOnly = true` to only define specific locations for the
files required for diridp, and nothing else.

To help with creating directories with the correct permissions, the `dirs`
option is provided. By default, directories listed here are created at service
start with owner `diridp:root` and permissions `0750`. It is recommended to
only change the group from these defaults.
