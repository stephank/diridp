{
  outputs = { self }: {
    overlays.default = import ./nix/overlay.nix;
    nixosModules.default = import ./nix/nixosModule.nix;
  };
}
