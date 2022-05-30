final: prev: {

  diridp = final.callPackage ./package.nix {
    inherit (final.darwin.apple_sdk.frameworks) CoreServices;
  };

}
