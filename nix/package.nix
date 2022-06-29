{ lib, stdenv, rustPlatform, CoreServices }:

rustPlatform.buildRustPackage {
  name = "diridp";

  src = ./..;
  cargoLock = {
    lockFile = ./../Cargo.lock;
    outputHashes = {
       "curve25519-dalek-4.0.0-pre.3" = "sha256-d+eETOnLv/n7B1vkarnWQdOUqY3mye1vdKykF9ZoQDc=";
       "ed25519-dalek-1.0.1" = "sha256-xiv7s32OOrExybJTW6Sp6qpzoSYdpn6D5QZIFfk5OIk=";
     };
  };

  buildInputs = lib.optionals stdenv.isDarwin [ CoreServices ];

  # Tests rely on Node.js and additional dependencies.
  # Skip for now an rely on our own CI.
  doCheck = false;
}
