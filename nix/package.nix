{ lib, stdenv, rustPlatform, CoreServices }:

rustPlatform.buildRustPackage {
  name = "diridp";

  src = ./..;
  cargoLock.lockFile = ./../Cargo.lock;

  buildInputs = lib.optionals stdenv.isDarwin [ CoreServices ];
}
