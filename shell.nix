{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  buildInputs = [
    pkgs.go
    pkgs.docker
    pkgs.gnumake
    pkgs.google-cloud-sdk
  ];
}
