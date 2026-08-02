{
  description = "port inspector";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        portinspector = pkgs.buildGoModule {
          pname = "port-inspector";
          version = "0.1.0";
          src = ./.;
          vendorHash = "sha256-/aQNlRqaNaXfc8me8Yh8/y42sG6tQtUuR3hKaQF9kzE=";
          subPackages = [ "." ];
          env.CGO_ENABLED = "0";
          meta.mainProgram = "port-inspector";
        };
      in {
        packages.default = portinspector;
        packages.dashboard = portinspector;
        apps.default = {
          type = "app";
          program = "${portinspector}/bin/port-inspector";
        };
        devShells.default = pkgs.mkShell {
          packages = [ pkgs.go pkgs.gopls ];
        };
      });
}
