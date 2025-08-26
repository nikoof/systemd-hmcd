{
  description = "High tech AI-powered SaaS file transfer framework for the Brainport Region.";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      devShells.default = pkgs.mkShell {
        packages = with pkgs; [
          gpgme
          valgrind
        ];
      };

      packages.default = pkgs.stdenv.mkDerivation {
        pname = "hmc";
        version = "0.1.0";

        src = ./.;

        buildInputs = [ pkgs.gpgme ];

        buildPhase = ''
          cc -o nob nob.c
          ./nob
        '';

        installPhase = ''
          mkdir -p $out/bin/
          cp ./build/hmc $out/bin
        '';
      };

      defaultApp = flake-utils.lib.mkApp {
        drv = self.packages.${system}.default;
      };
    });
}
