{
  description = "Haskell 'wai-cryptocookie' library";

  inputs = {
    flakety.url = "github:k0001/flakety/e59d1244867cb95a7bf052e29ed569419c31914d";
    nixpkgs.follows = "flakety/nixpkgs";
    flake-parts.follows = "flakety/flake-parts";
  };

  outputs = inputs@{ ... }:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      flake.overlays.default = inputs.nixpkgs.lib.composeManyExtensions [
        inputs.flakety.overlays.default
        (final: prev:
          let
            hsLib = prev.haskell.lib;
            hsClean = drv:
              hsLib.overrideCabal drv
              (old: { src = prev.lib.sources.cleanSource old.src; });
          in {
            haskell = prev.haskell // {
              packageOverrides = prev.lib.composeExtensions
                (prev.haskell.packageOverrides or (_: _: { })) (hself: hsuper: {
                  wai-cryptocookie =
                    hsClean (hself.callPackage ./wai-cryptocookie { });
                });
            };
          })
      ];
      systems = [ "x86_64-linux" "i686-linux" "aarch64-linux" ];
      perSystem = { config, pkgs, system, ... }: {
        _module.args.pkgs = import inputs.nixpkgs {
          inherit system;
          overlays = [ inputs.self.overlays.default ];
        };
        packages = {
          #wai-cryptocookie__ghc96 =
          #  pkgs.haskell.packages.ghc96.wai-cryptocookie;
          wai-cryptocookie__ghc98 =
            pkgs.haskell.packages.ghc98.wai-cryptocookie;
          default = pkgs.releaseTools.aggregate {
            name = "every output from this flake";
            constituents = [
              #config.packages.wai-cryptocookie__ghc96
              #config.packages.wai-cryptocookie__ghc96.doc
              #config.devShells.ghc96
              config.packages.wai-cryptocookie__ghc98
              config.packages.wai-cryptocookie__ghc98.doc
              config.devShells.ghc98
            ];
          };
        };
        devShells = let
          mkShellFor = ghc:
            ghc.shellFor {
              packages = p: [ p.wai-cryptocookie ];
              withHoogle = true;
              nativeBuildInputs =
                [ pkgs.cabal-install pkgs.cabal2nix pkgs.ghcid ];
            };
        in {
          default = config.devShells.ghc98;
          #ghc96 = mkShellFor pkgs.haskell.packages.ghc96;
          ghc98 = mkShellFor pkgs.haskell.packages.ghc98;
        };
      };
    };
}
