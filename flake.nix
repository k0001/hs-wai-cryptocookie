{
  description = "Haskell 'wai-session-cookie' library";

  inputs = {
    flakety.url = "github:k0001/flakety/8f037523671a95a77a56a9ef6e87891466312a6a";
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
                  wai-session-cookie =
                    hsClean (hself.callPackage ./wai-session-cookie { });
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
          #wai-session-cookie__ghc96 =
          #  pkgs.haskell.packages.ghc96.wai-session-cookie;
          wai-session-cookie__ghc98 =
            pkgs.haskell.packages.ghc98.wai-session-cookie;
          default = pkgs.releaseTools.aggregate {
            name = "every output from this flake";
            constituents = [
              #config.packages.wai-session-cookie__ghc96
              #config.packages.wai-session-cookie__ghc96.doc
              #config.devShells.ghc96
              config.packages.wai-session-cookie__ghc98
              config.packages.wai-session-cookie__ghc98.doc
              config.devShells.ghc98
            ];
          };
        };
        devShells = let
          mkShellFor = ghc:
            ghc.shellFor {
              packages = p: [ p.wai-session-cookie ];
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
