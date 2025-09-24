{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    haskell-flake.url = "github:srid/haskell-flake";
    hs-wai-csrf.url = "github:k0001/hs-wai-csrf";
    hs-wai-csrf.inputs.nixpkgs.follows = "nixpkgs";
    hs-wai-csrf.inputs.haskell-flake.follows = "haskell-flake";
    hs-wai-csrf.inputs.flake-parts.follows = "flake-parts";
  };
  outputs =
    inputs@{
      self,
      nixpkgs,
      flake-parts,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } (
      { withSystem, ... }:
      let
        # mapListToAttrs f [a b] = {a = f a; b = f b;}
        mapListToAttrs =
          f: xs:
          builtins.listToAttrs (
            builtins.map (x: {
              name = x;
              value = f x;
            }) xs
          );
        ghcVersions = [
          "ghc984"
          "ghc9102"
          "ghc9122"
        ];
      in
      {
        systems = nixpkgs.lib.systems.flakeExposed;
        imports = [
          inputs.haskell-flake.flakeModule
        ];
        flake.haskellFlakeProjectModules = mapListToAttrs (
          ghc:
          (
            { pkgs, lib, ... }:
            withSystem pkgs.system (
              { config, ... }: config.haskellProjects.${ghc}.defaults.projectModules.output
            )
          )
        ) ghcVersions;
        perSystem =
          {
            self',
            pkgs,
            config,
            ...
          }:
          {
            haskellProjects = mapListToAttrs (ghc: {
              basePackages = pkgs.haskell.packages.${ghc};
              settings.wai-cryptocookie = {
                check = true;
                haddock = true;
                libraryProfiling = true;
              };
              packages = {
                #brick.source = "2.9";
                #wai-csrf.source = "${inputs.hs-wai-csrf}/wai-csrf";
              };
              autoWire = [
                "packages"
                "checks"
                "devShells"
              ];
              imports = [
                inputs.hs-wai-csrf.haskellFlakeProjectModules.${ghc}
              ];
              devShell = {
                tools = hp: { inherit (pkgs) cabal2nix; };
              };
            }) ghcVersions;
            packages.default = self'.packages.ghc9122-wai-cryptocookie;
            packages.doc = self'.packages.ghc9122-wai-cryptocookie.doc;
            devShells.default = self'.devShells.ghc9122;
          };
      }
    );
}
