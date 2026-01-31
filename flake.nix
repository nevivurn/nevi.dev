{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        runtimeDeps = with pkgs; [
          hugo
          nodejs
        ];
      in
      {
        apps.serve = flake-utils.lib.mkApp {
          drv = pkgs.writeShellApplication {
            name = "hugo-serve";
            runtimeInputs = runtimeDeps;
            text = ''
              npm install
              hugo gen chromastyles --style dracula > assets/highlight-dracula.css
              hugo serve
            '';
          };
        };
        packages.default =
          let
            npmDeps = pkgs.fetchNpmDeps {
              name = "nevi-dev-npm-deps";
              src = ./.;
              hash = "sha256-2fjBRZO42wi6K9AcIDTgsQf4a5gYFTg8shR2Ji1YWxE=";
            };
          in
          pkgs.stdenvNoCC.mkDerivation {
            name = "nevi-dev";
            src = ./.;

            inherit npmDeps;
            nativeBuildInputs = runtimeDeps ++ (with pkgs; [ npmHooks.npmConfigHook ]);

            preBuild = ''
              hugo gen chromastyles --style dracula > assets/highlight-dracula.css
            ''
            + nixpkgs.lib.optionalString (self ? shortRev) ''
              sed -i 's/DRAFT/${self.shortRev}/' config.toml
            '';

            buildPhase = ''
              runHook preBuild
              hugo --minify -d $out/public
              runHook postBuild
            '';
            dontFixup = true; # don't strip CTF challenge binaries etc.
          };
      }
    );
}
