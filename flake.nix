{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";

    resume.url = "git+ssh://git@github.com/nevivurn/resume";
    resume.inputs.flake-utils.follows = "flake-utils";
  };

  outputs =
    { self
    , nixpkgs
    , flake-utils
    , resume
    }:
    flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = nixpkgs.legacyPackages.${system};
      resumePDF = "${resume.packages.${system}.default}/resume.pdf";
    in
    {
      devShells.default = pkgs.mkShell {
        inputsFrom = [ self.packages.${system}.default ];
        shellHook = ''
          ln -sf ${resumePDF} static/
        '';
      };
      packages.default =
        let
          npmDeps = pkgs.fetchNpmDeps {
            name = "nevi-dev-npm-deps";
            src = ./.;
            hash = "sha256-397JK00/JbJAUthPiamZKPuLE8l2q4f51B0FwtEE7Pc=";
          };
        in
        pkgs.stdenvNoCC.mkDerivation {
          name = "nevi-dev";
          src = ./.;

          inherit npmDeps;
          passthru = { inherit npmDeps; };

          nativeBuildInputs = with pkgs; [ hugo nodejs npmHooks.npmConfigHook ];

          preBuild = ''
            cp ${resumePDF} static/
          '' + nixpkgs.lib.optionalString (self ? rev) ''
            sed -i 's/build: draft/build: ${builtins.substring 0 7 self.rev}/' config.toml
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
