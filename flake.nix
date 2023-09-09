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
      resumeVersion = resume.shortRev;
    in
    {
      devShells.default = pkgs.mkShell {
        inputsFrom = [ self.packages.${system}.default ];
        shellHook = ''
          hugo gen chromastyles --style dracula > assets/highlight-dracula.css
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
            hugo gen chromastyles --style dracula > assets/highlight-dracula.css
            cp ${resumePDF} 'static/Yongun_Seong_resume-${resumeVersion}.pdf'
            sed -i 's/resume\.pdf/Yongun_Seong_resume-${resumeVersion}\.pdf/' config.toml
          '' + nixpkgs.lib.optionalString (self ? rev) ''
            sed -i 's/DRAFT/${builtins.substring 0 7 self.rev}/' config.toml
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
