{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";

    resume.url = "git+ssh://git@github.com/nevivurn/resume";
    resume.inputs.flake-utils.follows = "flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, resume }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        runtimeDeps = with pkgs; [ hugo nodejs ];
        resumePDF = "${resume.packages.${system}.default}/resume.pdf";
        resumeVersion = resume.shortRev;
      in {
        apps.serve = flake-utils.lib.mkApp {
          drv = pkgs.writeShellApplication {
            name = "hugo-serve";
            runtimeInputs = runtimeDeps;
            text = ''
              npm install
              hugo gen chromastyles --style dracula > assets/highlight-dracula.css
              ln -sf ${resumePDF} static/
              hugo serve
            '';
          };
        };
        packages.default = let
          npmDeps = pkgs.fetchNpmDeps {
            name = "nevi-dev-npm-deps";
            src = ./.;
            hash = "sha256-RD+iyBjBcI9bIafZIbfXSLVLv9qLrugoOQ08UWA7GM4=";
          };
        in pkgs.stdenvNoCC.mkDerivation {
          name = "nevi-dev";
          src = ./.;

          inherit npmDeps;
          passthru = { inherit npmDeps; };

          nativeBuildInputs = runtimeDeps
            ++ (with pkgs; [ npmHooks.npmConfigHook ]);

          preBuild = ''
            hugo gen chromastyles --style dracula > assets/highlight-dracula.css
            cp ${resumePDF} 'static/Yongun_Seong_resume-${resumeVersion}.pdf'
            sed -i 's/resume\.pdf/Yongun_Seong_resume-${resumeVersion}\.pdf/' config.toml
          '' + nixpkgs.lib.optionalString (self ? shortRev) ''
            sed -i 's/DRAFT/${self.shortRev}/' config.toml
          '';

          buildPhase = ''
            runHook preBuild
            hugo --minify -d $out/public
            runHook postBuild
          '';
          dontFixup = true; # don't strip CTF challenge binaries etc.
        };
      });
}
