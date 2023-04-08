{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      devShells.${system}.default =
        pkgs.mkShell {
          nativeBuildInputs = with pkgs; [ hugo nodejs ];
        };
      packages.${system}.nevi-dev =
        pkgs.buildNpmPackage {
          name = "nevi-dev";
          src = builtins.path { path = ./.; name = "nevi-dev"; };
          npmDepsHash = "sha256-lLt0Le/DJZcOopLGbtmyKA7MMkrErtByNZXwaO4mhaI=";

          nativeBuildInputs = with pkgs; [ hugo ];

          buildPhase = ''
            runHook preBuild
            hugo --minify -d $out/public
            runHook postBuild
          '';
          installPhase = ''
            runHook preInstall
            #mkdir -p $out
            #cp -r public $out/public
            runHook postInstall
          '';
        };
      defaultPackage.x86_64-linux = self.packages.${system}.nevi-dev;
    };
}
