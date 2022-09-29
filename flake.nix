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
          nativeBuildInputs = with pkgs; [ hugo nodejs node2nix ];
        };
      packages.${system}.nevi-dev =
        let
          nodeDependencies = (import ./node.nix { inherit pkgs; }).nodeDependencies;
        in
        pkgs.stdenvNoCC.mkDerivation {
          name = "nevi-dev";
          src = builtins.path { path = ./.; name = "nevi-dev"; };
          nativeBuildInputs = with pkgs; [ nodejs ];

          postPatch = ''
            ln -sf ${nodeDependencies}/lib/node_modules node_modules
          '';

          buildPhase = ''
            runHook preBuild
            ${pkgs.hugo}/bin/hugo --minify -d $out/public
            runHook postBuild
          '';

          installPhase = "true";
        };
      defaultPackage.x86_64-linux = self.packages.${system}.nevi-dev;
    };
}
