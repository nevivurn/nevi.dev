{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      packages.${system}.default =
        pkgs.buildNpmPackage {
          name = "nevi-dev";
          src = builtins.path { path = ./.; name = "nevi-dev"; };
          npmDepsHash = "sha256-mhib/0WJE3EfXvfiaWEDiwfPYoVTfzH0AWBVWhRy5M8=";

          nativeBuildInputs = with pkgs; [ hugo ];

          buildPhase = ''
            runHook preBuild
            hugo --minify -d $out/public
            runHook postBuild
          '';
          dontNpmInstall = true;
          dontFixup = true; # don't fixup CTF challenge binaries etc.
        };
    };
}
