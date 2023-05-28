{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      packages.${system}.default =
        let
          npmDeps = pkgs.fetchNpmDeps {
            name = "nevi-dev-npm-deps";
            src = builtins.path {
              path = ./.;
              name = "nevi-dev";
              filter = _p: _:
                let p = builtins.baseNameOf _p; in
                p == "package.json" || p == "package-lock.json";
            };

            hash = "sha256-0xI3UQE25nUQI4g+a+hs7O5miqUhvFQDUiohjarFJEY=";
          };
        in

        pkgs.stdenvNoCC.mkDerivation {
          name = "nevi-dev";
          src = builtins.path { path = ./.; name = "nevi-dev"; };

          inherit npmDeps;
          passthru = { inherit npmDeps; };

          nativeBuildInputs = with pkgs; [ hugo nodejs npmHooks.npmConfigHook ];

          buildPhase = ''
            runHook preBuild
            hugo --minify -d $out/public
            runHook postBuild
          '';
          dontFixup = true; # don't fixup CTF challenge binaries etc.
        };
    };
}
