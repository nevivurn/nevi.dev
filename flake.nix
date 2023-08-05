{
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system}; in
      {
        packages.default =
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
              hash = "sha256-397JK00/JbJAUthPiamZKPuLE8l2q4f51B0FwtEE7Pc=";
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
      }
    );
}
