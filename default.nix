{ stdenvNoCC, callPackage, nodejs, hugo, ... }:

let
  nodeDependencies = (callPackage ./node.nix { inherit nodejs; }).nodeDependencies;
in
  stdenvNoCC.mkDerivation rec {
    name = "nevi-dev";
    src = ./.;
    nativeBuildInputs = [ nodejs ];

    postPatch = ''
      ln -sf ${nodeDependencies}/lib/node_modules node_modules
    '';

    buildPhase = ''
      runHook preBuild
      ${hugo}/bin/hugo --minify -d $out/public
      runHook postBuild
    '';

    installPhase = "true";
  }
