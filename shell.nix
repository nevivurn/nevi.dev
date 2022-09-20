{ mkShell, hugo, nodejs, node2nix, ... }:

mkShell {
  nativeBuildInputs = [ hugo nodejs node2nix ];
}
