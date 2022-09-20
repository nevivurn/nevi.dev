{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      devShells.${system}.default = pkgs.callPackage ./shell.nix { };
      packages.${system}.nevi-dev = pkgs.callPackage ./default.nix { };
      defaultPackage.x86_64-linux = self.packages.${system}.nevi-dev;
  };
}
