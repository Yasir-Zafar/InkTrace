{
  description = "InkTrace - leak tracing with invisible text watermarks";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAllSystems (pkgs:
        let
          python = pkgs.python312.withPackages (ps: with ps; [
            pytest
            pytest-cov
            hypothesis
            flask
          ]);
        in
        {
          default = pkgs.mkShell {
            packages = [
              python
              pkgs.ruff
              pkgs.sqlite
              pkgs.poppler-utils
              pkgs.gh
              pkgs.git
            ];

            shellHook = ''
              export PYTHONPATH="$PWD/src''${PYTHONPATH:+:$PYTHONPATH}"
              echo "inktrace dev shell: $(python --version), ruff $(ruff --version | cut -d' ' -f2), sqlite $(sqlite3 --version | cut -d' ' -f1)"
            '';
          };
        });

      formatter = forAllSystems (pkgs: pkgs.nixpkgs-fmt);
    };
}
