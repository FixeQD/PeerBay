{
  description = "PeerBay, local-first peer-to-peer connectivity for Android, Linux, and Windows";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    crane-tauri.url = "github:JPHutchins/crane-tauri";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      crane-tauri,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        inherit (pkgs) lib;
        craneLib = crane.mkLib pkgs;
        frontendPackage = builtins.fromJSON (builtins.readFile ./package.json);
        tauriManifest = fromTOML (builtins.readFile ./src-tauri/Cargo.toml);
        tauriPackage = tauriManifest.package;

        frontendSrc = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [
            ./package.json
            ./bun.lock
            ./tsconfig.json
            ./vite.config.js
            ./src
            ./static
          ];
        };

        nodeModules = pkgs.stdenvNoCC.mkDerivation {
          pname = "${frontendPackage.name}-node-modules";
          version = frontendPackage.version;
          src = frontendSrc;

          nativeBuildInputs = [
            pkgs.bun
            pkgs.writableTmpDirAsHomeHook
          ];

          dontConfigure = true;
          dontFixup = true;

          buildPhase = ''
            runHook preBuild
            export BUN_INSTALL_CACHE_DIR=$(mktemp -d)
            bun install \
              --frozen-lockfile \
              --ignore-scripts \
              --no-progress \
              --cpu="*" \
              --os="*"
            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall
            mkdir -p "$out"
            cp -R node_modules "$out/node_modules"
            runHook postInstall
          '';

          outputHashMode = "recursive";
          outputHash = "sha256-pGr7PGUH8lhc8t3Thd1tsoLc3G4SN4+MBeQAGHIvzSs=";
        };

        frontend = pkgs.stdenvNoCC.mkDerivation {
          pname = "${frontendPackage.name}-frontend";
          version = frontendPackage.version;
          src = frontendSrc;

          nativeBuildInputs = [
            pkgs.bun
            pkgs.nodejs
          ];
          dontConfigure = true;

          buildPhase = ''
            runHook preBuild
            cp -R ${nodeModules}/node_modules ./node_modules
            chmod -R u+w ./node_modules
            patchShebangs node_modules
            bun run build
            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall
            cp -R build "$out"
            runHook postInstall
          '';
        };

        tauri = crane-tauri.lib.buildTauriApp { inherit pkgs craneLib; } {
          pname = tauriPackage.name;
          version = tauriPackage.version;
          src = ./.;
          inherit frontend;
        };
      in
      {
        packages = {
          inherit frontend;
          default = tauri.app;
          wrapped = tauri.wrappedApp;
        };

        checks = {
          inherit (tauri) app;

          clippy = craneLib.cargoClippy (
            tauri.commonArgs
            // {
              cargoArtifacts = tauri.cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- -D warnings";
              TAURI_CONFIG = tauri.tauriConfig;
            }
          );

          fmt = craneLib.cargoFmt { src = tauri.commonArgs.src; };
        };

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};
        };
      }
    );
}
