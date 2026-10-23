#!/usr/bin/env bash

set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tauri_manifest="$repo_root/src-tauri/Cargo.toml"

cd "$repo_root"

echo "[target-gates] checking host workspace without optional features"
cargo check --workspace --locked --no-default-features

echo "[target-gates] checking Linux capability feature gates"
cargo check \
  --manifest-path "$tauri_manifest" \
  --lib \
  --locked \
  --no-default-features \
  --features linux-all

for target in aarch64-linux-android x86_64-linux-android; do
  echo "[target-gates] checking Android target: $target"
  cargo check \
    --manifest-path "$tauri_manifest" \
    --lib \
    --locked \
    --no-default-features \
    --target "$target"
done

echo "[target-gates] checking direct dependencies for Linux service-manager coupling"
direct_tree="$(cargo tree \
  --manifest-path "$tauri_manifest" \
  --no-default-features \
  --depth 1)"

for forbidden in systemd libsystemd networkmanager network-manager udev libudev; do
  if [[ "$direct_tree" == *"$forbidden"* ]]; then
    printf 'forbidden direct Linux service dependency found: %s\n' "$forbidden" >&2
    exit 1
  fi
done

echo "[target-gates] passed: target gates and Linux service independence"
