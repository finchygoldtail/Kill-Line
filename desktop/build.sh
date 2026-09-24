#!/usr/bin/env bash
# Build the Kill Line desktop app (Linux): .deb and .AppImage.
#
# Prerequisites (Debian/Ubuntu):
#   sudo apt install clang libbpf-dev libwebkit2gtk-4.1-dev libgtk-3-dev \
#        librsvg2-dev libayatana-appindicator3-dev
#   cargo install tauri-cli --version "^2" --locked
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$HERE/.."
TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"

# 1. The engine: the killline CLI, bundled inside the app as a sidecar.
cargo build --release --locked --manifest-path "$ROOT/Cargo.toml" -p killline-cli
mkdir -p "$HERE/src-tauri/binaries"
cp "$ROOT/target/release/killline" "$HERE/src-tauri/binaries/killline-$TRIPLE"

# 2. The app and its installers.
cd "$HERE/src-tauri"
cargo tauri build "$@"
echo
echo "Installers:"
find "$HERE/src-tauri/target/release/bundle" -maxdepth 2 \( -name '*.deb' -o -name '*.AppImage' \) -print
