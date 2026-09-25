# Build the Kill Line desktop app for Windows: NSIS installer and MSI.
#
# Prerequisites: Rust (MSVC toolchain), WebView2 (preinstalled on Windows 10/11),
#   cargo install tauri-cli --version "^2" --locked
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $Here
$Triple = (rustc -vV | Select-String '^host: ').ToString().Substring(6).Trim()

# 1. The engine (killline.exe), bundled with the app as a sidecar.
cargo build --release --locked --manifest-path "$Root\Cargo.toml" -p killline-cli
New-Item -ItemType Directory -Force "$Here\src-tauri\binaries" | Out-Null
Copy-Item "$Root\target\release\killline.exe" "$Here\src-tauri\binaries\killline-$Triple.exe" -Force

# 2. The app and its installers.
Push-Location "$Here\src-tauri"
cargo tauri build @args
Pop-Location
Write-Host ""
Write-Host "Installers:"
Get-ChildItem -Recurse "$Here\src-tauri\target\release\bundle" -Include *.exe,*.msi | ForEach-Object { $_.FullName }
