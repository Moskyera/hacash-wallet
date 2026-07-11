#!/usr/bin/env bash
# Build Hacash Wallet iOS (macOS + Xcode only)
set -euo pipefail
cd "$(dirname "$0")"

echo "Installing JS dependencies..."
yarn install --frozen-lockfile || yarn install

if [ ! -d "src-tauri/gen/apple" ]; then
  echo "Initializing iOS project (first time)..."
  yarn tauri ios init
fi

echo "Building frontend..."
yarn build

echo "Building iOS release..."
yarn tauri ios build

echo "Done. Open Xcode project under src-tauri/gen/apple if needed."