@echo off
cd /d "%~dp0.."
gh release create v0.1.28-mobile ^
  --title "Hacash Wallet Mobile v0.1.28" ^
  --notes-file releases\v0.1.28-mobile-release-body.md ^
  --target main ^
  releases\hacash-wallet-mobile-v0.1.28-arm64.apk