@echo off
cd /d "%~dp0.."
gh release create v0.1.16-mobile ^
  --title "Hacash Wallet Mobile v0.1.16" ^
  --notes-file releases\v0.1.16-mobile-release-body.md ^
  --target main ^
  releases\hacash-wallet-mobile-v0.1.16-arm64.apk