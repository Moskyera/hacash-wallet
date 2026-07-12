@echo off
cd /d "%~dp0.."
gh release create v0.1.28-desktop ^
  --title "Hacash Wallet Desktop v0.1.28" ^
  --notes-file releases\v0.1.28-desktop-release-body.md ^
  --target main ^
  releases\hacash-wallet-desktop-v0.1.28-x64-setup.exe ^
  releases\hacash-wallet-desktop-v0.1.28-x64.msi ^
  releases\hacash-wallet-desktop-v0.1.28-x64-portable.exe