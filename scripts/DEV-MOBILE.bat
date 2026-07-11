@echo off
setlocal
title Hacash Wallet Mobile - Dev

set "MOBILE_DIR=%~dp0..\apps\mobile"

echo.
echo  Hacash Wallet Mobile (Phase 1)
echo  Desktop preview: yarn tauri dev
echo  Android:         yarn tauri android dev  (requires Android SDK)
echo.

cd /d "%MOBILE_DIR%"
echo Syncing dependencies...
call yarn install

echo Starting mobile shell on http://127.0.0.1:1421 ...
call yarn tauri dev