@echo off
cd /d "%~dp0"
yarn tauri:android:build
exit /b %ERRORLEVEL%