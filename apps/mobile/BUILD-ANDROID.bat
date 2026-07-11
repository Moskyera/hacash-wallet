@echo off
setlocal
cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File "%~dp0build-android.ps1"
exit /b %ERRORLEVEL%