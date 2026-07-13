@echo off
cd /d "%~dp0src-tauri\gen\android"
call gradlew.bat assembleUniversalRelease --no-daemon
exit /b %ERRORLEVEL%