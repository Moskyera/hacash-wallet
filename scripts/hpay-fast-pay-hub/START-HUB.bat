@echo off
setlocal EnableExtensions

rem  HPAY Fast Pay Hub - Windows launcher.
rem
rem  SECRETS ARE NEVER WRITTEN DOWN HERE, and never printed. The Hub reads its
rem  address and keys from the environment, so this file only checks that they
rem  are present and says which one is missing by NAME. Putting a key in a .bat
rem  puts it in a file, in your shell history, and in every backup of both.

set "HUB_DIR=%~dp0"
set "HUB_EXE=%HUB_DIR%fast-pay-hub.exe"

if not exist "%HUB_EXE%" (
  echo.
  echo   fast-pay-hub.exe is not beside this file.
  echo   Keep START-HUB.bat and fast-pay-hub.exe in the same folder.
  echo.
  exit /b 1
)

set "MISSING="
if "%HACASH_HUB_ADDRESS%"=="" set "MISSING=%MISSING% HACASH_HUB_ADDRESS"
if "%HACASH_HUB_SECRET_HEX%"=="" set "MISSING=%MISSING% HACASH_HUB_SECRET_HEX"
if "%HACASH_HUB_STATE_KEY_HEX%"=="" set "MISSING=%MISSING% HACASH_HUB_STATE_KEY_HEX"
if "%HACASH_HUB_JOURNAL_KEY_HEX%"=="" set "MISSING=%MISSING% HACASH_HUB_JOURNAL_KEY_HEX"

if not "%MISSING%"=="" (
  echo.
  echo   The Hub will not start. These are not set:%MISSING%
  echo.
  echo   Set them for this window only, so they are not stored on disk:
  echo.
  echo       set HACASH_HUB_ADDRESS=your-hub-address
  echo       set HACASH_HUB_SECRET_HEX=...
  echo       set HACASH_HUB_STATE_KEY_HEX=...
  echo       set HACASH_HUB_JOURNAL_KEY_HEX=...
  echo       START-HUB.bat
  echo.
  echo   Use a dedicated, low-balance Hacash address for the Hub. Never the
  echo   address holding your savings.
  echo.
  exit /b 1
)

rem  The node the Hub CALLS, on its own port. The Hub itself listens on 8790,
rem  so the two run side by side on one machine without competing for a port.
if "%HACASH_HUB_NODE_URL%"=="" set "HACASH_HUB_NODE_URL=http://127.0.0.1:8080"
if "%HACASH_HUB_LISTEN%"=="" set "HACASH_HUB_LISTEN=127.0.0.1:8790"

echo.
echo   Hub listening on %HACASH_HUB_LISTEN%
echo   Reading the Hacash node at %HACASH_HUB_NODE_URL%
echo   State file: %HUB_DIR%hub-state.sealed.json
echo.
echo   Keep %HACASH_HUB_LISTEN% private. Publish it only through an HTTPS
echo   reverse proxy, never by opening the port to the internet.
echo.

"%HUB_EXE%" ^
  --listen "%HACASH_HUB_LISTEN%" ^
  --node-url "%HACASH_HUB_NODE_URL%" ^
  --state-file "%HUB_DIR%hub-state.sealed.json"

endlocal
