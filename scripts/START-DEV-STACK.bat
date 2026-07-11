@echo off
setlocal EnableDelayedExpansion

title Hacash Quantum Wallet - Dev Stack

rem Repo layout (sibling fullnode):
rem   ../hacash-fullnodedev/target/debug
rem   ./apps/desktop

set "REPO_ROOT=%~dp0.."
set "NODE_DIR=%REPO_ROOT%..\hacash-fullnodedev\target\debug"
set "WALLET_DIR=%REPO_ROOT%apps\desktop"
set "RPC_URL=http://127.0.0.1:8080"

echo.
echo  ========================================
echo   Hacash Quantum Wallet - Dev Stack
echo  ========================================
echo.
echo  Wallet repo: %REPO_ROOT%
echo  Fullnode:    %NODE_DIR%
echo.

if not exist "%NODE_DIR%\hacash.exe" (
    echo ERROR: hacash.exe not found.
    echo   %NODE_DIR%\hacash.exe
    echo.
    echo Build first:
    echo   cd %REPO_ROOT%..\hacash-fullnodedev
    echo   cargo build
    echo.
    echo Copy hacash.config.ini and poworker.config.ini into target\debug
    pause
    exit /b 1
)

if not exist "%NODE_DIR%\poworker.exe" (
    echo ERROR: poworker.exe not found.
    echo   %NODE_DIR%\poworker.exe
    pause
    exit /b 1
)

if not exist "%NODE_DIR%\hacash.config.ini" (
    echo ERROR: hacash.config.ini missing in %NODE_DIR%
    pause
    exit /b 1
)

if not exist "%NODE_DIR%\poworker.config.ini" (
    echo ERROR: poworker.config.ini missing in %NODE_DIR%
    pause
    exit /b 1
)

if not exist "%WALLET_DIR%\package.json" (
    echo ERROR: wallet app not found in %WALLET_DIR%
    pause
    exit /b 1
)

where yarn >nul 2>&1
if errorlevel 1 (
    echo ERROR: yarn not found in PATH. Install Node.js / Yarn first.
    pause
    exit /b 1
)

echo Stopping stale processes (chain data is kept)...
taskkill /IM hacash.exe /F >nul 2>&1
taskkill /IM poworker.exe /F >nul 2>&1
taskkill /IM hacash-wallet.exe /F >nul 2>&1

for /f "tokens=5" %%P in ('netstat -ano ^| findstr ":1420" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%P >nul 2>&1
)

timeout /t 2 /nobreak >nul

echo [1/4] Starting HACASH fullnode...
start "HACASH-FULLNODE" cmd /k "cd /d %NODE_DIR% && title HACASH-FULLNODE && echo Directory: %NODE_DIR% && echo Node RPC: %RPC_URL% && echo KEEP THIS WINDOW OPEN && echo. && hacash.exe"

echo [2/4] Waiting for node RPC (max 60s)...
set /a tries=0
:waitrpc
set /a tries+=1
if !tries! gtr 60 goto rpcfail
timeout /t 1 /nobreak >nul
powershell -NoProfile -Command "try { Invoke-RestMethod '%RPC_URL%/query/latest' -TimeoutSec 2 | Out-Null; exit 0 } catch { exit 1 }" >nul 2>&1
if errorlevel 1 goto waitrpc
echo       Node RPC ready.

echo [3/5] Starting POWORKER...
start "HACASH-POWORKER" cmd /k "cd /d %NODE_DIR% && title HACASH-POWORKER && echo Directory: %NODE_DIR% && echo KEEP THIS WINDOW OPEN && echo. && poworker.exe"

timeout /t 2 /nobreak >nul

echo [4/5] Starting Fast Pay hub (CSP)...
set "HACASH_HUB_SECRET_ARG="
if defined HACASH_HUB_SECRET_HEX set "HACASH_HUB_SECRET_ARG=--hub-secret-hex %HACASH_HUB_SECRET_HEX%"
if defined HACASH_HUB_ADDRESS (
    start "FAST-PAY-HUB" cmd /k "cd /d %REPO_ROOT% && title FAST-PAY-HUB && echo Directory: %REPO_ROOT% && echo Hub: http://127.0.0.1:8790 && echo KEEP THIS WINDOW OPEN && echo. && cargo run -p l2-fast-pay-hub --features server --bin fast-pay-hub -- --hub-address %HACASH_HUB_ADDRESS% %HACASH_HUB_SECRET_ARG%"
) else (
    echo       SKIP: set HACASH_HUB_ADDRESS=1YourHubAddress to auto-start the CSP hub.
)

timeout /t 2 /nobreak >nul

echo [5/5] Starting Quantum Wallet...
start "QUANTUM-WALLET" cmd /k "cd /d %WALLET_DIR% && title QUANTUM-WALLET && echo Directory: %WALLET_DIR% && echo First start may compile ~30s && echo Use your vault passphrase on Unlock && echo KEEP THIS WINDOW OPEN && echo. && yarn tauri dev"

echo.
echo  ========================================
echo   Launched 4 windows - keep all open
echo  ========================================
echo.
echo   1. HACASH-FULLNODE  ^(hacash.exe^)
echo   2. HACASH-POWORKER  ^(poworker.exe^)
echo   3. FAST-PAY-HUB     ^(http://127.0.0.1:8790^)
echo   4. QUANTUM-WALLET   ^(yarn tauri dev^)
echo.
echo   Node: %RPC_URL%
echo   Hub:  http://127.0.0.1:8790
echo.
echo   Send tab    - legacy L1 fund to quantum address
echo   Quantum tab - Type 4 sends ^(keystore password^)
echo   Air-gap     - Prepare -^> Sign offline -^> Broadcast signed
echo.
pause
exit /b 0

:rpcfail
echo.
echo  Node RPC did not respond in 60 seconds.
echo  Check the HACASH-FULLNODE window for errors.
echo.
pause
exit /b 1