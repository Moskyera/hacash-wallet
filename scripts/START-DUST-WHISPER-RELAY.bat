@echo off
setlocal EnableDelayedExpansion

title DUST Whisper relay

rem ===========================================================================
rem  Starts a DUST Whisper relay: the mailbox the wallet messenger collects
rem  from, and the encrypted submit path that forwards transactions to a
rem  fullnode. One parameter: the fullnode URL this relay forwards to.
rem
rem    START-DUST-WHISPER-RELAY.bat https://nodeapi.example.org
rem
rem  There is no default node URL here on purpose. A wallet compares the node
rem  this relay declares against its own node and refuses to broadcast through
rem  it if they differ, so a guessed default produces a relay that looks online
rem  and blocks every transaction. Chat still works in that state, which makes
rem  it harder to diagnose, not easier.
rem
rem  Everything else is read from the environment:
rem
rem    DUST_WHISPER_LISTEN      host:port to bind     (default 127.0.0.1:8787)
rem                             The desktop wallet auto-starts its own relay
rem                             on that same port by default, so if the wallet
rem                             is open here, this bind fails. Move one of the
rem                             two.
rem    DUST_WHISPER_KEY_FILE    relay X25519 key file
rem                             (default %%USERPROFILE%%\.hacash-dust-whisper\relay.key)
rem    DUST_WHISPER_SECRET_HEX  the key itself, read by the binary; overrides
rem                             the file
rem    DUST_WHISPER_RELAY_BIN   path to the binary
rem    RUST_LOG                 default info. debug logs recipient addresses.
rem
rem  What running this means for the people who use it:
rem  docs\RUNNING-A-RELAY.md, section 6. Read it before you publish the
rem  address.
rem ===========================================================================

set "REPO_ROOT=%~dp0.."
set "NODE_URL=%~1"

if "%NODE_URL%"=="" (
    echo ERROR: no fullnode URL given.
    echo.
    echo   Usage: %~nx0 https://nodeapi.example.org
    echo.
    echo   The relay decrypts transactions submitted to it and posts them to
    echo   one node that you choose. This script will not guess which. It has
    echo   to be the same node the wallets using this relay are configured
    echo   with, or their Privacy screen reports "Broadcast blocked" and
    echo   nobody can tell why.
    echo.
    echo   Running a relay, and what you can see once you do:
    echo   docs\RUNNING-A-RELAY.md
    echo.
    exit /b 1
)

echo %NODE_URL% | findstr /r /i "^https*://" >nul
if errorlevel 1 (
    echo ERROR: node URL must start with http:// or https://, got %NODE_URL%
    exit /b 1
)

set "LISTEN=%DUST_WHISPER_LISTEN%"
if not defined LISTEN set "LISTEN=127.0.0.1:8787"
set "KEY_FILE=%DUST_WHISPER_KEY_FILE%"
if not defined KEY_FILE set "KEY_FILE=%USERPROFILE%\.hacash-dust-whisper\relay.key"
if not defined RUST_LOG set "RUST_LOG=info"

set "RELAY_BIN=%DUST_WHISPER_RELAY_BIN%"
if not defined RELAY_BIN (
    set "RELAY_BIN=%REPO_ROOT%\target\release\dust-whisper-relay.exe"
    if not exist "!RELAY_BIN!" set "RELAY_BIN=%REPO_ROOT%\target\debug\dust-whisper-relay.exe"
)
if not exist "%RELAY_BIN%" (
    rem Naming one path here used to send people looking at a debug build
    rem moments after being told to make a release one. List what was tried.
    if defined DUST_WHISPER_RELAY_BIN (
        echo ERROR: relay binary not found at %RELAY_BIN%
        echo         ^(from DUST_WHISPER_RELAY_BIN^)
    ) else (
        echo ERROR: no relay binary found. Looked for:
        echo         %REPO_ROOT%\target\release\dust-whisper-relay.exe
        echo         %REPO_ROOT%\target\debug\dust-whisper-relay.exe
        echo         CARGO_TARGET_DIR moves these. Set DUST_WHISPER_RELAY_BIN
        echo         if yours is elsewhere.
    )
    echo.
    echo   Build it:
    echo     cargo build -p dust-whisper --features relay --bin dust-whisper-relay --release --locked
    echo.
    echo   The relay feature is off in a default build, so plain 'cargo build'
    echo   does not produce this binary.
    exit /b 1
)

for %%K in ("%KEY_FILE%") do set "KEY_DIR=%%~dpK"
if not exist "%KEY_DIR%" mkdir "%KEY_DIR%"

set "KEY_STATE=existing key"
if not exist "%KEY_FILE%" set "KEY_STATE=none yet, one will be generated"
if defined DUST_WHISPER_SECRET_HEX set "KEY_STATE=from DUST_WHISPER_SECRET_HEX, file ignored"

set "PUBLIC_WARNING="
for /f "tokens=1 delims=:" %%H in ("%LISTEN%") do set "LISTEN_HOST=%%H"
if /i not "%LISTEN_HOST%"=="127.0.0.1" if /i not "%LISTEN_HOST%"=="localhost" set "PUBLIC_WARNING=yes"

echo.
echo  ========================================================================
echo   DUST Whisper relay
echo  ========================================================================
echo.
echo   Listen        : %LISTEN%
echo   Forwards to   : %NODE_URL%
echo   Key file      : %KEY_FILE%
echo   Key           : %KEY_STATE%
echo   RUST_LOG      : %RUST_LOG%
echo.
echo   Two things this relay does, in one process. It holds encrypted chat
echo   envelopes until their recipient collects them, and it decrypts
echo   submitted transactions and posts them to the node above.
echo.
echo   What you will be able to see: both addresses and the timing of every
echo   message, because the envelope carries 'to' and 'from' in clear so the
echo   relay can route on one and check the sender's signature against the
echo   other. Sealed message bodies are closed to you. Bodies sent before the
echo   two wallets had each other's keys are not: their key is derived from
echo   the two addresses that are printed on the envelope. And you decrypt
echo   every transaction submitted through the transaction path in full.
echo.
echo   Undelivered mail is held in memory and nowhere else. Restarting this
echo   process drops it, and neither sender nor recipient is told.
echo.
echo   Running a relay means holding other people's metadata.
echo   docs\RUNNING-A-RELAY.md section 6 says exactly how much, and section 9
echo   is the short list of things that turn a useful relay into a harmful
echo   one.
echo.
echo  ========================================================================
echo.

if defined PUBLIC_WARNING (
    echo   NOTE: binding %LISTEN%. That is not 127.0.0.1 or localhost, so
    echo   treat this listener as reachable by other machines.
    echo.
    echo   Terminate HTTPS in a reverse proxy in front of this. The wallet
    echo   enforces HTTPS for transactions to a non local relay, but the
    echo   messenger path does not check the scheme at all, so a plain http://
    echo   relay URL carries chat across the network with both addresses
    echo   readable by anyone on the path.
    echo.
    echo   Check your proxy access log before you publish the address: the
    echo   inbox challenge carries the recipient address in the query string,
    echo   so a default log records who collected mail and when, in a file
    echo   this relay knows nothing about.
    echo.
)

echo %RUST_LOG% | findstr /i "debug trace" >nul
if not errorlevel 1 (
    echo   NOTE: RUST_LOG is %RUST_LOG%. At debug the request tracing layer
    echo   prints full URIs, and the inbox challenge URI contains a user's
    echo   address. That log is a record of who checked their mail and when.
    echo   Use info unless you are actively debugging, and delete what you
    echo   collected afterwards.
    echo.
)

"%RELAY_BIN%" ^
  --listen %LISTEN% ^
  --node-url "%NODE_URL%" ^
  --key-file "%KEY_FILE%"

exit /b %errorlevel%
