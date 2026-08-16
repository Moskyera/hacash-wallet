@echo off
setlocal EnableDelayedExpansion

title DEV ONLY - Hub and witness on ONE host - NOT AN ANCHOR

rem ===========================================================================
rem  Local development only. Starts the Fast Pay Hub and a rollback-anchor
rem  witness together on this one machine.
rem
rem  This is the configuration ADR-001 calls Option B, and Option B defends
rem  against nothing. It exists because local development and the Local Pilot
rem  need a witness to talk to, not because it makes anything safer.
rem
rem  Production: scripts\START-HUB-WITH-REMOTE-WITNESS.bat
rem  Operator guide for a real witness: docs\l2\RUNNING-A-WITNESS.md
rem ===========================================================================

set "REPO_ROOT=%~dp0.."
set "DEV_DIR=%REPO_ROOT%\.dev-anchor"
set "WITNESS_LISTEN=127.0.0.1:8791"
set "WITNESS_URL=http://127.0.0.1:8791"
set "HUB_LISTEN=127.0.0.1:8790"
set "NODE_URL=http://127.0.0.1:8080"
set "WITNESS_ID=dev-local-witness"
set "STORE_FILE=%DEV_DIR%\witness-store.log"
set "ATTESTATION_FILE=%DEV_DIR%\dev-attestation.json"
set "ATTEST_LOG=%DEV_DIR%\dev-attestation.stderr"
set "INSTANCE_LOG=%DEV_DIR%\witness-instance.out"
set "INSTANCE_ERR=%DEV_DIR%\witness-instance.err"
set "RUN_WITNESS_BAT=%DEV_DIR%\run-dev-witness.bat"
set "RUN_HUB_BAT=%DEV_DIR%\run-dev-hub.bat"
set "HUB_STATE_FILE=%DEV_DIR%\dev-hub-state.json"

rem Well-known, worthless development keys. They are written down in a script in
rem a public repository on purpose: nothing that uses them may ever hold value.
set "WITNESS_RECEIPT_SECRET=hpay-dev-witness-receipt-key-do-not-use-anywhere-real"
set "WITNESS_AUTHORISATION_SECRET=hpay-dev-witness-authorisation-key-do-not-use-anywhere-real"

echo.
echo  ###########################################################################
echo  #                                                                         #
echo  #   DEVELOPMENT CONFIGURATION - THE ROLLBACK ANCHOR DOES NOT COUNT HERE   #
echo  #                                                                         #
echo  ###########################################################################
echo.
echo   The witness you are about to start runs on THIS machine, writes its
echo   counter to THIS filesystem, and is in THIS machine's backup set.
echo.
echo   That means it goes backwards exactly when the Hub goes backwards.
echo   Restore this box from an image taken an hour ago and the Hub's state and
echo   the witness's counter both come back at the older position, agreeing with
echo   each other perfectly. Every signature verifies. Every check passes. The
echo   Hub will happily co-sign a bill serial it has already co-signed, with
echo   different balances, and nothing in this configuration will notice.
echo.
echo   That is the entire failure the anchor exists to prevent, and this
echo   configuration does not prevent it. ADR-001 calls this Option B and
echo   rejected it. It is here because local development needs a witness to
echo   talk to, and for no other reason.
echo.
echo   What you DO get here: the wire protocol, the receipts, the refusals, the
echo   startup probe and the recovery drills, all real and all exercisable.
echo   What you DO NOT get: an anchor.
echo.
echo   The Hub will publish this honestly. In the rollback_anchor object on
echo   /v1/readiness/mainnet you will see
echo     witness_endpoint_posture        : same_host_or_plaintext
echo     witness_endpoint_is_local       : true
echo     witness_store_in_hub_state_tree : true
echo     witness_co_located              : true
echo     witness_operator                : LOCAL-DEV-NO-SEPARATION
echo   On a mainnet profile the Hub refuses to start in this shape at all. It
echo   starts here only because this is the development profile. If you ever
echo   see that operator string, or witness_co_located true, on a machine
echo   holding real value, that Hub has no anchor and somebody must be told.
echo.
echo   Real deployment: docs\l2\RUNNING-A-WITNESS.md
echo   Production launcher: scripts\START-HUB-WITH-REMOTE-WITNESS.bat
echo.
echo  ###########################################################################
echo.

where cargo >nul 2>&1
if errorlevel 1 (
    echo ERROR: cargo not found in PATH. Install the Rust toolchain first.
    pause
    exit /b 1
)

if not defined HACASH_HUB_ADDRESS (
    echo ERROR: HACASH_HUB_ADDRESS is not set.
    echo.
    echo   The witness's deployment attestation is bound to one exact Hub
    echo   identity, so the Hub address has to be known before anything starts.
    echo.
    echo   set HACASH_HUB_ADDRESS=1YourDevHubAddress
    echo   set HACASH_HUB_SECRET_HEX=your64characterdevprivatekey
    echo.
    pause
    exit /b 1
)
if not defined HACASH_HUB_SECRET_HEX (
    echo ERROR: HACASH_HUB_SECRET_HEX is not set.
    echo   The rollback anchor binds the key that signs bills, so the Hub needs
    echo   its signer before the anchor can be attached.
    pause
    exit /b 1
)

if not exist "%DEV_DIR%" mkdir "%DEV_DIR%" >nul 2>&1

echo [1/6] Building the Hub and the witness...
pushd "%REPO_ROOT%" >nul
cargo build -p l2-fast-pay-hub --features rollback-witness --bin fast-pay-hub --bin hpay-rollback-witness
if errorlevel 1 (
    popd >nul
    echo ERROR: build failed.
    pause
    exit /b 1
)
popd >nul

set "WITNESS_BIN=%REPO_ROOT%\target\debug\hpay-rollback-witness.exe"
set "HUB_BIN=%REPO_ROOT%\target\debug\fast-pay-hub.exe"
if not exist "%WITNESS_BIN%" (
    echo ERROR: %WITNESS_BIN% was not produced by the build.
    pause
    exit /b 1
)
if not exist "%HUB_BIN%" (
    echo ERROR: %HUB_BIN% was not produced by the build.
    pause
    exit /b 1
)

echo [2/6] Reading the witness store identity...
rem Output goes to a file and is parsed from there. `for /f` over a backticked
rem command whose first token is a quoted path does not work in cmd.
"%WITNESS_BIN%" --witness-id %WITNESS_ID% --store "%STORE_FILE%" --receipt-secret-hex "%WITNESS_RECEIPT_SECRET%" instance > "%INSTANCE_LOG%" 2> "%INSTANCE_ERR%"
if errorlevel 1 (
    echo ERROR: the witness store would not open.
    type "%INSTANCE_ERR%"
    pause
    exit /b 1
)
set "WITNESS_RECEIPT_ADDRESS="
set "WITNESS_INSTANCE_ID="
for /f "usebackq tokens=1,* delims==" %%A in (`type "%INSTANCE_LOG%"`) do (
    if "%%A"=="witness_receipt_address" set "WITNESS_RECEIPT_ADDRESS=%%B"
    if "%%A"=="witness_instance_id" set "WITNESS_INSTANCE_ID=%%B"
)
if not defined WITNESS_RECEIPT_ADDRESS (
    echo ERROR: the witness would not report its receipt address.
    type "%INSTANCE_LOG%"
    type "%INSTANCE_ERR%"
    pause
    exit /b 1
)
echo       witness_instance_id     = !WITNESS_INSTANCE_ID!
echo       witness_receipt_address = !WITNESS_RECEIPT_ADDRESS!

echo [3/6] Issuing a one-day development attestation...
rem The posture enum has no "same host" value, on purpose: a configuration that
rem wants it cannot express it. So the separation statement carries the truth,
rem and it is written to be read out loud during an incident. One day of
rem validity, so this cannot be set once and forgotten.
"%WITNESS_BIN%" --witness-id %WITNESS_ID% --store "%STORE_FILE%" --receipt-secret-hex "%WITNESS_RECEIPT_SECRET%" attest --hub-identity "%HACASH_HUB_ADDRESS%" --authorisation-secret-hex "%WITNESS_AUTHORISATION_SECRET%" --posture same-operator-separate-infrastructure --witness-operator "LOCAL-DEV-NO-SEPARATION" --separation-statement "NONE. This witness runs on the same host, the same filesystem and the same backup set as the Hub state it witnesses. There is no separation of any kind. This is ADR-001 Option B and it defends against nothing. Local development only." --validity-days 1 > "%ATTESTATION_FILE%" 2> "%ATTEST_LOG%"
if errorlevel 1 (
    echo ERROR: the attestation could not be issued.
    type "%ATTEST_LOG%"
    pause
    exit /b 1
)
set "WITNESS_AUTHORISATION_ADDRESS="
for /f "usebackq tokens=1,* delims==" %%A in (`type "%ATTEST_LOG%"`) do (
    if "%%A"=="witness_authorisation_address" set "WITNESS_AUTHORISATION_ADDRESS=%%B"
)
if not defined WITNESS_AUTHORISATION_ADDRESS (
    echo ERROR: the attestation did not report the authorisation address.
    type "%ATTEST_LOG%"
    pause
    exit /b 1
)
echo       witness_authorisation_address = !WITNESS_AUTHORISATION_ADDRESS!

echo [4/6] Starting the witness on %WITNESS_LISTEN% ...
rem The two launch lines are written into their own small scripts rather than
rem inlined after `cmd /k`. Quoted paths inside a quoted `cmd /k` argument are a
rem well-known way to lose an argument silently, and a launcher that half-starts
rem is worse than one that does not start.
> "%RUN_WITNESS_BAT%" echo @echo off
>>"%RUN_WITNESS_BAT%" echo title DEV-WITNESS-SAME-HOST
>>"%RUN_WITNESS_BAT%" echo echo THIS WITNESS IS ON THE HUB'S OWN HOST. IT IS NOT AN ANCHOR.
>>"%RUN_WITNESS_BAT%" echo echo Store: %STORE_FILE%
>>"%RUN_WITNESS_BAT%" echo echo KEEP THIS WINDOW OPEN
>>"%RUN_WITNESS_BAT%" echo echo.
>>"%RUN_WITNESS_BAT%" echo "%WITNESS_BIN%" --witness-id %WITNESS_ID% --store "%STORE_FILE%" --receipt-secret-hex "%WITNESS_RECEIPT_SECRET%" serve --listen %WITNESS_LISTEN%
start "DEV-WITNESS-SAME-HOST" cmd /k "%RUN_WITNESS_BAT%"

echo [5/6] Waiting for the witness to accept connections (max 30s)...
set /a tries=0
:waitwitness
set /a tries+=1
if !tries! gtr 30 goto witnessfail
timeout /t 1 /nobreak >nul
powershell -NoProfile -Command "try { $c = New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1', 8791); $c.Close(); exit 0 } catch { exit 1 }" >nul 2>&1
if errorlevel 1 goto waitwitness
echo       Witness is listening.

echo [6/6] Starting the Hub on %HUB_LISTEN% pointing at %WITNESS_URL% ...
> "%RUN_HUB_BAT%" echo @echo off
>>"%RUN_HUB_BAT%" echo title DEV-HUB-ANCHOR-DOES-NOT-COUNT
>>"%RUN_HUB_BAT%" echo echo THE ANCHOR DOES NOT COUNT IN THIS CONFIGURATION.
>>"%RUN_HUB_BAT%" echo echo The witness is on this same host, in this same backup set.
>>"%RUN_HUB_BAT%" echo echo Restore this machine and both go backwards together.
>>"%RUN_HUB_BAT%" echo echo KEEP THIS WINDOW OPEN
>>"%RUN_HUB_BAT%" echo echo.
>>"%RUN_HUB_BAT%" echo "%HUB_BIN%" --listen %HUB_LISTEN% --node-url %NODE_URL% --deployment-profile development --hub-address %HACASH_HUB_ADDRESS% --hub-secret-hex %HACASH_HUB_SECRET_HEX% --state-file "%HUB_STATE_FILE%" --rollback-witness-url %WITNESS_URL% --rollback-witness-id %WITNESS_ID% --rollback-witness-receipt-address !WITNESS_RECEIPT_ADDRESS! --rollback-witness-authorisation-address !WITNESS_AUTHORISATION_ADDRESS! --rollback-witness-attestation-file "%ATTESTATION_FILE%"
start "DEV-HUB-ANCHOR-DOES-NOT-COUNT" cmd /k "%RUN_HUB_BAT%"

echo.
echo  ========================================================================
echo   Two windows launched. Keep both open.
echo.
echo     DEV-WITNESS-SAME-HOST            %WITNESS_URL%
echo     DEV-HUB-ANCHOR-DOES-NOT-COUNT    http://%HUB_LISTEN%
echo.
echo   Node API expected at %NODE_URL%
echo.
echo   Check what the Hub says about its own anchor:
echo     curl http://%HUB_LISTEN%/v1/readiness/mainnet
echo.
echo   And remember what this configuration is: a working protocol on one
echo   machine. Not an anchor. Not a defence. Not production.
echo  ========================================================================
echo.
pause
exit /b 0

:witnessfail
echo.
echo  The witness did not start listening within 30 seconds.
echo  Check the DEV-WITNESS-SAME-HOST window for the reason.
echo.
pause
exit /b 1
