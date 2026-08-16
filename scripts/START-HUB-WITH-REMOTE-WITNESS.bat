@echo off
setlocal EnableDelayedExpansion

title HPAY Fast Pay Hub - remote rollback anchor witness

rem ===========================================================================
rem  Starts the Fast Pay Hub pointing at a rollback-anchor witness that runs
rem  somewhere else. One parameter: the witness base URL.
rem
rem    START-HUB-WITH-REMOTE-WITNESS.bat https://witness.example.org
rem
rem  Everything else the anchor needs is read from the environment, because the
rem  Hub binary already reads those variables itself:
rem
rem    HACASH_HUB_ROLLBACK_WITNESS_ID
rem    HACASH_HUB_ROLLBACK_WITNESS_RECEIPT_ADDRESS
rem    HACASH_HUB_ROLLBACK_WITNESS_AUTHORISATION_ADDRESS
rem    HACASH_HUB_ROLLBACK_WITNESS_ATTESTATION_FILE
rem
rem  Moving to a different witness - your own, the counterparty's, a neutral
rem  third party's - is a change to the argument above and those four values.
rem  It is never a code change. See docs/l2/ADR-001-EXTERNAL-ROLLBACK-ANCHOR.md
rem  and docs/l2/RUNNING-A-WITNESS.md.
rem ===========================================================================

set "REPO_ROOT=%~dp0.."
set "WITNESS_URL=%~1"
set "HUB_BIN=%REPO_ROOT%\target\release\fast-pay-hub.exe"
if not exist "%HUB_BIN%" set "HUB_BIN=%REPO_ROOT%\target\debug\fast-pay-hub.exe"
if defined HPAY_HUB_BIN set "HUB_BIN=%HPAY_HUB_BIN%"

if "%WITNESS_URL%"=="" (
    echo ERROR: no witness URL given.
    echo.
    echo   Usage: %~nx0 https://witness.example.org
    echo.
    echo   There is no default witness address, and this script will not invent
    echo   one. A URL that does not answer is worse than an empty field: the Hub
    echo   would refuse to sign for a reason nobody could explain. Pick a witness
    echo   and pass it.
    echo.
    echo   Running one yourself: docs\l2\RUNNING-A-WITNESS.md
    echo.
    exit /b 1
)

set "MISSING="
if not defined HACASH_HUB_ROLLBACK_WITNESS_ID set "MISSING=!MISSING! HACASH_HUB_ROLLBACK_WITNESS_ID"
if not defined HACASH_HUB_ROLLBACK_WITNESS_RECEIPT_ADDRESS set "MISSING=!MISSING! HACASH_HUB_ROLLBACK_WITNESS_RECEIPT_ADDRESS"
if not defined HACASH_HUB_ROLLBACK_WITNESS_AUTHORISATION_ADDRESS set "MISSING=!MISSING! HACASH_HUB_ROLLBACK_WITNESS_AUTHORISATION_ADDRESS"
if not defined HACASH_HUB_ROLLBACK_WITNESS_ATTESTATION_FILE set "MISSING=!MISSING! HACASH_HUB_ROLLBACK_WITNESS_ATTESTATION_FILE"
if defined MISSING (
    echo ERROR: the anchor configuration is incomplete. Missing:!MISSING!
    echo.
    echo   All five anchor settings are required together. A partial anchor
    echo   configuration is refused rather than run without an anchor, because a
    echo   Hub that was meant to have one and silently does not is the worst
    echo   outcome available.
    echo.
    echo   The witness operator gives you all four values plus the URL. See
    echo   docs\l2\RUNNING-A-WITNESS.md, "Pointing a Hub at it".
    echo.
    exit /b 1
)

if not exist "%HACASH_HUB_ROLLBACK_WITNESS_ATTESTATION_FILE%" (
    echo ERROR: attestation file not found:
    echo   %HACASH_HUB_ROLLBACK_WITNESS_ATTESTATION_FILE%
    echo.
    echo   It is the signed statement naming who runs the witness and what
    echo   separates its failure domain from this Hub's. It has a bounded life
    echo   on purpose; if it has expired, ask the witness operator to sign a
    echo   fresh one. Do not relax the check.
    exit /b 1
)

if not defined HACASH_HUB_ADDRESS (
    echo ERROR: HACASH_HUB_ADDRESS is not set. See docs\HUB-OPERATOR.md.
    exit /b 1
)
if not defined HACASH_HUB_SECRET_HEX (
    echo ERROR: HACASH_HUB_SECRET_HEX is not set. The rollback anchor binds the
    echo        key that signs bills, so the Hub needs its signer.
    exit /b 1
)
if not exist "%HUB_BIN%" (
    echo ERROR: Hub binary not found at %HUB_BIN%
    echo   Build it:
    echo     cargo build -p l2-fast-pay-hub --features server --bin fast-pay-hub --release --locked
    exit /b 1
)

set "HUB_LISTEN=%HACASH_HUB_LISTEN%"
if not defined HUB_LISTEN set "HUB_LISTEN=127.0.0.1:8790"
set "NODE_URL=%HACASH_NODE_URL%"
if not defined NODE_URL set "NODE_URL=http://127.0.0.1:8080"
set "PROFILE=%HACASH_HUB_DEPLOYMENT_PROFILE%"
if not defined PROFILE set "PROFILE=mainnet-bounded-pilot"

set "STATE_ARGS="
if defined HACASH_HUB_STATE_FILE set "STATE_ARGS=--state-file "%HACASH_HUB_STATE_FILE%""

echo.
echo  ========================================================================
echo   HPAY Fast Pay Hub with an external rollback anchor
echo  ========================================================================
echo.
echo   Witness URL   : %WITNESS_URL%
echo   Witness id    : %HACASH_HUB_ROLLBACK_WITNESS_ID%
echo   Attestation   : %HACASH_HUB_ROLLBACK_WITNESS_ATTESTATION_FILE%
echo   Hub listen    : %HUB_LISTEN%
echo   Node API      : %NODE_URL%
echo   Profile       : %PROFILE%
echo.
echo   The Hub reserves its exact ledger position with that witness before it
echo   uses its signing key. If the witness is unreachable, the Hub refuses to
echo   sign and the channels freeze. That is the designed behaviour and there
echo   is no flag that changes it. Frozen channels lose nobody any money.
echo.
echo   If the witness is run by the same organisation that runs this Hub, read
echo   ADR-001 on what that does and does not protect against before telling
echo   anybody this Hub is anchored.
echo.
echo  ========================================================================
echo.

"%HUB_BIN%" ^
  --listen %HUB_LISTEN% ^
  --node-url %NODE_URL% ^
  --deployment-profile %PROFILE% ^
  --hub-fee-mei 0 ^
  %STATE_ARGS% ^
  --rollback-witness-url "%WITNESS_URL%"

exit /b %errorlevel%
