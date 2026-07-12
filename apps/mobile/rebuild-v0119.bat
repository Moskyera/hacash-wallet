@echo off
setlocal
set "ANDROID_HOME=%LOCALAPPDATA%\Android\Sdk"
set "ANDROID_SDK_ROOT=%LOCALAPPDATA%\Android\Sdk"
set "NDK_HOME=%LOCALAPPDATA%\Android\Sdk\ndk\27.2.12479018"
set "JAVA_HOME=C:\Program Files\Android\Android Studio\jbr"
set "PATH=%JAVA_HOME%\bin;%PATH%"
set "ROOT=C:\Users\KQHEX\Documents\moskyera-quantum-wallet"
set "MOBILE=%ROOT%\apps\mobile"
set "TC=%NDK_HOME%\toolchains\llvm\prebuilt\windows-x86_64\bin"
set "LOG=%MOBILE%\rebuild-v0119.log"
set "VER=0.1.27"

echo === v%VER% rebuild started %DATE% %TIME% === > "%LOG%"

powershell -ExecutionPolicy Bypass -File "%MOBILE%\generate-app-icons.ps1" >> "%LOG%" 2>&1
if errorlevel 1 goto fail

set "CC_aarch64_linux_android=%TC%\aarch64-linux-android34-clang.cmd"
set "AR_aarch64_linux_android=%TC%\llvm-ar.exe"
set "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=%TC%\aarch64-linux-android34-clang.cmd"

cd /d "%ROOT%"
cargo build --release --target aarch64-linux-android -p hacash-wallet-mobile >> "%LOG%" 2>&1
if errorlevel 1 goto fail

cd /d "%MOBILE%"
yarn build >> "%LOG%" 2>&1
if errorlevel 1 goto fail

powershell -ExecutionPolicy Bypass -File .\apply-android-patches.ps1 >> "%LOG%" 2>&1
if errorlevel 1 goto fail

powershell -ExecutionPolicy Bypass -File .\sync-android-frontend.ps1 >> "%LOG%" 2>&1
if errorlevel 1 goto fail

set "SRC=%ROOT%\target\aarch64-linux-android\release\libhacash_wallet_mobile_lib.so"
set "JNI=%MOBILE%\src-tauri\gen\android\app\src\main\jniLibs\arm64-v8a"
if not exist "%JNI%" mkdir "%JNI%"
copy /Y "%SRC%" "%JNI%\libhacash_wallet_mobile_lib.so" >> "%LOG%" 2>&1

cd /d "%MOBILE%\src-tauri\gen\android"
call gradlew.bat assembleUniversalRelease --no-daemon >> "%LOG%" 2>&1
if errorlevel 1 goto fail

if not exist "%ROOT%\releases" mkdir "%ROOT%\releases"
copy /Y "%MOBILE%\src-tauri\gen\android\app\build\outputs\apk\universal\release\app-universal-release.apk" "%ROOT%\releases\hacash-wallet-mobile-v%VER%-arm64.apk" >> "%LOG%" 2>&1

echo === v%VER% rebuild OK %DATE% %TIME% === >> "%LOG%"
exit /b 0

:fail
echo === v%VER% rebuild FAILED %DATE% %TIME% === >> "%LOG%"
exit /b 1