@echo off
setlocal
set "ANDROID_HOME=%LOCALAPPDATA%\Android\Sdk"
set "ANDROID_SDK_ROOT=%LOCALAPPDATA%\Android\Sdk"
set "NDK_HOME=%LOCALAPPDATA%\Android\Sdk\ndk\27.2.12479018"
set "JAVA_HOME=C:\Program Files\Android\Android Studio\jbr"
set "PATH=%JAVA_HOME%\bin;%PATH%"
set "ROOT=C:\Users\KQHEX\Documents\moskyera-quantum-wallet"
set "MOBILE=%ROOT%\apps\mobile"
set "LOG=%MOBILE%\rebuild-v012.log"

cd /d "%MOBILE%"
echo === rebuild v0.1.2 started %DATE% %TIME% === > "%LOG%"

powershell -ExecutionPolicy Bypass -File .\generate-app-icons.ps1 >> "%LOG%" 2>&1
powershell -ExecutionPolicy Bypass -File .\apply-android-patches.ps1 >> "%LOG%" 2>&1
yarn build >> "%LOG%" 2>&1
if errorlevel 1 goto fail

powershell -ExecutionPolicy Bypass -File .\sync-android-frontend.ps1 >> "%LOG%" 2>&1
if errorlevel 1 goto fail

set "SRC=%ROOT%\target\aarch64-linux-android\release\libhacash_wallet_mobile_lib.so"
set "JNI=%MOBILE%\src-tauri\gen\android\app\src\main\jniLibs\arm64-v8a"
if not exist "%JNI%" mkdir "%JNI%"
if exist "%SRC%" copy /Y "%SRC%" "%JNI%\libhacash_wallet_mobile_lib.so" >> "%LOG%" 2>&1

cd /d "%MOBILE%\src-tauri\gen\android"
call gradlew.bat assembleUniversalRelease --no-daemon >> "%LOG%" 2>&1
if errorlevel 1 goto fail

set "APK=%MOBILE%\src-tauri\gen\android\app\build\outputs\apk\universal\release\app-universal-release.apk"
copy /Y "%APK%" "%ROOT%\releases\hacash-wallet-mobile-v0.1.2-arm64.apk" >> "%LOG%" 2>&1

echo === rebuild v0.1.2 OK %DATE% %TIME% === >> "%LOG%"
exit /b 0

:fail
echo === rebuild v0.1.2 FAILED %DATE% %TIME% === >> "%LOG%"
exit /b 1