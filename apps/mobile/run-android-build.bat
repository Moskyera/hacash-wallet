@echo off
setlocal
cd /d "C:\Users\KQHEX\Documents\moskyera-quantum-wallet\apps\mobile"
set "ANDROID_HOME=%LOCALAPPDATA%\Android\Sdk"
set "ANDROID_SDK_ROOT=%LOCALAPPDATA%\Android\Sdk"
set "NDK_HOME=%LOCALAPPDATA%\Android\Sdk\ndk\27.2.12479018"
set "JAVA_HOME=C:\Program Files\Android\Android Studio\jbr"
set "PATH=%JAVA_HOME%\bin;%PATH%"
echo === Android build started %DATE% %TIME% === >> tauri-android-build2.log
node node_modules\@tauri-apps\cli\tauri.js android build --target aarch64 --apk -v -c tauri.android.build.conf.json >> tauri-android-build2.log 2>&1
echo === Android build finished exit=%ERRORLEVEL% %DATE% %TIME% === >> tauri-android-build2.log
exit /b %ERRORLEVEL%