@echo off
setlocal
set "NDK_HOME=%LOCALAPPDATA%\Android\Sdk\ndk\27.2.12479018"
set "TC=%NDK_HOME%\toolchains\llvm\prebuilt\windows-x86_64\bin"
set "CC_aarch64_linux_android=%TC%\aarch64-linux-android34-clang.cmd"
set "AR_aarch64_linux_android=%TC%\llvm-ar.exe"
set "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=%TC%\aarch64-linux-android34-clang.cmd"
cd /d C:\Users\KQHEX\Documents\moskyera-quantum-wallet
cargo build --release --target aarch64-linux-android -p hacash-wallet-mobile
exit /b %ERRORLEVEL%