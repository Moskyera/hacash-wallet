@echo off
title HPAY Wallet Launcher
powershell -ExecutionPolicy Bypass -File "%~dp0start-wallet.ps1"
if errorlevel 1 pause