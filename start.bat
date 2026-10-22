@echo off
title Phishing URL Detector (PhishGuard) - Local Server
echo ========================================================
echo    Phishing URL Detector (PhishGuard)
echo    PBL Progress Review-II - Local Web Server
echo ========================================================
echo.
echo Starting local HTTP server at http://localhost:8000/
echo Press Ctrl+C in this window to stop the server.
echo.
start http://localhost:8000/
powershell -ExecutionPolicy Bypass -File "%~dp0server.ps1" -port 8000
pause
