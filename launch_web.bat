@echo off
title Secure Email Authentication Gateway
echo ========================================================================
echo     SECURE EMAIL AUTHENTICATION GATEWAY (SPF | DKIM | DMARC)
echo ========================================================================
echo Starting Web Dashboard on http://127.0.0.1:5000 ...
py run_gateway_web.py 2>nul || python run_gateway_web.py 2>nul || "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" run_gateway_web.py
pause
