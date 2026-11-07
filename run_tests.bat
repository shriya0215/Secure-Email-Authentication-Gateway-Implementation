@echo off
title Secure Email Authentication Gateway - Test Suite
echo ========================================================================
echo     Running Email Authentication Gateway Test Suite
echo ========================================================================
py email_gateway_cli.py test-suite 2>nul || python email_gateway_cli.py test-suite 2>nul || "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" email_gateway_cli.py test-suite
echo.
echo ========================================================================
echo     Running Unit Tests via Pytest
echo ========================================================================
py -m pytest -v tests/ 2>nul || python -m pytest -v tests/ 2>nul || "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" -m pytest -v tests/
pause
