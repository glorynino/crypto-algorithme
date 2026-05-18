@echo off
setlocal
cd /d "%~dp0"

if exist "env\Scripts\python.exe" (
    set "PYTHON=env\Scripts\python.exe"
) else if exist ".venv\Scripts\python.exe" (
    set "PYTHON=.venv\Scripts\python.exe"
) else (
    set "PYTHON=python"
)

echo ====================================================
echo   TP 1 - CHIFFREMENT CLASSIQUE
echo ====================================================
echo Project: %CD%
echo Python:  %PYTHON%
echo.

if "%~1"=="" (
    echo Usage: run_tp1_tests.bat [1-7]
    echo   1 Quick Caesar test
    echo   6 Complete TP1 suite
    exit /b 0
)

if "%~1"=="1" (
    "%PYTHON%" test_tp1_quick.py
) else if "%~1"=="2" (
    pushd "Caesar cipher" && "%PYTHON%" caesar_attacks.py && popd
) else if "%~1"=="3" (
    pushd "Vignere cipher" && "%PYTHON%" vignere_attacks.py && popd
) else if "%~1"=="4" (
    pushd "HILL" && "%PYTHON%" hill_attacks.py && popd
) else if "%~1"=="5" (
    pushd "OTP algorithm" && "%PYTHON%" otp_attacks.py && popd
) else if "%~1"=="6" (
    "%PYTHON%" tp1_complete.py
) else if "%~1"=="7" (
    pushd "Caesar cipher" && "%PYTHON%" tests.py && popd
    pushd "Vignere cipher" && "%PYTHON%" tests.py && popd
    pushd "HILL" && "%PYTHON%" tests.py && popd
    pushd "OTP algorithm" && "%PYTHON%" tests.py && popd
) else (
    echo Invalid choice. Use 1-7.
    exit /b 1
)

echo.
echo Test completed.
