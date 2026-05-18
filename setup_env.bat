@echo off
setlocal
cd /d "%~dp0"

echo Installing dependencies for crypto-algorithme...
echo.

if not exist "env\Scripts\python.exe" (
    echo Creating virtual environment in .\env
    py -3 -m venv env 2>nul || python -m venv env
    if errorlevel 1 (
        echo Failed to create venv. Install Python 3 from https://www.python.org/
        exit /b 1
    )
)

call env\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo.
echo Done. Run the TP1 suite with:
echo   env\Scripts\python.exe tp1_complete.py
echo or:
echo   run_tp1_tests.bat 6
echo.
echo In Cursor/VS Code: select interpreter env\Scripts\python.exe
