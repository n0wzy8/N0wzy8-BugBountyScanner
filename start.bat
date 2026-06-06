@echo off
title N0wzy8 Scanner
color 0A

echo =====================================
echo        N0wzy8 Bug Bounty Scanner
echo =====================================
echo.

echo [*] Checking Python...

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python was not found.
    echo Please install Python and try again.
    pause
    exit
)

echo [*] Checking dependencies...

pip show requests >nul 2>&1
if %errorlevel% neq 0 goto install

pip show dnspython >nul 2>&1
if %errorlevel% neq 0 goto install

pip show beautifulsoup4 >nul 2>&1
if %errorlevel% neq 0 goto install

pip show rich >nul 2>&1
if %errorlevel% neq 0 goto install

goto run

:install
echo.
echo [*] Missing dependencies detected.
echo [*] Installing requirements...

pip install -r requirements.txt

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Installation failed.
    pause
    exit
)

:run
echo.
echo [*] Launching scanner...
echo.

python main.py

echo.
echo Scan finished.
pause