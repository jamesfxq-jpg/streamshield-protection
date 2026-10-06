@echo off
setlocal
set "INSTALL=%LOCALAPPDATA%\StreamShield Protection"
set "NODE=%INSTALL%\runtime\node.exe"
if not exist "%NODE%" (
  echo StreamShield runtime is missing. Re-run the installer.
  pause
  exit /b 1
)

curl.exe -sf http://localhost:8787/health >nul 2>nul
if not errorlevel 1 (
  start "" "http://localhost:8787"
  exit /b 0
)

cd /d "%INSTALL%\app"
start "StreamShield Protection" /min cmd /c ""%NODE%" "dist\src\server.js""
timeout /t 2 /nobreak >nul
start "" "http://localhost:8787"
exit /b 0
