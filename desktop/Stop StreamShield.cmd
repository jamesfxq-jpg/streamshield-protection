@echo off
setlocal
set "PIDFILE=%LOCALAPPDATA%\StreamShield Protection\app\data\streamshield.pid"
if not exist "%PIDFILE%" (
  echo StreamShield does not appear to be running.
  exit /b 0
)
set /p PID=<"%PIDFILE%"
if "%PID%"=="" exit /b 0
taskkill /PID %PID% /T >nul 2>nul
timeout /t 1 /nobreak >nul
del /q "%PIDFILE%" >nul 2>nul
echo StreamShield stopped.
