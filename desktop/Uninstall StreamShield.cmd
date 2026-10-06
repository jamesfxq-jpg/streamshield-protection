@echo off
setlocal
set "INSTALL=%LOCALAPPDATA%\StreamShield Protection"
call "%INSTALL%\Stop StreamShield.cmd" >nul 2>nul
echo.
echo This removes the StreamShield application from this PC.
echo If you connected Kick, use "Delete My StreamShield Data" in the dashboard first to revoke access and remove cloud channel data.
choice /M "Remove StreamShield Protection from this PC"
if errorlevel 2 exit /b 0
del /q "%USERPROFILE%\Desktop\StreamShield Protection.cmd" >nul 2>nul
del /q "%USERPROFILE%\Desktop\Uninstall StreamShield.cmd" >nul 2>nul
cd /d "%TEMP%"
rmdir /S /Q "%INSTALL%" >nul 2>nul
echo StreamShield Protection removed.
pause
