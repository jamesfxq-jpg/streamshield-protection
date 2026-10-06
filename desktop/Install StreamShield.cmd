@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "PRODUCT=StreamShield Protection"
set "INSTALL=%LOCALAPPDATA%\StreamShield Protection"
set "NODEVER=22.23.3"
set "NODEZIP=node-v22.23.3-win-x64.zip"
set "NODEURL=https://nodejs.org/download/release/v22.23.3/%NODEZIP%"
set "NODEHASH=2b0ff57b049cda1bbcea2240eec20467018713c1efe1f7360c2681859b90ed71"

echo.
echo ==========================================
echo   StreamShield Protection Beta Installer
echo ==========================================
echo.

if not exist "%INSTALL%" mkdir "%INSTALL%"
if not exist "%INSTALL%\app" mkdir "%INSTALL%\app"
if not exist "%INSTALL%\runtime" mkdir "%INSTALL%\runtime"

xcopy "%~dp0app\*" "%INSTALL%\app\" /E /I /Y >nul
if errorlevel 4 (
  echo ERROR: Windows could not copy the StreamShield application files.
  pause
  exit /b 5
)
xcopy "%~dp0Streamer Branding\*" "%INSTALL%\Streamer Branding\" /E /I /Y >nul
if errorlevel 4 (
  echo ERROR: Windows could not copy the StreamShield OBS branding files.
  pause
  exit /b 6
)
copy /Y "%~dp0Start StreamShield.cmd" "%INSTALL%\Start StreamShield.cmd" >nul
copy /Y "%~dp0Stop StreamShield.cmd" "%INSTALL%\Stop StreamShield.cmd" >nul
copy /Y "%~dp0Uninstall StreamShield.cmd" "%INSTALL%\Uninstall StreamShield.cmd" >nul
copy /Y "%~dp0README.txt" "%INSTALL%\README.txt" >nul

if not exist "%INSTALL%\runtime\node.exe" (
  echo Downloading the official Node.js %NODEVER% runtime...
  set "TMPZIP=%TEMP%\%NODEZIP%"
  set "TMPNODE=%TEMP%\streamshield-node-%RANDOM%"
  curl.exe -fL --retry 3 --connect-timeout 20 -o "!TMPZIP!" "%NODEURL%"
  if errorlevel 1 (
    echo ERROR: Could not download the Node.js runtime.
    pause
    exit /b 2
  )
  set "HASH="
  for /f "skip=1 tokens=*" %%H in ('certutil -hashfile "!TMPZIP!" SHA256 2^>nul') do if not defined HASH set "HASH=%%H"
  set "HASH=!HASH: =!"
  if /I not "!HASH!"=="%NODEHASH%" (
    echo ERROR: Node.js checksum verification failed.
    del /q "!TMPZIP!" >nul 2>nul
    pause
    exit /b 3
  )
  mkdir "!TMPNODE!" >nul 2>nul
  tar.exe -xf "!TMPZIP!" -C "!TMPNODE!"
  if errorlevel 1 (
    echo ERROR: Windows could not extract the Node.js runtime.
    pause
    exit /b 4
  )
  copy /Y "!TMPNODE!\node-v22.23.3-win-x64\node.exe" "%INSTALL%\runtime\node.exe" >nul
  del /q "!TMPZIP!" >nul 2>nul
  rmdir /S /Q "!TMPNODE!" >nul 2>nul
)

> "%USERPROFILE%\Desktop\StreamShield Protection.cmd" echo @echo off
>> "%USERPROFILE%\Desktop\StreamShield Protection.cmd" echo call "%%LOCALAPPDATA%%\StreamShield Protection\Start StreamShield.cmd"
> "%USERPROFILE%\Desktop\Uninstall StreamShield.cmd" echo @echo off
>> "%USERPROFILE%\Desktop\Uninstall StreamShield.cmd" echo call "%%LOCALAPPDATA%%\StreamShield Protection\Uninstall StreamShield.cmd"

echo.
echo Installation complete.
echo StreamShield will now start. Click "Connect Kick" in the browser.
echo.
call "%INSTALL%\Start StreamShield.cmd"
exit /b 0
