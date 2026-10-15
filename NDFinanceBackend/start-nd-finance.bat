@echo off
setlocal

set "PROJECT_DIR=%~dp0"
set "PROJECT_FILE=%PROJECT_DIR%NDFinanceBackend.csproj"
set "APP_URL=http://localhost:5080"
set "ND_HTML_PATH=%PROJECT_DIR%..\index.html"
set "ASPNETCORE_ENVIRONMENT=Development"
title ND Finance Server

set "HAS_DOTNET_SDK="
for /f "tokens=1" %%V in ('dotnet --list-sdks 2^>nul') do set "HAS_DOTNET_SDK=1"
if not defined HAS_DOTNET_SDK (
  echo .NET SDK was not found. Install the .NET 8 SDK, then run this launcher again.
  pause
  exit /b 1
)

curl.exe --fail --silent "%APP_URL%/api/health" >nul 2>nul
if not errorlevel 1 (
  curl.exe --fail --silent "%APP_URL%/" >nul 2>nul
  if not errorlevel 1 (
    start "" "%APP_URL%/"
    echo ND Finance READY: %APP_URL%/
    exit /b 0
  )
)

start "" /min powershell.exe -NoProfile -WindowStyle Hidden -Command "$url='%APP_URL%/'; for ($attempt = 0; $attempt -lt 120; $attempt++) { try { $health = Invoke-WebRequest -UseBasicParsing -Uri ($url + 'api/health') -TimeoutSec 2; $page = Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 2; if ($health.StatusCode -eq 200 -and $page.StatusCode -eq 200) { Start-Process $url; exit 0 } } catch {} ; Start-Sleep -Seconds 1 }"
dotnet run --project "%PROJECT_FILE%"