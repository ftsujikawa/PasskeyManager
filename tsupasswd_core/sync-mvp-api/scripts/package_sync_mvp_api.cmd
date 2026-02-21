@echo off
setlocal enabledelayedexpansion

set "PROJECT_DIR=%~dp0.."
set "OUTPUT_DIR=%PROJECT_DIR%\publish-out"
set "ARTIFACT=%PROJECT_DIR%\sync-mvp-api-publish.tar.gz"

if not "%~1"=="" set "OUTPUT_DIR=%~1"
if not "%~2"=="" set "ARTIFACT=%~2"

echo [1/3] dotnet publish...
dotnet publish "%PROJECT_DIR%\SyncMvpApi.csproj" -c Release -o "%OUTPUT_DIR%"
if errorlevel 1 (
  echo ERROR: dotnet publish failed.
  exit /b 1
)

echo [2/3] create tar.gz...
if exist "%ARTIFACT%" del /f /q "%ARTIFACT%"
tar -czf "%ARTIFACT%" -C "%OUTPUT_DIR%" .
if errorlevel 1 (
  echo ERROR: tar creation failed.
  exit /b 1
)

echo [3/3] done
echo OUTPUT_DIR=%OUTPUT_DIR%
echo ARTIFACT=%ARTIFACT%
exit /b 0
