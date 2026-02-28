@echo off
setlocal

if "%~1"=="" (
  echo Usage: %~nx0 ^<captured_logs.txt^>
  exit /b 2
)

set "LOG_FILE=%~1"
if not exist "%LOG_FILE%" (
  echo ERROR: log file not found: %LOG_FILE%
  exit /b 2
)

set "SCRIPT_DIR=%~dp0"
set "CHECKER_PS1=%SCRIPT_DIR%check_sync_runtime_log_keys.ps1"
if not exist "%CHECKER_PS1%" (
  echo ERROR: checker script not found: %CHECKER_PS1%
  exit /b 2
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%CHECKER_PS1%" -LogFile "%LOG_FILE%"

set "RC=%ERRORLEVEL%"
echo ExitCode=%RC%
exit /b %RC%
