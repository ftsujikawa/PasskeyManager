@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "CHECKER_PS1=%SCRIPT_DIR%check_request_id_gap_blocks.ps1"

if not exist "%CHECKER_PS1%" (
  echo ERROR: checker script not found: %CHECKER_PS1%
  exit /b 2
)

set "TARGET_ROOT=%~1"
if "%TARGET_ROOT%"=="" set "TARGET_ROOT=."

powershell -NoProfile -ExecutionPolicy Bypass -File "%CHECKER_PS1%" -RepoRoot "%TARGET_ROOT%"
set "RC=%ERRORLEVEL%"
echo ExitCode=%RC%
exit /b %RC%
