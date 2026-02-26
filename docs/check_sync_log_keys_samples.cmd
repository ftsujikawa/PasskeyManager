@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "CHECKER=%SCRIPT_DIR%check_sync_log_keys.cmd"

if not exist "%CHECKER%" (
  echo ERROR: checker script not found: %CHECKER%
  exit /b 2
)

set "HAS_ERROR=0"

call :run_case "%SCRIPT_DIR%samples\abnormal_sync_logs_pass.txt" 0
call :run_case "%SCRIPT_DIR%samples\abnormal_sync_logs_fail.txt" 1
call :run_case "%SCRIPT_DIR%samples\abnormal_sync_logs_fail_request_id_format.txt" 1
call :run_case "%SCRIPT_DIR%samples\abnormal_sync_logs_fail_failure_kind_value.txt" 1

if "%HAS_ERROR%"=="0" (
  echo OK: all sync log sample checks completed as expected.
  exit /b 0
)

echo ERROR: one or more sample checks did not match expected exit codes.
exit /b 1

:run_case
set "TARGET_FILE=%~1"
set "EXPECTED_RC=%~2"

if not exist "%TARGET_FILE%" (
  echo ERROR: sample file not found: %TARGET_FILE%
  set "HAS_ERROR=1"
  goto :eof
)

echo ===== Checking: %~nx1 (expected ExitCode=%EXPECTED_RC%) =====
call "%CHECKER%" "%TARGET_FILE%"
set "ACTUAL_RC=%ERRORLEVEL%"

if "%ACTUAL_RC%"=="%EXPECTED_RC%" (
  echo RESULT: PASS ^(ExitCode=%ACTUAL_RC%^)
) else (
  echo RESULT: FAIL ^(actual=%ACTUAL_RC%, expected=%EXPECTED_RC%^)
  set "HAS_ERROR=1"
)

echo.
goto :eof
