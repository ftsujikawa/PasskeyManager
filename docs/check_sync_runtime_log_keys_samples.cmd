@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "CHECKER=%SCRIPT_DIR%check_sync_runtime_log_keys.cmd"
set "SCENARIO=%~1"

if not exist "%CHECKER%" (
  echo ERROR: checker script not found: %CHECKER%
  exit /b 2
)

if "%SCENARIO%"=="" set "SCENARIO=both"

set "HAS_ERROR=0"

if /i "%SCENARIO%"=="both" goto :run_both
if /i "%SCENARIO%"=="batch" goto :run_both
if /i "%SCENARIO%"=="pass" goto :run_pass
if /i "%SCENARIO%"=="fail" goto :run_fail
if /i "%SCENARIO%"=="fail_manual_resync_summary_request_id_format" goto :run_fail_manual_resync_summary_request_id_format

echo ERROR: unsupported scenario: %SCENARIO%
echo Usage: %~nx0 [both^|batch^|pass^|fail^|fail_manual_resync_summary_request_id_format]
exit /b 2

:run_both
call :run_case "%SCRIPT_DIR%samples\runtime_sync_logs_pass.txt" 0
call :run_case "%SCRIPT_DIR%samples\runtime_sync_logs_fail.txt" 1
call :run_case "%SCRIPT_DIR%samples\runtime_sync_logs_fail_manual_resync_summary_request_id_format.txt" 1
goto :finish

:run_pass
call :run_case "%SCRIPT_DIR%samples\runtime_sync_logs_pass.txt" 0
goto :finish

:run_fail
call :run_case "%SCRIPT_DIR%samples\runtime_sync_logs_fail.txt" 1
call :run_case "%SCRIPT_DIR%samples\runtime_sync_logs_fail_manual_resync_summary_request_id_format.txt" 1
goto :finish

:run_fail_manual_resync_summary_request_id_format
call :run_case "%SCRIPT_DIR%samples\runtime_sync_logs_fail_manual_resync_summary_request_id_format.txt" 1
goto :finish

:finish
if "%HAS_ERROR%"=="0" (
  echo OK: runtime sync log sample checks completed as expected. scenario=%SCENARIO%
  exit /b 0
)

echo ERROR: one or more runtime sample checks did not match expected exit codes. scenario=%SCENARIO%
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
