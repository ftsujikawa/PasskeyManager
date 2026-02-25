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

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$log = Get-Content -Raw -Path '%LOG_FILE%';" ^
  "$checks = @(" ^
  "  @{ Name = '409_recovery'; Pattern = 'recovery=manual_resync_now' }," ^
  "  @{ Name = 'read_encrypted_vault_data'; Pattern = 'operation=read_encrypted_vault_data\s+reason=' }," ^
  "  @{ Name = 'vault_unlock_ui_required'; Pattern = 'operation=vault_unlock\s+reason=ui_required' }" ^
  ");" ^
  "$failed = @();" ^
  "foreach ($c in $checks) {" ^
  "  if ($log -match $c.Pattern) { Write-Host ('PASS: ' + $c.Name) }" ^
  "  else { Write-Host ('FAIL: ' + $c.Name); $failed += $c.Name }" ^
  "}" ^
  "if ($failed.Count -gt 0) { Write-Error ('missing keys: ' + ($failed -join ', ')); exit 1 }" ^
  "Write-Host 'OK: abnormal sync log keys are present.'; exit 0"

set "RC=%ERRORLEVEL%"
echo ExitCode=%RC%
exit /b %RC%
