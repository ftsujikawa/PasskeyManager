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
  "$sensitivePatterns = @('token=', 'bearer=', 'authorization=', 'access_token=', 'refresh_token=', 'client_secret=');" ^
  "$sensitiveHits = @();" ^
  "foreach ($p in $sensitivePatterns) { if ($log -match [regex]::Escape($p)) { $sensitiveHits += $p } }" ^
  "if ($sensitiveHits.Count -eq 0) { Write-Host 'PASS: sensitive_markers_absent' }" ^
  "else { Write-Host ('FAIL: sensitive_markers_absent found=' + ($sensitiveHits -join '|')); $failed += 'sensitive_markers_absent' }" ^
  "if ($failed.Count -gt 0) { Write-Error ('check failures: ' + ($failed -join ', ')); exit 1 }" ^
  "Write-Host 'OK: abnormal sync log checks passed.'; exit 0"

set "RC=%ERRORLEVEL%"
echo ExitCode=%RC%
exit /b %RC%
