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
  "$sensitivePatterns = @('token=', 'bearer=', 'authorization=', 'authorization:', 'access_token=', 'refresh_token=', 'client_secret=');" ^
  "$sensitiveHits = @();" ^
  "foreach ($p in $sensitivePatterns) { if ($log -match [regex]::Escape($p)) { $sensitiveHits += $p } }" ^
  "if ($sensitiveHits.Count -eq 0) { Write-Host 'PASS: sensitive_markers_absent' }" ^
  "else { Write-Host ('FAIL: sensitive_markers_absent found=' + ($sensitiveHits -join '|')); $failed += 'sensitive_markers_absent' }" ^
  "$lines = $log -split '\r?\n';" ^
  "$operationMissing = @();" ^
  "foreach ($line in $lines) { if (![string]::IsNullOrWhiteSpace($line) -and $line -match '^(INFO|WARNING|SUCCESS|FAILED):\s+(summary|sync)\s' -and $line -notmatch '(^|\s)operation=') { $operationMissing += $line } }" ^
  "if ($operationMissing.Count -eq 0) { Write-Host 'PASS: operation_key_present' }" ^
  "else { Write-Host ('FAIL: operation_key_present count=' + $operationMissing.Count); $failed += 'operation_key_present' }" ^
  "$messageCodeMissing = @();" ^
  "foreach ($line in $lines) { if (![string]::IsNullOrWhiteSpace($line) -and $line -match '(^|\s)message=' -and $line -notmatch '(^|\s)message_code=') { $messageCodeMissing += $line } }" ^
  "if ($messageCodeMissing.Count -eq 0) { Write-Host 'PASS: message_code_with_message' }" ^
  "else { Write-Host ('FAIL: message_code_with_message count=' + $messageCodeMissing.Count); $failed += 'message_code_with_message' }" ^
  "if ($failed.Count -gt 0) { Write-Host ('FAIL: check_failures=' + ($failed -join ',')); exit 1 }" ^
  "Write-Host 'OK: abnormal sync log checks passed.'; exit 0"

set "RC=%ERRORLEVEL%"
echo ExitCode=%RC%
exit /b %RC%
