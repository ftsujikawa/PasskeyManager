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
  "$syncFailureLines = @();" ^
  "foreach ($line in $lines) { if (![string]::IsNullOrWhiteSpace($line) -and $line -match '^(WARNING|FAILED):\s+sync\s+result=failed\s+operation=(put_vault|restore_snapshot|test_connection)\b') { $syncFailureLines += $line } }" ^
  "$requestIdMissing = @();" ^
  "foreach ($line in $syncFailureLines) { if ($line -notmatch '(^|\s)request_id=') { $requestIdMissing += $line } }" ^
  "if ($requestIdMissing.Count -eq 0) { Write-Host 'PASS: request_id_with_sync_failure' }" ^
  "else { Write-Host ('FAIL: request_id_with_sync_failure count=' + $requestIdMissing.Count); $failed += 'request_id_with_sync_failure' }" ^
  "$syncStartLines = @();" ^
  "foreach ($line in $lines) { if (![string]::IsNullOrWhiteSpace($line) -and $line -match '^INFO:\s+sync\s+state=start\s+operation=(put_vault|restore_snapshot|manual_resync)\b') { $syncStartLines += $line } }" ^
  "$startRequestIdMissing = @();" ^
  "foreach ($line in $syncStartLines) { if ($line -notmatch '(^|\s)request_id=') { $startRequestIdMissing += $line } }" ^
  "if ($startRequestIdMissing.Count -eq 0) { Write-Host 'PASS: request_id_with_sync_start' }" ^
  "else { Write-Host ('FAIL: request_id_with_sync_start count=' + $startRequestIdMissing.Count); $failed += 'request_id_with_sync_start' }" ^
  "$startRequestIdInvalid = @();" ^
  "foreach ($line in $syncStartLines) { if ($line -match '(^|\s)request_id=([^\s]+)') { $value = $matches[2].TrimEnd('.', ','); if ($value -notmatch '^[0-9]{8}T[0-9]{9}Z-(put_vault|restore_snapshot|manual_resync)$') { $startRequestIdInvalid += $line } } }" ^
  "if ($startRequestIdInvalid.Count -eq 0) { Write-Host 'PASS: request_id_format_with_sync_start' }" ^
  "else { Write-Host ('FAIL: request_id_format_with_sync_start count=' + $startRequestIdInvalid.Count); $failed += 'request_id_format_with_sync_start' }" ^
  "$failureKindMissing = @();" ^
  "foreach ($line in $syncFailureLines) { if ($line -notmatch '(^|\s)failure_kind=') { $failureKindMissing += $line } }" ^
  "if ($failureKindMissing.Count -eq 0) { Write-Host 'PASS: failure_kind_with_sync_failure' }" ^
  "else { Write-Host ('FAIL: failure_kind_with_sync_failure count=' + $failureKindMissing.Count); $failed += 'failure_kind_with_sync_failure' }" ^
  "$allowedFailureKinds = @('authorization','not_found','version_conflict','rate_limited','server_error','http_error','client_error','transport_or_unknown','none');" ^
  "$failureKindInvalid = @();" ^
  "foreach ($line in $syncFailureLines) { if ($line -match '(^|\s)failure_kind=([^\s]+)') { $value = $matches[2].TrimEnd('.', ','); if ($allowedFailureKinds -notcontains $value) { $failureKindInvalid += $line } } }" ^
  "if ($failureKindInvalid.Count -eq 0) { Write-Host 'PASS: failure_kind_allowed_values' }" ^
  "else { Write-Host ('FAIL: failure_kind_allowed_values count=' + $failureKindInvalid.Count); $failed += 'failure_kind_allowed_values' }" ^
  "if ($failed.Count -gt 0) { Write-Host ('FAIL: check_failures=' + ($failed -join ',')); exit 1 }" ^
  "Write-Host 'OK: abnormal sync log checks passed.'; exit 0"

set "RC=%ERRORLEVEL%"
echo ExitCode=%RC%
exit /b %RC%
