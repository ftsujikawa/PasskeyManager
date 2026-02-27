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
  "$failed = @();" ^
  "$allowedFailureKinds = @('authorization','not_found','version_conflict','rate_limited','server_error','http_error','client_error','transport_or_unknown','none');" ^
  "$normalizeToken = { param([string]$value) if ([string]::IsNullOrWhiteSpace($value)) { return '' } return ([regex]::Replace($value.TrimEnd('.', ','), '[^0-9A-Za-z_-]+$', '')) };" ^
  "$sensitivePatterns = @('token=', 'bearer=', 'authorization=', 'authorization:', 'access_token=', 'refresh_token=', 'client_secret=');" ^
  "$sensitiveHits = @();" ^
  "foreach ($p in $sensitivePatterns) { if ($log -match [regex]::Escape($p)) { $sensitiveHits += $p } }" ^
  "if ($sensitiveHits.Count -eq 0) { Write-Host 'PASS: sensitive_markers_absent' } else { Write-Host ('FAIL: sensitive_markers_absent found=' + ($sensitiveHits -join '|')); $failed += 'sensitive_markers_absent' }" ^
  "$lines = $log -split '\r?\n';" ^
  "$syncLines = @(); foreach ($line in $lines) { if (![string]::IsNullOrWhiteSpace($line) -and $line -match '^(INFO|WARNING|SUCCESS|FAILED):\s+sync\s') { $syncLines += $line } }" ^
  "if ($syncLines.Count -gt 0) { Write-Host ('PASS: sync_lines_present count=' + $syncLines.Count) } else { Write-Host 'FAIL: sync_lines_present count=0'; $failed += 'sync_lines_present' }" ^
  "$operationMissing = @(); foreach ($line in $lines) { if (![string]::IsNullOrWhiteSpace($line) -and $line -match '^(INFO|WARNING|SUCCESS|FAILED):\s+(summary|sync)\s' -and $line -notmatch '(^|\s)operation=') { $operationMissing += $line } }" ^
  "if ($operationMissing.Count -eq 0) { Write-Host 'PASS: operation_key_present' } else { Write-Host ('FAIL: operation_key_present count=' + $operationMissing.Count); $failed += 'operation_key_present' }" ^
  "$messageCodeMissing = @(); foreach ($line in $lines) { if (![string]::IsNullOrWhiteSpace($line) -and $line -match '(^|\s)message=' -and $line -notmatch '(^|\s)message_code=') { $messageCodeMissing += $line } }" ^
  "if ($messageCodeMissing.Count -eq 0) { Write-Host 'PASS: message_code_with_message' } else { Write-Host ('FAIL: message_code_with_message count=' + $messageCodeMissing.Count); $failed += 'message_code_with_message' }" ^
  "$syncFailureLines = @(); foreach ($line in $lines) { if (![string]::IsNullOrWhiteSpace($line) -and $line -match '^(WARNING|FAILED):\s+sync\s+result=(failed|warning)\s+operation=(put_vault|restore_snapshot|test_connection|manual_resync)\b') { $syncFailureLines += $line } }" ^
  "$requestIdMissing = @(); foreach ($line in $syncFailureLines) { if ($line -notmatch '(^|\s)request_id=') { $requestIdMissing += $line } }" ^
  "if ($requestIdMissing.Count -eq 0) { Write-Host 'PASS: request_id_with_sync_failure' } else { Write-Host ('FAIL: request_id_with_sync_failure count=' + $requestIdMissing.Count); $failed += 'request_id_with_sync_failure' }" ^
  "$syncStartLines = @(); foreach ($line in $lines) { if (![string]::IsNullOrWhiteSpace($line) -and $line -match '^INFO:\s+sync\s+state=start\s+operation=(put_vault|restore_snapshot|manual_resync)\b') { $syncStartLines += $line } }" ^
  "$startRequestIdMissing = @(); foreach ($line in $syncStartLines) { if ($line -notmatch '(^|\s)request_id=') { $startRequestIdMissing += $line } }" ^
  "if ($startRequestIdMissing.Count -eq 0) { Write-Host 'PASS: request_id_with_sync_start' } else { Write-Host ('FAIL: request_id_with_sync_start count=' + $startRequestIdMissing.Count); $failed += 'request_id_with_sync_start' }" ^
  "$manualResyncSuccessSummaryLines = @(); foreach ($line in $lines) { if (![string]::IsNullOrWhiteSpace($line) -and $line -match '^SUCCESS:\s+summary\s+result=success\s+operation=manual_resync\b') { $manualResyncSuccessSummaryLines += $line } }" ^
  "$manualResyncSummaryRequestIdMissing = @(); foreach ($line in $manualResyncSuccessSummaryLines) { if ($line -notmatch '(^|\s)request_id=') { $manualResyncSummaryRequestIdMissing += $line } }" ^
  "if ($manualResyncSummaryRequestIdMissing.Count -eq 0) { Write-Host 'PASS: request_id_with_manual_resync_summary_success' } else { Write-Host ('FAIL: request_id_with_manual_resync_summary_success count=' + $manualResyncSummaryRequestIdMissing.Count); $failed += 'request_id_with_manual_resync_summary_success' }" ^
  "$startRequestIdInvalid = @(); foreach ($line in $syncStartLines) { if ($line -match '^INFO:\s+sync\s+state=start\s+operation=([a-z_]+)\b') { $operation = $matches[1]; if ($line -match '(^|\s)request_id=([^\s]+)') { $rawValue = $matches[2]; $value = & $normalizeToken $rawValue; if ($value -notmatch '^[0-9]{8}T[0-9]{9}Z-([a-z_]+)$') { $startRequestIdInvalid += $line } else { $opFromId = $matches[1]; if ($opFromId -ne $operation) { $startRequestIdInvalid += $line } } } } }" ^
  "if ($startRequestIdInvalid.Count -eq 0) { Write-Host 'PASS: request_id_format_with_sync_start_runtime' } else { Write-Host ('FAIL: request_id_format_with_sync_start_runtime count=' + $startRequestIdInvalid.Count); $failed += 'request_id_format_with_sync_start_runtime' }" ^
  "$nameNotResolvedLines = @(); foreach ($line in $lines) { if (![string]::IsNullOrWhiteSpace($line) -and ($line -match '(^|\s)sync_failure=name_not_resolved(\s|$)' -or $line -match '(^|\s)reason=name_not_resolved(\s|$)')) { $nameNotResolvedLines += $line } }" ^
  "$nameNotResolvedHostMissing = @(); foreach ($line in $nameNotResolvedLines) { if ($line -notmatch '(^|\s)host=') { $nameNotResolvedHostMissing += $line } }" ^
  "if ($nameNotResolvedHostMissing.Count -eq 0) { Write-Host 'PASS: name_not_resolved_host_required' } else { Write-Host ('FAIL: name_not_resolved_host_required count=' + $nameNotResolvedHostMissing.Count); $failed += 'name_not_resolved_host_required' }" ^
  "$failureKindInvalid = @(); foreach ($line in $lines) { if ($line -match '(^|\s)failure_kind=([^\s]+)') { $value = & $normalizeToken $matches[2]; if ($allowedFailureKinds -notcontains $value) { $failureKindInvalid += $line } } }" ^
  "if ($failureKindInvalid.Count -eq 0) { Write-Host 'PASS: failure_kind_allowed_values' } else { Write-Host ('FAIL: failure_kind_allowed_values count=' + $failureKindInvalid.Count); $failed += 'failure_kind_allowed_values' }" ^
  "if ($failed.Count -gt 0) { Write-Host ('FAIL: check_failures=' + ($failed -join ',')); exit 1 }" ^
  "Write-Host 'OK: runtime sync log checks passed.'; exit 0"

set "RC=%ERRORLEVEL%"
echo ExitCode=%RC%
exit /b %RC%
