param(
    [string]$RepoRoot = "."
)

$ErrorActionPreference = 'Stop'

$root = (Resolve-Path -LiteralPath $RepoRoot).Path
$targetFiles = Get-ChildItem -Path $root -Recurse -Filter *.cpp |
    Where-Object { $_.FullName -notmatch '\\(x64|build|packages|\.git)\\' }

$emitCallPattern = '(LogInfo|LogSuccess|LogWarning|LogFailure|LogInProgress|UpdatePasskeyOperationStatusText|statusSink|syncStatusTextBlock\(\)\.Text)\s*\('
$runtimePrefixPattern = 'L"(INFO|SUCCESS|WARNING|FAILED):\s+(summary|sync)\s'

$gaps = New-Object System.Collections.Generic.List[object]

function Add-Gap {
    param(
        [string]$File,
        [int]$Line,
        [string]$Kind,
        [string]$Snippet
    )

    $gaps.Add([pscustomobject]@{
            file = $File
            line = $Line
            kind = $Kind
            snippet = $Snippet
        })
}

foreach ($file in $targetFiles) {
    $lines = Get-Content -LiteralPath $file.FullName
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]

        if ($line -notmatch $emitCallPattern) {
            continue
        }

        $statement = $line
        $startLine = $i + 1
        $openParens = (($line.ToCharArray() | Where-Object { $_ -eq '(' }).Count)
        $closeParens = (($line.ToCharArray() | Where-Object { $_ -eq ')' }).Count)

        $j = $i
        while (($j + 1) -lt $lines.Count -and ($openParens -gt $closeParens -or $statement -notmatch ';\s*$')) {
            $j++
            $next = $lines[$j]
            $statement += "`n" + $next
            $openParens += (($next.ToCharArray() | Where-Object { $_ -eq '(' }).Count)
            $closeParens += (($next.ToCharArray() | Where-Object { $_ -eq ')' }).Count)

            if (($j - $i) -gt 80) {
                break
            }
        }

        if ($statement -match $runtimePrefixPattern) {
            if ($statement -notmatch 'request_id=') {
                Add-Gap -File $file.FullName.Replace($root + '\\', '') -Line $startLine -Kind 'direct_emit' -Snippet ($line.Trim())
            }
            $i = $j
            continue
        }

        if ($statement -match '\b([A-Za-z_][A-Za-z0-9_]*)\b\s*(\+\s*L"[^\"]*")?\s*\}\s*\)\s*;\s*$') {
            $varName = $matches[1]
            $windowStart = [Math]::Max(0, $i - 60)
            $windowLines = $lines[$windowStart..$i]
            $windowText = ($windowLines -join "`n")

            $assignRuntimePattern = ('\b{0}\s*=\s*L"(INFO|SUCCESS|WARNING|FAILED):\s+(summary|sync)\s' -f [regex]::Escape($varName))
            $appendPattern = ('\b{0}\s*\+=\s*[\s\S]*?request_id=' -f [regex]::Escape($varName))
            $assignWithRequestIdPattern = ('\b{0}\s*=\s*[\s\S]*?request_id=' -f [regex]::Escape($varName))

            if ($windowText -match $assignRuntimePattern) {
                $hasRequestIdInAssign = $windowText -match $assignWithRequestIdPattern
                $hasRequestIdAppended = $windowText -match $appendPattern
                if (-not $hasRequestIdInAssign -and -not $hasRequestIdAppended) {
                    Add-Gap -File $file.FullName.Replace($root + '\\', '') -Line $startLine -Kind 'variable_emit' -Snippet ($line.Trim())
                }
            }
        }

        $i = $j
    }
}

if ($gaps.Count -eq 0) {
    Write-Host 'OK: no request_id gaps in operational summary/sync emits.'
    exit 0
}

Write-Host ('FAIL: request_id_gaps_found count=' + $gaps.Count)
foreach ($gap in $gaps) {
    Write-Host ("- {0}:{1} [{2}] {3}" -f $gap.file, $gap.line, $gap.kind, $gap.snippet)
}
exit 1
