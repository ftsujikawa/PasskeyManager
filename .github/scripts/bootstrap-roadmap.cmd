@echo off
setlocal

where gh >nul 2>nul
if errorlevel 1 echo [ERROR] GitHub CLI (gh) not found. Install gh first.
if errorlevel 1 exit /b 1

gh auth status >nul 2>nul
if errorlevel 1 echo [ERROR] gh is not authenticated. Run: gh auth login
if errorlevel 1 exit /b 1

gh repo view >nul 2>nul
if errorlevel 1 echo [ERROR] No default repository. Run in repo root or: gh repo set-default ^<ORG/REPO^>
if errorlevel 1 exit /b 1

powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $lines=Get-Content -Encoding UTF8 -Path '%~f0'; $idx=[Array]::IndexOf($lines, ':__PWSH__'); if ($idx -lt 0) { throw 'Embedded PowerShell block not found.' }; $start=$idx+1; $script=($lines[$start..($lines.Count-1)] -join [Environment]::NewLine); Invoke-Expression $script"

if errorlevel 1 echo [ERROR] bootstrap failed.
if errorlevel 1 exit /b 1

echo [OK] bootstrap finished.
exit /b 0

:__PWSH__
$ErrorActionPreference='Stop'

function Ensure-Label {
  param([string]$Name,[string]$Color,[string]$Description)
  gh label create $Name --color $Color --description $Description 2>$null
  if ($LASTEXITCODE -ne 0) {
    gh label edit $Name --color $Color --description $Description | Out-Null
  }
}

function New-IssueIfNotExists {
  param([string]$Title,[string]$Priority,[int]$SP,[string]$Depends,[string]$DoD,[string[]]$Labels)
  $existing = gh issue list --state open --search $Title --json title,number | ConvertFrom-Json
  if ($existing -and ($existing | Where-Object { $_.title -eq $Title })) {
    Write-Host ('[skip] exists: ' + $Title)
    return
  }

  $body = @'
## 概要
__TITLE__

## 優先度
__PRIORITY__

## 見積り
__SP__ SP

## 依存
__DEPENDS__

## 受け入れ条件（DoD）
__DOD__
'@

  $body = $body.Replace('__TITLE__',$Title).Replace('__PRIORITY__',$Priority).Replace('__SP__', [string]$SP).Replace('__DEPENDS__',$Depends).Replace('__DOD__',$DoD)
  $labelArgs=@()
  foreach($lb in $Labels){ $labelArgs += @('--label',$lb)}
  gh issue create --title $Title --body $body @labelArgs | Out-Null
  Write-Host ('[created] ' + $Title)
}

$labels = @(
@{ n='roadmap'; c='1D76DB'; d='Long-term roadmap item' },@{ n='tier1'; c='0E8A16'; d='Tier 1 (0-6 months)' },@{ n='tier2'; c='2DA44E'; d='Tier 2 (6-12 months)' },@{ n='tier3'; c='5319E7'; d='Tier 3 (12-18 months)' },@{ n='sprint1'; c='BFDADC'; d='Sprint 1' },@{ n='sprint2'; c='C2E0C6'; d='Sprint 2' },@{ n='sprint3'; c='F9D0C4'; d='Sprint 3' },
@{ n='sync'; c='0366D6'; d='Sync engine and behavior' },@{ n='sync-history'; c='0052CC'; d='Sync history and restore' },@{ n='conflict'; c='D93F0B'; d='Conflict handling (409)' },@{ n='queue'; c='FBCA04'; d='Offline queue and retry' },@{ n='metrics'; c='6F42C1'; d='Operational metrics' },@{ n='vault'; c='A2EEEF'; d='Vault data and protection' },@{ n='ui'; c='C5DEF5'; d='UI/UX changes' },@{ n='logging'; c='B60205'; d='Logging and diagnostics' },@{ n='perf'; c='F9D0C4'; d='Performance improvements' },@{ n='ops'; c='7057FF'; d='Operations and runbooks' },@{ n='docs'; c='0075CA'; d='Documentation' },@{ n='test'; c='BFD4F2'; d='Testing and validation' },
@{ n='P0'; c='B60205'; d='Highest priority' },@{ n='P1'; c='D93F0B'; d='High priority' },@{ n='P2'; c='FBCA04'; d='Normal priority' },@{ n='SP:2'; c='EDEDED'; d='Story points 2' },@{ n='SP:3'; c='EDEDED'; d='Story points 3' },@{ n='SP:5'; c='EDEDED'; d='Story points 5' },@{ n='SP:8'; c='EDEDED'; d='Story points 8' }
)
foreach ($l in $labels) { Ensure-Label -Name $l.n -Color $l.c -Description $l.d }

$issues = @(
@{ t='feat(sync-history): 履歴エントリ型を追加'; p='P0'; sp=2; dep='なし'; dod='SyncHistoryEntryにtimestamp,operation,result,statusCode,errorCode,errorMessage,serverVersion,requestIdを定義。シリアライズ/デシリアライズ可能。'; l=@('roadmap','tier1','sprint1','sync-history','P0','SP:2') },
@{ t='feat(sync-history): ローカル永続ストア実装'; p='P0'; sp=5; dep='#1'; dod='1000件保持、上限超過時は古い順に削除。再起動後も履歴復元。'; l=@('roadmap','tier1','sprint1','sync-history','P0','SP:5') },
@{ t='feat(sync-history): 保存APIをMainPageログ更新に接続'; p='P0'; sp=3; dep='#2'; dod='UpdatePasskeyOperationStatusText呼び出し時に履歴保存。既存表示を壊さない。'; l=@('roadmap','tier1','sprint1','sync-history','P0','SP:3') },
@{ t='feat(ui): 履歴ListViewを追加（最新順）'; p='P0'; sp=3; dep='#3'; dod='MainPage.xamlに履歴一覧。最新先頭表示。'; l=@('roadmap','tier1','sprint1','ui','P0','SP:3') },
@{ t='feat(ui): 履歴詳細パネル（code/message/server_version）'; p='P1'; sp=3; dep='#4'; dod='項目選択で詳細表示。長文折り返し。'; l=@('roadmap','tier1','sprint1','ui','P1','SP:3') },
@{ t='feat(ui): 履歴フィルタ（success/warning/failed）'; p='P1'; sp=2; dep='#4'; dod='フィルタ切替で表示件数即時反映。Allで全件。'; l=@('roadmap','tier1','sprint1','ui','P1','SP:2') },
@{ t='feat(vault): 復元用スナップショット保存'; p='P0'; sp=5; dep='なし'; dod='同期前後で暗号化Vaultスナップショット保持。直近N件保持。'; l=@('roadmap','tier1','sprint1','vault','P0','SP:5') },
@{ t='feat(vault): 直前状態に復元API'; p='P0'; sp=5; dep='#7'; dod='復元前バックアップ取得。復元結果ログ出力。'; l=@('roadmap','tier1','sprint1','vault','P0','SP:5') },
@{ t='feat(ui): Restore Last Snapshotボタンと確認ダイアログ'; p='P1'; sp=3; dep='#8'; dod='確認ダイアログあり。成否をsyncStatusTextBlockに反映。'; l=@('roadmap','tier1','sprint1','ui','P1','SP:3') },
@{ t='test(sync-history): 履歴/復元の結合テスト'; p='P0'; sp=5; dep='#2,#8'; dod='履歴保存・再起動復元・スナップショット復元を自動テスト。破損データ系も含む。'; l=@('roadmap','tier1','sprint1','test','P0','SP:5') },
@{ t='feat(conflict): 競合解決戦略enum定義'; p='P0'; sp=2; dep='なし'; dod='LocalWins/ServerWins/MergeAttemptを定義。API指定可能。'; l=@('roadmap','tier1','sprint2','conflict','P0','SP:2') },
@{ t='feat(ui): 409競合ダイアログ（戦略選択）'; p='P0'; sp=3; dep='#11'; dod='409時のみ表示。選択結果保持。'; l=@('roadmap','tier1','sprint2','ui','conflict','P0','SP:3') },
@{ t='feat(sync): LocalWins実装'; p='P0'; sp=5; dep='#11,#12'; dod='server_version取得後に再PUT。ログにstrategy名。'; l=@('roadmap','tier1','sprint2','sync','conflict','P0','SP:5') },
@{ t='feat(sync): ServerWins実装'; p='P1'; sp=5; dep='#11,#12'; dod='サーバー状態取り込み後にローカル更新。欠損なし。'; l=@('roadmap','tier1','sprint2','sync','conflict','P1','SP:5') },
@{ t='feat(sync): MergeAttempt v1（時刻ベース）'; p='P1'; sp=8; dep='#11,#12'; dod='非衝突フィールド自動マージ。解決不能時は手動へ。'; l=@('roadmap','tier1','sprint2','sync','conflict','P1','SP:8') },
@{ t='feat(ui): 競合詳細表示（差分プレビュー）'; p='P1'; sp=5; dep='#12'; dod='local/server差分を視認可能。user_id,version,updated_at表示。'; l=@('roadmap','tier1','sprint2','ui','conflict','P1','SP:5') },
@{ t='feat(logging): 競合イベント監査ログ追加'; p='P1'; sp=3; dep='#13 or #14 or #15'; dod='strategy,outcome,serverVersion記録。履歴画面で確認可。'; l=@('roadmap','tier1','sprint2','logging','conflict','P1','SP:3') },
@{ t='test(conflict): 競合ケース自動テスト（10ケース）'; p='P0'; sp=5; dep='#13,#14,#15'; dod='主要分岐カバー。CI安定実行。'; l=@('roadmap','tier1','sprint2','test','conflict','P0','SP:5') },
@{ t='perf(conflict): 競合解決のタイムアウト/再試行制御'; p='P1'; sp=3; dep='#13,#15'; dod='UIフリーズなし。タイムアウト時に説明付き警告。'; l=@('roadmap','tier1','sprint2','perf','conflict','P1','SP:3') },
@{ t='docs(conflict): ユーザー向け競合解決ガイド'; p='P2'; sp=2; dep='#12,#13,#14'; dod='3戦略の使い分け説明。失敗時復旧手順を明記。'; l=@('roadmap','tier1','sprint2','docs','conflict','P2','SP:2') },
@{ t='feat(queue): オフラインキュー型定義'; p='P0'; sp=2; dep='なし'; dod='operation,payload,retries,nextRetryAt,createdAt定義。シリアライズ可能。'; l=@('roadmap','tier1','sprint3','queue','P0','SP:2') },
@{ t='feat(queue): キューストア永続化'; p='P0'; sp=5; dep='#21'; dod='再起動後キュー復元。上限設定可能。'; l=@('roadmap','tier1','sprint3','queue','P0','SP:5') },
@{ t='feat(sync): 失敗時のキュー投入（401/403除外）'; p='P0'; sp=3; dep='#22'; dod='429/5xx/ネットワーク断で投入。401/403は即警告。'; l=@('roadmap','tier1','sprint3','sync','queue','P0','SP:3') },
@{ t='feat(sync): バックグラウンド再送ワーカー'; p='P0'; sp=8; dep='#23'; dod='起動時に再送開始。成功時キュー削除。'; l=@('roadmap','tier1','sprint3','sync','queue','P0','SP:8') },
@{ t='feat(sync): 再送ポリシー（指数バックオフ + jitter）'; p='P1'; sp=5; dep='#24'; dod='500ms→1s→2s + jitter。最大試行超過でdead-letter。'; l=@('roadmap','tier1','sprint3','sync','queue','P1','SP:5') },
@{ t='feat(ui): キュー状態表示（件数/最終再送時刻）'; p='P1'; sp=3; dep='#24'; dod='MainPageでキュー件数可視化。リアルタイム反映。'; l=@('roadmap','tier1','sprint3','ui','queue','P1','SP:3') },
@{ t='feat(ui): Retry Queue Now手動再送'; p='P1'; sp=3; dep='#24'; dod='ボタン押下で即時再送。二重起動防止。'; l=@('roadmap','tier1','sprint3','ui','queue','P1','SP:3') },
@{ t='feat(metrics): 同期メトリクス収集'; p='P1'; sp=5; dep='#24'; dod='success_rate,retry_count,queue_depth,latency_p95収集。表示/JSON出力可。'; l=@('roadmap','tier1','sprint3','metrics','P1','SP:5') },
@{ t='test(queue): キュー/再送の障害注入テスト'; p='P0'; sp=5; dep='#24,#25'; dod='ネットワーク断/429/5xxで期待動作。二重送信なし。'; l=@('roadmap','tier1','sprint3','test','queue','P0','SP:5') },
@{ t='docs(ops): 運用Runbook（キュー詰まり・復旧）'; p='P2'; sp=2; dep='#26,#28'; dod='障害時確認手順を明文化。収集ログ項目を列挙。'; l=@('roadmap','tier1','sprint3','docs','ops','P2','SP:2') }
)

foreach ($i in $issues) {
  New-IssueIfNotExists -Title $i.t -Priority $i.p -SP $i.sp -Depends $i.dep -DoD $i.dod -Labels $i.l
}

Write-Host 'Done: labels ensured + issues created/skipped.'
gh issue list --limit 100
