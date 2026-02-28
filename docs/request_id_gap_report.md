# request_id Gap Report (Operational summary/sync logs)

## Scope
- Source: `*.cpp` under repository
- Target lines: string literals beginning with `INFO|SUCCESS|WARNING|FAILED` and containing `summary` or `sync`
- Rule: detect lines without `request_id=`

## Result
### 1) Fixed in this step
- `MainPage::ReloadSnapshotCandidates` の運用ログ2行に `request_id` を追加済み
  - `INFO: sync state=ready operation=load_snapshot_candidates ... selected=latest`
  - `INFO: sync state=ready operation=load_snapshot_candidates ... reason=no_snapshot_history`

### 2) Remaining detections
Current detections are all **intermediate string fragments** in multi-line concatenation, where `request_id` is appended later in the same function/block.

- `PluginManagement/PluginRegistrationManager.cpp`
  - around line 598 (`retry_conflict` fragment)
  - around line 634 (`retry_backoff` fragment)
  - around line 652 (`sync result=failed` fragment)
  - around line 883 (`summary result=warning` fragment)
  - around line 891 (`summary state=observed` fragment)
  - around line 986 (`summary state=observed` fragment)
  - around line 1350 (`snapshot_not_found` warning fragment)
  - around line 1365 (`sync result=failed` warning fragment)
  - around line 1404 (`sync result=success` success fragment)

## Interpretation
- After this update, user-visible operational log lines in `MainPage.xaml.cpp` are aligned with `request_id` policy for the targeted areas.
- Remaining detections are not direct policy violations but scan limitations caused by line-based matching over split string assembly.

## Suggested next step
- If we enforce repo-wide static checks, switch from line-based to block-aware checks (or check emitted runtime samples only).
