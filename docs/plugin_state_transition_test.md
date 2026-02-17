# Plugin State 遷移テスト（Register → Enable → Enabled）

## 目的
Register 後に `State: Disabled` となる仕様を前提に、Enable 導線と最終的な `Enabled` 遷移を確認する。

## 事前条件
- MSIX パッケージ版アプリ
- Plugin が未登録、または Disabled 状態を再現可能

## 手順

### 1) Register 後の状態
1. `Register` を押す
2. 期待結果:
   - ログに `Plugin registered` が出る
   - 状態表示が `Disabled` の場合、案内文が表示される
   - `Enable in Settings` ボタンが表示される

### 2) Enable 導線
1. `Enable in Settings` を押す
2. 期待結果:
   - `Opening Windows Settings for plugin activation...` ログが出る
   - `Windows Settings opened. Waiting for plugin state update...` ログが出る
   - Windows Settings（passkeys-advancedoptions）が開く

### 3) Enabled 遷移確認
1. Windows Settings で plugin を有効化する
2. アプリに戻り、最大10秒程度待つ（2秒間隔ポーリング）
3. 期待結果:
   - `Plugin state changed to Enabled.` ログが出る
   - 状態表示が `Enabled`
   - 案内文が非表示
   - Enable ボタン表示が `Enabled`

### 4) 自動再同期が間に合わない場合
1. Settings で有効化後、10秒程度待っても `Enabled` へ遷移しない場合
2. 期待結果:
   - `Plugin is still not Enabled. After enabling in Settings, click Refresh.` 警告が出る
3. `Refresh` を押す
4. 期待結果:
   - 状態表示が `Enabled` に更新される

## 異常系
- Settings を開けない場合:
  - `Failed to open Windows Settings...` 警告が出る
  - 手動導線（Settings > Accounts > Passkeys > Advanced options）で継続可能
