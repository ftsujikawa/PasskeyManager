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
   - Windows Settings（passkeys-advancedoptions）が開く

### 3) Enabled 遷移確認
1. Windows Settings で plugin を有効化する
2. アプリに戻って `Refresh` を押す
3. 期待結果:
   - 状態表示が `Enabled`
   - 案内文が非表示
   - Enable ボタン表示が `Enabled`

## 異常系
- Settings を開けない場合:
  - `Failed to open Windows Settings...` 警告が出る
  - 手動導線（Settings > Accounts > Passkeys > Advanced options）で継続可能
