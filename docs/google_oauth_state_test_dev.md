# Google OAuth 回帰テスト（開発者向け）

## 目的
Google OAuth の状態遷移と実装整合（UI表示・トークン保存・エラーガード）を、技術観点で確認する。

## 対象機能
- Sign-in / Disconnect の状態制御
- refresh_token の保存・再利用・削除
- 実行中ガード（多重起動防止）
- 接続詳細表示（最終接続時刻 / Token path）

## 事前条件
- MSIX パッケージ実行
- `appsetting.local.json` に有効な OAuth 設定
- `%LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalCache\Local\tsupasswd\` へアクセス可能

## 技術チェック項目

### 1. 初回サインイン
- 前提: `google_refresh_token.bin` が存在しない
- 操作: `Google Sign-in` 実行
- 期待:
  - ブラウザー起動は1回
  - ログ: `Google OAuth complete (refresh_token saved)`
  - `google_refresh_token.bin` が生成される
  - UI:
    - `Google Connected`
    - Sign-in 無効 / Disconnect 有効
    - `Google last connected` が時刻表示
    - `Token path` が `...\google_refresh_token.bin`

### 2. 再起動後の再利用
- 操作: アプリ再起動
- 期待:
  - Browser 起動なし
  - 新規 OAuth フロー開始なし
  - UI は接続済み状態を維持

### 3. Disconnect
- 操作: `Disconnect` 実行
- 期待:
  - ログ: `Google refresh_token removed. Sign-in required next time.`
  - トークンファイル削除
  - UI:
    - `Google Sign-in`
    - Disconnect 無効
    - `Google last connected: -`

### 4. Disconnect 後の再サインイン
- 操作: `Google Sign-in`
- 期待:
  - 初回同等に復帰（生成・表示・ボタン状態）

### 5. 多重起動ガード
- 前提: トークンなし
- 操作: `Google Sign-in` を連打
- 期待:
  - 追加実行が拒否される
  - ログ: `Google OAuth is already in progress...`
  - `state mismatch` が発生しない

### 6. OAuth Smoke Test
- 操作: `Run OAuth Smoke Test` 実行
- 期待:
  - ログ: `Running OAuth smoke test: state check + debug snapshot`
  - ログ: `Google state check:`（診断付き）
  - ログ: `OAuth smoke test debug snapshot:` または `debug snapshot is empty`

### 7. Vault Recovery 導線
- 前提: `ReadEncryptedVaultData` が missing / empty warning を出す状態
- 期待:
  - `vaultRecoveryHintText` が表示される
  - `Run Vault Recovery` ボタンが表示される
- 操作: `Run Vault Recovery` 実行
- 期待:
  - 成功時ログ: `Vault recovery completed...`
  - `vaultLockSwitch().IsOn(true)`
  - 復旧ヒントと復旧ボタンが非表示化される

## 障害切り分けメモ
- トークン未保存:
  - 保存先パス表示を確認
  - LocalCache 配下の実ファイル有無を確認
- state mismatch:
  - 多重クリック再現有無
  - 実行中ボタン無効化の動作確認
- vault 警告同時発生時:
  - `ReadEncryptedVaultData` の warning ログ種別（missing / empty）を確認

## 実行記録
- 実施者:
- 実施日時:
- ビルド/コミット:
- 結果:
  - [ ] 1 初回サインイン
  - [ ] 2 再利用
  - [ ] 3 Disconnect
  - [ ] 4 再サインイン
  - [ ] 5 多重起動ガード
  - [ ] 6 OAuth Smoke Test
  - [ ] 7 Vault Recovery 導線
- 備考:
