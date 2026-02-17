# Release Notes: Google OAuth UX/State Improvements

## 対象
- Google OAuth（Drive appdata scope）連携まわりの接続状態管理

## 変更概要

### 1. 接続済みUIの明確化
- `refresh_token` が存在する場合、`Google Sign-in` ボタンを `Google Connected` 表示に変更
- Connected 状態では Sign-in ボタンを無効化し、不要な再実行を防止

### 2. Disconnect 機能の追加
- `Disconnect` ボタンを追加
- クリック時に保存済み `google_refresh_token.bin` を削除
- 削除成功時は未接続状態（`Google Sign-in`）へ UI を戻す

### 3. OAuth 多重起動ガードとの整合
- OAuth 実行中は Sign-in / Disconnect を適切に無効化
- 完了時（成功/失敗）に UI 状態を一元更新

### 4. 状態遷移テスト手順の整備
- 手動確認チェックリストを追加
- 追加ファイル: `docs/google_oauth_state_test.md`

## 期待効果
- 接続済み時の誤操作（不要なブラウザ起動）を抑止
- 切断→再接続の動作が UI/保存状態と一致
- OAuth state mismatch の再発リスク低減（UI 連打起因）

## 影響範囲
- MainPage の Google OAuth 操作 UI
- Google refresh token 保存/削除処理
- 既存の OAuth フロー本体（PKCE/loopback）には仕様変更なし

## 動作確認
- `docs/google_oauth_state_test.md` の 1〜5 を実施

## 注意事項
- MSIX 実行時の token ファイルはコンテナ配下に作成される
  - `%LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalCache\Local\tsupasswd\google_refresh_token.bin`
