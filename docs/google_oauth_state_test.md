# Google OAuth 状態回帰テストチェックリスト

## 実行ログテンプレート
- 担当者:
- 実施日時:
- ビルド/コミット:
- 環境（MSIX パッケージファミリー / OS）:

## 事前条件
- ビルド対象: パッケージ版アプリ（MSIX）
- `appsetting.local.json` に有効な Google OAuth 認証情報が設定されている
- ネットワーク接続が利用可能

## テストケース

### 1) 初回サインイン（保存済みトークンなし）
1. トークンファイルが存在しないことを確認する:
   - `%LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalCache\Local\tsupasswd\google_refresh_token.bin`
2. アプリを起動し、MainPage を開く。
3. ボタン表示が `Google Sign-in` で、Disconnect が無効になっていることを確認する。
4. ステータス表示が以下であることを確認する:
   - `Google last connected: -`
   - `Token path: ...\google_refresh_token.bin`
5. `Google Sign-in` をクリックする。
6. 期待結果:
   - ブラウザーが 1 回だけ起動する。
   - ログに `Google OAuth complete (refresh_token saved)` が出力される。
   - ボタン表示が `Google Connected` に変わる。
   - `Google Sign-in` が無効、Disconnect が有効になる。
   - `Google last connected:` がローカル時刻に更新される。

### 2) 保存済みトークン再利用（ブラウザー起動なし）
1. アプリを再起動する。
2. ボタン表示が `Google Connected` であることを確認する。
3. `Token path` がマスク表示（`...\google_refresh_token.bin`）のままであることを確認する。
4. `Google Connected` ボタン（無効状態でクリック不可）を確認する。
5. 期待結果:
   - ブラウザーが起動しない。
   - 新規 OAuth フローが開始されない。

### 3) Disconnect フロー
1. `Disconnect` をクリックする。
2. 期待結果:
   - ログに `Google refresh_token removed. Sign-in required next time.` が出力される。
   - ボタン表示が `Google Sign-in` に戻る。
   - Disconnect が無効になる。
   - トークンファイルが削除される。
   - `Google last connected: -` 表示に戻る。

### 4) Disconnect 後の再サインイン
1. `Google Sign-in` をクリックする。
2. 期待結果:
   - ブラウザーが 1 回だけ起動する。
   - OAuth が完了し、トークンファイルが再作成される。
   - UI が接続済み状態に戻る。

### 5) 多重クリック防止ガード
1. 保存済みトークンがない状態で、`Google Sign-in` を連打する。
2. 期待結果:
   - フロー実行中は追加起動がブロックされる。
   - 警告ログ `Google OAuth is already in progress...` が表示される。

### 6) OAuth Smoke Test 実行
1. `Run OAuth Smoke Test` をクリックする。
2. 期待結果:
   - ログに `Running OAuth smoke test: state check + debug snapshot` が出る。
   - 続けて `Google state check:` を含む状態ログが出る。
   - `OAuth smoke test debug snapshot:` または `debug snapshot is empty` が出る。

### 7) Vault Recovery 実行導線
1. Vault の暗号データ欠損/破損状態を作る（または同等の警告を再現する）。
2. 期待結果:
   - `Vault recovery:` ヒントが表示される。
   - `Run Vault Recovery` ボタンが表示される。
3. `Run Vault Recovery` をクリックする。
4. 期待結果:
   - 成功時は `Vault recovery completed...` ログが表示される。
   - `vaultLockSwitch` が Passkey 側になる。
   - ヒント表示と `Run Vault Recovery` ボタンが非表示になる。

## 実行結果記録（実行後に記入）
- [ ] ケース1 pass / fail
- [ ] ケース2 pass / fail
- [ ] ケース3 pass / fail
- [ ] ケース4 pass / fail
- [ ] ケース5 pass / fail
- [ ] ケース6 pass / fail
- [ ] ケース7 pass / fail
- 検出した問題:
  -
- 関連アプリログ:
  -

## 合格基準
- 接続済み状態で想定外のブラウザー再起動が発生しない。
- サインイン / 切断 / 再起動の各操作で UI 状態とトークンファイル状態が一貫している。
- UI 多重起動による `state mismatch` が発生しない。
- OAuth Smoke Test 実行で状態ログとデバッグスナップショット結果が必ず残る。
- Vault 警告時の復旧導線表示と復旧後の非表示遷移が一貫している。
