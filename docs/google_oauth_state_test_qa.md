# Google OAuth 回帰テスト（QA向け）

## テスト目的
ユーザー操作として、Google 接続・切断が正しく動くことを確認する。

## 事前準備
- パッケージ版アプリ（MSIX）を起動できる
- Google OAuth 設定済み（開発チーム準備済み）

## テスト手順

### ケース1: 初回接続
1. アプリを起動する
2. `Google Sign-in` が表示されていることを確認する
3. `Disconnect` が押せないことを確認する
4. `Google Sign-in` を押す
5. ブラウザーで Google 認証を完了する

期待結果:
- 認証後にアプリへ戻る
- `Google Connected` 表示になる
- `Disconnect` が押せるようになる
- ログに成功メッセージが表示される

### ケース2: 再起動後の状態維持
1. アプリを閉じて再起動する
2. 画面を開く

期待結果:
- `Google Connected` が維持される
- ブラウザーが自動で開かない

### ケース3: 切断
1. `Disconnect` を押す

期待結果:
- `Google Sign-in` 表示に戻る
- `Disconnect` が押せなくなる
- ログに切断完了メッセージが表示される

### ケース4: 切断後に再接続
1. `Google Sign-in` を押す
2. Google 認証を完了する

期待結果:
- 再び `Google Connected` になる
- `Disconnect` が押せる

### ケース5: 連打耐性
1. `Google Sign-in` を素早く複数回押す

期待結果:
- 認証処理は1回だけ開始される
- エラーで止まらない

### ケース6: OAuth Smoke Test
1. `Run OAuth Smoke Test` を押す

期待結果:
- 実行開始ログが表示される
- `Google state check` を含む状態ログが表示される
- debug snapshot の結果ログが表示される

### ケース7: Vault Recovery
1. Vault データ欠損/破損警告が出る状態を用意する
2. `Run Vault Recovery` が表示されることを確認する
3. `Run Vault Recovery` を押す

期待結果:
- 復旧完了ログが表示される
- 復旧ヒントとボタンが消える
- Vault Unlock Method が Passkey 側になる

## 判定
- [ ] ケース1 合格
- [ ] ケース2 合格
- [ ] ケース3 合格
- [ ] ケース4 合格
- [ ] ケース5 合格
- [ ] ケース6 合格
- [ ] ケース7 合格

## 不具合記録
- 発生手順:
- 実際の結果:
- 期待結果:
- 画面ログ/スクリーンショット:
