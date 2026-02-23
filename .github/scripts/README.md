# Roadmap Bootstrap Scripts

このディレクトリには、GitHub のラベル作成とロードマップ Issue 一括起票用スクリプトを配置します。

## 対象スクリプト

- `bootstrap-roadmap.cmd`
  - ラベル作成/更新
  - Sprint1〜3 の Issue 30件作成（既存タイトルはスキップ）

## 初回セットアップ

1. GitHub CLI をインストール
2. 認証

```powershell
gh auth login
```

3. 対象リポジトリを選択（必要な場合）

```powershell
gh repo set-default <ORG_OR_USER>/<REPO>
```

## 実行方法

リポジトリルートで実行:

```powershell
.\.github\scripts\bootstrap-roadmap.cmd
```

## 再実行時の注意

- 同名タイトルの **open issue** は作成をスキップします。
- ラベルは `create` 失敗時に `edit` へフォールバックするため、再実行で上書き可能です。
- 依存関係（`#1` など）はテンプレート文字列として投入されるため、必要に応じて実際の issue 番号に後で更新してください。

## トラブルシュート

- `gh auth status` が失敗する場合:
  - `gh auth login` を再実行
- `gh repo view` が失敗する場合:
  - 実行ディレクトリをリポジトリルートにする
  - もしくは `gh repo set-default` を設定
- 作成途中で中断した場合:
  - 同じコマンドを再実行（重複作成はスキップ）
