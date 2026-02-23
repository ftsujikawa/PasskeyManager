# PasskeyManager

PasskeyManager は、Windows 向けのパスキー管理/検証用アプリケーションです。

## Roadmap Issue 一括起票

ロードマップ用のラベル作成と Issue 一括起票は、以下のスクリプトで実行できます。

- `./.github/scripts/bootstrap-roadmap.cmd`

詳細手順は次のドキュメントを参照してください。

- `./.github/scripts/README.md`

### クイックスタート

1. GitHub CLI を認証

```powershell
gh auth login
```

2. （必要に応じて）対象リポジトリを設定

```powershell
gh repo set-default <ORG_OR_USER>/<REPO>
```

3. リポジトリルートで実行

```powershell
.\.github\scripts\bootstrap-roadmap.cmd
```

### 再実行時の挙動

- 同名タイトルの open issue は作成スキップされます。
- ラベルは作成失敗時に更新にフォールバックします。
- 依存番号（`#1` 形式）はテンプレート値なので、起票後に必要なら更新してください。
