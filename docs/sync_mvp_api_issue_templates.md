# sync-mvp-api 既知課題 Issue テンプレート

このファイルは、運用確認で挙がった既知課題を GitHub Issue 化するためのテンプレートです。

---

## 1) sync-mvp-api: move persistence from JSON file to DB

### Summary
`sync-mvp-api` は現在 `vault-store.json` へのファイル保存で永続化している。運用継続に向けて DB 永続化へ移行したい。

### Background
- 現在は単一ファイル I/O に依存
- 同時更新や障害時リカバリの堅牢性に限界がある
- 将来的な検索・運用分析が難しい

### Scope
- 保存先を JSON ファイルから DB に置き換える
- `GET /v1/vaults/{userId}` / `PUT /v1/vaults/{userId}` の API 契約は維持
- 既存データ（JSON）移行手順を用意

### Out of Scope
- 新規 API 追加
- 複雑なマルチリージョン設計

### Acceptance Criteria
- [ ] DB を使って vault の read/write ができる
- [ ] 既存 API のレスポンス互換性が維持される
- [ ] 409 競合ロジックが DB 移行後も同等に動作する
- [ ] 旧 JSON データからの移行手順が文書化される

### Notes
- 候補: PostgreSQL / SQLite（初期は SQLite でも可）

---

## 2) sync-mvp-api: enforce stricter TLS / security headers

### Summary
公開運用のセキュリティ強化として TLS 設定を厳格化し、主要なセキュリティヘッダを有効化する。

### Background
- 現在は nginx + Let's Encrypt で TLS は動作中
- 追加の防御（ヘッダ、設定見直し）を明示化したい

### Scope
- TLS 設定の見直し（不要なプロトコル/暗号スイート除外）
- セキュリティヘッダ追加（HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy 等）
- 設定後の疎通確認手順を docs 化

### Out of Scope
- WAF 導入
- CDN 導入

### Acceptance Criteria
- [ ] `nginx -t` が成功し、reload 後も API が正常応答
- [ ] 主要セキュリティヘッダがレスポンスで確認できる
- [ ] TLS 設定変更後も `GET/PUT` の既存フローが壊れない

---

## 3) sync-mvp-api: add audit logging for vault operations

### Summary
監査性向上のため、vault 操作（GET/PUT/403/409）に対する監査ログを整備する。

### Background
- 現在は ASP.NET の標準ログ中心
- 誰が・いつ・何をしたかの追跡情報が不足

### Scope
- 監査ログ項目を定義（timestamp, user_id, method, result_code, remote_addr など）
- 成功/失敗（403/409含む）を一貫して記録
- 個人情報/機微データは記録しない方針を明文化

### Out of Scope
- SIEM 連携の本実装

### Acceptance Criteria
- [ ] 監査ログフォーマットが定義・実装される
- [ ] 403/409 を含む主要イベントが記録される
- [ ] vault 実データ本文はログ出力しない
- [ ] ログ保管期間・ローテーション方針が docs に追記される

---

## 4) sync-mvp-api: add rate limiting for /v1/vaults endpoints

### Summary
過負荷・悪用対策として `/v1/vaults/*` にレート制限を導入する。

### Background
- 現在はレート制限なし
- ブルートフォースや高頻度アクセスに対する防御層が必要

### Scope
- `/v1/vaults/{userId}` の GET/PUT にレート制限適用
- 制限超過時は適切なステータス（例: 429）を返す
- 閾値設定を運用で調整可能にする（環境変数または設定ファイル）

### Out of Scope
- アカウント凍結機能
- 高度な bot 判定

### Acceptance Criteria
- [ ] しきい値超過で 429 が返る
- [ ] 正常利用範囲では既存フローに影響がない
- [ ] 閾値を設定で変更可能
- [ ] 運用手順（確認コマンド含む）が docs に追記される
