# tsupasswd_core Threat Model (A-01 / STRIDE)

最終更新: 2026-02-26
対象: PasskeyManager (`tsupasswd_core`) + sync-mvp-api

## 1. スコープ

### In Scope
- ローカルVaultの暗号化保存・復号
- Passkey作成/利用によるVaultリカバリ
- sync-mvp-api との同期（PUT/GET, Bearer認証）
- 復元（restore_snapshot）/手動再同期（manual_resync）
- 運用フロー（deploy, preflight, rollback, backup）

### Out of Scope (本ドキュメント初版)
- ブラウザ拡張自動入力
- 組織向け高度権限管理
- 外部IdP連携

## 2. 保護対象資産

1. Vault暗号文 (`EncryptedVaultData`)
2. 鍵素材（HMAC secret / entropy / DPAPI保護コンテキスト）
3. 同期認証情報（Bearer token）
4. ユーザー識別子 (`TSUPASSWD_SYNC_USER_ID`)
5. 監査相関情報（`request_id`, `failure_kind`, `message_code`）
6. バックアップ/スナップショット（server/local）

## 3. 信頼境界

1. **Windowsローカル端末**
   - PasskeyManager プロセス
   - レジストリ (`HKCU\\Software\\Contoso\\PasskeyManager`)
   - ローカルファイル/アプリデータ
2. **ネットワーク境界**
   - `SyncClient` (WinHTTP)
   - sync-mvp-api (HTTP/HTTPS)
3. **サーバー境界**
   - sync-mvp-api 本体
   - SQLite DB / バックアップディレクトリ
4. **運用境界**
   - systemd service/timer
   - デプロイ/ロールバックスクリプト

## 4. データフロー（要約）

1. Passkey作成 (`CreateVaultPasskey`) で秘密情報を取得
2. Vault平文を DPAPI + (可能時)PRF由来entropy で暗号化
3. 暗号文をローカル保存し、同時に sync API へ PUT
4. 起動/復旧時にローカル読込 or server GET で復元
5. 失敗時は `request_id` を含む監査ログを出力

## 5. STRIDE分析

| ID | 区分 | 脅威 | 影響 | 現状対策 | 追加対策 | 優先度 |
|---|---|---|---|---|---|---|
| T01 | Spoofing | Bearer token漏洩による不正API利用 | 他者Vault上書き/取得 | Bearer必須、403/401制御 | 短寿命トークン化、ローテーション自動化、IP/レート制限強化 | High |
| T02 | Spoofing | `TSUPASSWD_SYNC_USER_ID` なりすまし | 異ユーザー領域アクセス | userIdを明示指定 | サーバー側で主体とuserIdの結合検証 | High |
| T03 | Tampering | ローカル暗号文（レジストリ値）改ざん | 復号失敗/不正状態 | サイズ下限/上限チェック、整合失敗時エラー | 暗号文に署名/整合タグ検証を追加 | High |
| T04 | Tampering | 同期レスポンス改ざん（平文HTTP） | 不正データ復元 | 失敗時検出あり | HTTPS強制、証明書運用手順追加済みを必須化 | High |
| T05 | Repudiation | 操作主体の否認 | 監査不能 | `request_id`/`failure_kind` ログ整備 | サーバー監査ログ保存期間/改ざん耐性の明文化 | Medium |
| T06 | Information Disclosure | レジストリ平文保存されたHMAC秘密 | 秘密漏洩による保護低下 | なし（コードコメントで課題認識） | HMAC secret の暗号化保管 or 外部保管へ移行 | High |
| T07 | Information Disclosure | ログへの機微出力混入 | 情報漏洩 | log checkerで禁止マーカー監視 | CI必須化 + 本番ログマスキング | Medium |
| T08 | Denial of Service | API過負荷/大量リトライ | 同期不可 | レート制限設定あり | バックオフ標準化、429時クライアント制御 | Medium |
| T09 | Denial of Service | バックアップ肥大化でディスク枯渇 | サービス停止 | pruneスクリプト/maintenance timer | 閾値監視とアラート追加 | Medium |
| T10 | Elevation of Privilege | 過剰権限でのサービス実行 | 侵害時影響拡大 | systemdで運用手順あり | 実行ユーザー最小権限化、Capability最小化 | High |

## 6. 優先対応バックログ（A-02入力）

### P0 (直近)
1. HMAC secret の平文保管廃止（T06）
2. 同期通信の HTTPS 強制と平文HTTP拒否（T04）
3. userId と認証主体のサーバー側結合検証（T02）

### P1
1. 暗号文整合性検証の強化（T03）
2. 監査ログ保持・改ざん耐性の運用定義（T05）
3. 最小権限実行ガイド整備（T10）

### P2
1. レート制限/再試行ポリシー最適化（T08）
2. バックアップ容量監視（T09）

## 7. 完了条件（A-01 DoD）

- [x] 資産一覧の定義
- [x] 信頼境界の定義
- [x] STRIDE別に脅威を列挙
- [x] High脅威に追加対策を割当
- [x] A-02（鍵設計ADR）への入力項目を抽出
