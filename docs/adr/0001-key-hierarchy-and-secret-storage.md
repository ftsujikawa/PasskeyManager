# ADR-0001: Key Hierarchy and Secret Storage for tsupasswd_core

- Status: Accepted (Draft v1)
- Date: 2026-02-26
- Owners: Security / Core
- Related: A-01 (`docs/tsupasswd_core_threat_model.md`)

## Context

`tsupasswd_core` はローカルVault暗号文を保持し、`sync-mvp-api` へ同期する。
現状コードでは以下の構成が存在する。

- Vault暗号化: `CryptProtectData`（必要時 entropy に PRF派生値を利用）
- Vault保存先: `HKCU\\Software\\Contoso\\PasskeyManager\\EncryptedVaultData`
- PRF由来の HMAC secret: `HMACSecretInput` にレジストリ平文保存

A-01 で特定した High リスクのうち、特に以下をこの ADR で解消対象にする。

- T06: HMAC secret 平文保存
- T03: ローカル暗号文改ざん耐性不足
- T04: 同期経路の平文HTTP混在

## Decision

## 1) 鍵階層

以下の論理鍵階層を採用する。

1. **K_root_local**
   - 端末ローカルの最上位鍵（DPAPIで保護）
   - 外部送信しない
2. **K_unlock**
   - Passkey PRF（利用可能時）から導出する鍵素材
   - PRF非対応時は `K_root_local` のみで復号可能なフォールバックを許容（暫定）
3. **K_vault_data (DEK)**
   - Vaultデータ暗号化に使うデータ鍵
   - 直接保存せず、`K_root_local`/`K_unlock` により保護された形で保持
4. **K_sync_auth**
   - 同期API認証用 Bearer token
   - 暗号鍵ではないが同等の機密として保護対象に含める

## 2) 保存方針

1. **禁止**: PRF由来生秘密（現 `HMACSecretInput`）の平文永続化
2. **許可**: 秘密値の永続化が必要な場合、少なくとも DPAPI 保護 blob として保存
3. Vault暗号文 (`EncryptedVaultData`) はサイズ検証に加えて整合性検証を追加
4. Bearer token は `.env` / 環境変数で管理し、ログ出力禁止

## 3) 暗号・導出ルール（v1）

1. PRF available の場合:
   - `K_unlock = HKDF-SHA256(PRF_output, salt=device_salt, info="tsupasswd_core/unlock/v1")`
2. PRF unavailable の場合:
   - `K_unlock` を使わず `K_root_local` のみ（互換目的）
3. Vault暗号化は当面 DPAPI を継続し、将来は AEAD（AES-GCM）へ移行可能なメタを保持
4. 乱数は OS CSPRNG (`BCryptGenRandom`) のみを使用

## 4) 同期経路ポリシー

1. 本番は HTTPS を必須とし、HTTP を拒否
2. 開発環境のみ HTTP 許容（明示フラグ必須）
3. `SyncClient` は `https://` 以外で警告ではなく失敗を返すモードを実装

## 5) ローテーション

1. Bearer token: 定期ローテーション（既存 `rotate_sync_mvp_api_token.sh`）
2. `K_root_local` 再生成イベント:
   - Vault recovery 実行時
   - 復号整合性異常検知時
3. 鍵更新時は `request_id` を伴う監査ログを必須化

## Consequences

### Positive
- 平文秘密の常駐を排除できる
- 脅威 T06/T03/T04 への具体対策が確定
- A-03（Recovery）での鍵ライフサイクル定義が容易になる

### Negative / Trade-off
- PRF非対応デバイス互換維持のため一時的に二重運用が必要
- 移行期間中は旧レジストリ値のマイグレーション処理が必要

## Implementation Plan (follow-up tickets)

1. **SEC-KEY-01**: `SetHMACSecret` の平文レジストリ保存を廃止し DPAPI 保護 blob 化
2. **SEC-KEY-02**: 起動時マイグレーション（旧 `HMACSecretInput` -> 新形式）
3. **SEC-KEY-03**: `ReadEncryptedVaultData` に整合性検証メタを追加
4. **SEC-NET-01**: `SyncClient` の HTTPS 必須モード導入
5. **SEC-LOG-01**: 鍵更新/復旧イベントの監査ログ標準化

## Verification

- 単体: 秘密の平文保存が発生しないこと
- 結合: recovery -> encrypt -> sync -> restore が成功
- セキュリティ: レジストリダンプに生秘密が含まれないこと
- 回帰: 既存ログ checker と sync smoke が全PASS

## Notes

本ADRは v1 であり、将来的に「VaultデータをDPAPI依存からAEAD + key envelopeへ移行」する際の上位方針として維持する。
