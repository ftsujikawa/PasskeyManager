# Chrome Native Messaging Host

`tsupasswd_core.exe --native-messaging-host` を Chrome 拡張から Native Messaging Host として利用します。

## 実行モード

- 通常起動: WinUI アプリ
- `--native-messaging-host`: UI を起動せず stdin/stdout で JSON メッセージを処理

## サポート command

- `vault.status.get`
- `vault.login.list`
- `vault.login.get`
- `vault.login.save`
- `vault.login.update`
- `vault.login.delete`
- `vault.sync.resync`

## request 形式

```json
{
  "id": "req-1",
  "version": 1,
  "command": "vault.status.get",
  "payload": {}
}
```

## response 形式

```json
{
  "id": "req-1",
  "version": 1,
  "ok": true,
  "result": {
    "vaultLocked": false
  },
  "error": null
}
```

## Chrome manifest

`docs/chrome-native-messaging-host.example.json` をベースに、`allowed_origins` と `path` を実環境に合わせて設定します。

## 拡張側接続例

```javascript
const port = chrome.runtime.connectNative('dev.happyfactory.tsupasswd_core');
port.postMessage({
  id: 'req-1',
  version: 1,
  command: 'vault.status.get',
  payload: {}
});
port.onMessage.addListener((message) => {
  console.log(message);
});
```

## 注意

- `vault.login.list` は password を返しません
- `vault.login.get` は `includeSecret: true` のときだけ password を返します
- `vault.login.save/update/delete` は `resync: true` で同期まで実行します
- recovery code や sync 設定が無い場合は error response を返します
