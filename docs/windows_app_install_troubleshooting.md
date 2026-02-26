# Windows App Install Troubleshooting

## 0x80073cfb: 非パッケージ版との競合

### 症状

アプリインストール時に以下エラーが出る。

- `現在のユーザーが、このアプリのパッケージ化されていないバージョンを既にインストールしています。`
- `競合するパッケージ: Contoso.tsupasswdcore`
- `0x80073cfb`

### 原因

同一アプリ ID の「非パッケージ版（unpackaged）」が既に存在し、MSIX などのパッケージ版へ置き換えできない。

### 対処手順（PowerShell）

1. 既存インストールを確認

```powershell
Get-AppxPackage -AllUsers *tsupasswdcore* | Select Name, PackageFullName, PackageUserInformation
```

2. 既存版をアンインストール

```powershell
Get-AppxPackage *tsupasswdcore* | Remove-AppxPackage
```

必要に応じて（管理者 PowerShell）:

```powershell
Get-AppxPackage -AllUsers *tsupasswdcore* | ForEach-Object { Remove-AppxPackage -Package $_.PackageFullName -AllUsers }
```

3. パッケージ版を再インストール

```powershell
Add-AppxPackage "C:\path\to\your.msix"
```

### 追加調査（再発時）

```powershell
Get-AppxPackage -AllUsers *tsupasswdcore* | Format-List *
Get-AppPackageLog -ActivityID <ActivityId>
```
