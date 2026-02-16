#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tsupasswd
{
    enum class LogLevel
    {
        Trace,
        Debug,
        Info,
        Warn,
        Error,
        Critical,
        Off,
    };

    struct ConfigDiagnostics
    {
        LogLevel LogLevelValue{ LogLevel::Info };
        bool LogToFile{ true };
        int32_t LogRetentionDays{ 7 };
        int32_t MaxLogFileSizeKB{ 1024 };
        bool EnableVerboseWinRTLogging{ false };
    };

    struct ConfigWebAuthnPlugin
    {
        bool Enabled{ true };
        std::wstring ExeArguments{ L"-PluginActivated" };
        int32_t OperationTimeoutMs{ 15000 };
    };

    struct ConfigWebAuthnBehavior
    {
        bool PreferPlatformAuthenticator{ true };
        bool AllowAutofillCapable{ true };
    };

    struct ConfigStorage
    {
        std::wstring SubDir{ L"tsupasswd" };
        std::wstring CacheDir{ L"cache" };
    };

    struct ConfigUi
    {
        std::wstring Theme{ L"system" };
        bool ShowDevCommands{ false };
    };

    struct ConfigGoogle
    {
        std::wstring ClientId{};
        std::wstring ClientSecret{};
        std::vector<std::wstring> Scopes{};
        int32_t LoopbackRedirectPort{ 0 };
    };

    struct AppConfig
    {
        int32_t SchemaVersion{ 1 };
        ConfigDiagnostics Diagnostics{};
        ConfigWebAuthnPlugin WebAuthnPlugin{};
        ConfigWebAuthnBehavior WebAuthnBehavior{};
        ConfigStorage Storage{};
        ConfigUi Ui{};
        ConfigGoogle Google{};
    };

    // 読み込み: 失敗しても既定値を返す（例外は投げない方針）
    AppConfig LoadConfigFromLocalAppData();

    AppConfig LoadConfigFromAppSettingsJson(std::wstring const& filePath);

    AppConfig LoadConfig();

    // 保存先（ディレクトリ/ファイル）生成
    std::wstring GetConfigDirectoryPath();
    std::wstring GetConfigFilePath();
}