#pragma once

#include <cstdint>
#include <string>

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

    struct DiagnosticsConfig
    {
        LogLevel LogLevelValue = LogLevel::Info;
        bool LogToFile = false;
        int32_t LogRetentionDays = 7;
        int32_t MaxLogFileSizeKB = 1024;
        bool EnableVerboseWinRTLogging = false;
    };

    struct WebAuthnPluginConfig
    {
        bool Enabled = false;
        std::wstring ExeArguments;
        int32_t OperationTimeoutMs = 15000;
    };

    struct WebAuthnBehaviorConfig
    {
        bool PreferPlatformAuthenticator = true;
        bool AllowAutofillCapable = true;
    };

    struct StorageConfig
    {
        std::wstring SubDir;
        std::wstring CacheDir;
    };

    struct UiConfig
    {
        std::wstring Theme;
        bool ShowDevCommands = false;
    };

    struct AppConfig
    {
        int32_t SchemaVersion = 1;

        DiagnosticsConfig Diagnostics{};
        WebAuthnPluginConfig WebAuthnPlugin{};
        WebAuthnBehaviorConfig WebAuthnBehavior{};
        StorageConfig Storage{};
        UiConfig Ui{};
    };

    std::wstring GetConfigDirectoryPath();
    std::wstring GetConfigFilePath();
    AppConfig LoadConfigFromLocalAppData();
}