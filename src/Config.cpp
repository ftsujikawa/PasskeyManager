#include "pch.h"
#include "Config.h"

#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>

#include <fstream>
#include <sstream>

#include <winrt/Windows.Data.Json.h>

#pragma comment(lib, "Shlwapi.lib")

namespace tsupasswd
{
    static std::wstring GetKnownFolderPath(REFKNOWNFOLDERID folderId)
    {
        PWSTR path = nullptr;
        HRESULT hr = SHGetKnownFolderPath(folderId, 0, nullptr, &path);
        if (FAILED(hr) || path == nullptr)
        {
            return L"";
        }

        std::wstring result(path);
        CoTaskMemFree(path);
        return result;
    }

    std::wstring GetConfigDirectoryPath()
    {
        std::wstring base = GetKnownFolderPath(FOLDERID_LocalAppData);
        if (base.empty())
        {
            return L"";
        }

        if (base.back() != L'\\')
        {
            base.push_back(L'\\');
        }

        base += L"tsupasswd";
        return base;
    }

    std::wstring GetConfigFilePath()
    {
        std::wstring dir = GetConfigDirectoryPath();
        if (dir.empty())
        {
            return L"";
        }

        dir += L"\\config.json";
        return dir;
    }

    static void EnsureDirectoryExists(std::wstring const& path)
    {
        if (path.empty())
        {
            return;
        }

        // 既にある場合も成功扱い
        (void)SHCreateDirectoryExW(nullptr, path.c_str(), nullptr);
    }

    static std::string ReadAllTextUtf8(std::wstring const& filePath)
    {
        std::ifstream ifs(filePath, std::ios::in | std::ios::binary);
        if (!ifs)
        {
            return {};
        }

        std::ostringstream oss;
        oss << ifs.rdbuf();
        return oss.str();
    }

    static LogLevel ParseLogLevel(std::wstring const& level)
    {
        if (level == L"trace") return LogLevel::Trace;
        if (level == L"debug") return LogLevel::Debug;
        if (level == L"info") return LogLevel::Info;
        if (level == L"warn") return LogLevel::Warn;
        if (level == L"error") return LogLevel::Error;
        if (level == L"critical") return LogLevel::Critical;
        if (level == L"off") return LogLevel::Off;
        return LogLevel::Info;
    }

    static bool TryGetObject(winrt::Windows::Data::Json::JsonObject const& obj, wchar_t const* key, winrt::Windows::Data::Json::JsonObject& out)
    {
        if (!obj.HasKey(key))
        {
            return false;
        }

        auto value = obj.GetNamedValue(key, nullptr);
        if (!value || value.ValueType() != winrt::Windows::Data::Json::JsonValueType::Object)
        {
            return false;
        }

        out = value.GetObjectW();
        return true;
    }

    static bool TryGetString(winrt::Windows::Data::Json::JsonObject const& obj, wchar_t const* key, std::wstring& out)
    {
        if (!obj.HasKey(key))
        {
            return false;
        }

        auto value = obj.GetNamedValue(key, nullptr);
        if (!value || value.ValueType() != winrt::Windows::Data::Json::JsonValueType::String)
        {
            return false;
        }

        out = value.GetString(); // 修正: std::wstring型に直接代入
        return true;
    }

    static bool TryGetBool(winrt::Windows::Data::Json::JsonObject const& obj, wchar_t const* key, bool& out)
    {
        if (!obj.HasKey(key))
        {
            return false;
        }

        auto value = obj.GetNamedValue(key, nullptr);
        if (!value || value.ValueType() != winrt::Windows::Data::Json::JsonValueType::Boolean)
        {
            return false;
        }

        out = value.GetBoolean();
        return true;
    }

    static bool TryGetInt32(winrt::Windows::Data::Json::JsonObject const& obj, wchar_t const* key, int32_t& out)
    {
        if (!obj.HasKey(key))
        {
            return false;
        }

        auto value = obj.GetNamedValue(key, nullptr);
        if (!value || value.ValueType() != winrt::Windows::Data::Json::JsonValueType::Number)
        {
            return false;
        }

        // JSON number は double。範囲/丸めは最小限の防御だけ。
        double d = value.GetNumber();
        if (d < static_cast<double>(INT32_MIN) || d > static_cast<double>(INT32_MAX))
        {
            return false;
        }

        out = static_cast<int32_t>(d);
        return true;
    }

    AppConfig LoadConfigFromLocalAppData()
    {
        // WinRT JSON を使うので WinRT 初期化（WinUI3 なら既に初期化済みのことが多いが、安全側）
        winrt::init_apartment(winrt::apartment_type::multi_threaded);

        AppConfig cfg{};

        std::wstring dirPath = GetConfigDirectoryPath();
        std::wstring filePath = GetConfigFilePath();
        if (dirPath.empty() || filePath.empty())
        {
            return cfg;
        }

        EnsureDirectoryExists(dirPath);

        std::string jsonUtf8 = ReadAllTextUtf8(filePath);
        if (jsonUtf8.empty())
        {
            return cfg; // ない/読めない → 既定
        }

        try
        {
            // WinRT の Parse は UTF-16 文字列入力
            std::wstring jsonW = winrt::to_hstring(jsonUtf8).c_str();
            auto root = winrt::Windows::Data::Json::JsonObject::Parse(jsonW);

            // schemaVersion
            (void)TryGetInt32(root, L"schemaVersion", cfg.SchemaVersion);

            // diagnostics
            winrt::Windows::Data::Json::JsonObject diagnostics;
            if (TryGetObject(root, L"diagnostics", diagnostics))
            {
                std::wstring level;
                if (TryGetString(diagnostics, L"logLevel", level))
                {
                    cfg.Diagnostics.LogLevelValue = ParseLogLevel(level);
                }

                (void)TryGetBool(diagnostics, L"logToFile", cfg.Diagnostics.LogToFile);
                (void)TryGetInt32(diagnostics, L"logRetentionDays", cfg.Diagnostics.LogRetentionDays);
                (void)TryGetInt32(diagnostics, L"maxLogFileSizeKB", cfg.Diagnostics.MaxLogFileSizeKB);
                (void)TryGetBool(diagnostics, L"enableVerboseWinRTLogging", cfg.Diagnostics.EnableVerboseWinRTLogging);
            }

            // webauthn
            winrt::Windows::Data::Json::JsonObject webauthn;
            if (TryGetObject(root, L"webauthn", webauthn))
            {
                winrt::Windows::Data::Json::JsonObject plugin;
                if (TryGetObject(webauthn, L"plugin", plugin))
                {
                    (void)TryGetBool(plugin, L"enabled", cfg.WebAuthnPlugin.Enabled);

                    std::wstring args;
                    if (TryGetString(plugin, L"exeArguments", args))
                    {
                        cfg.WebAuthnPlugin.ExeArguments = args;
                    }

                    (void)TryGetInt32(plugin, L"operationTimeoutMs", cfg.WebAuthnPlugin.OperationTimeoutMs);
                }

                winrt::Windows::Data::Json::JsonObject behavior;
                if (TryGetObject(webauthn, L"behavior", behavior))
                {
                    (void)TryGetBool(behavior, L"preferPlatformAuthenticator", cfg.WebAuthnBehavior.PreferPlatformAuthenticator);
                    (void)TryGetBool(behavior, L"allowAutofillCapable", cfg.WebAuthnBehavior.AllowAutofillCapable);
                }
            }

            // storage
            winrt::Windows::Data::Json::JsonObject storage;
            if (TryGetObject(root, L"storage", storage))
            {
                std::wstring subDir;
                if (TryGetString(storage, L"subDir", subDir))
                {
                    cfg.Storage.SubDir = subDir;
                }

                std::wstring cacheDir;
                if (TryGetString(storage, L"cacheDir", cacheDir))
                {
                    cfg.Storage.CacheDir = cacheDir;
                }
            }

            // ui
            winrt::Windows::Data::Json::JsonObject ui;
            if (TryGetObject(root, L"ui", ui))
            {
                std::wstring theme;
                if (TryGetString(ui, L"theme", theme))
                {
                    cfg.Ui.Theme = theme;
                }

                (void)TryGetBool(ui, L"showDevCommands", cfg.Ui.ShowDevCommands);
            }
        }
        catch (...)
        {
            // パース失敗など → 既定値で起動
            return AppConfig{};
        }

        return cfg;
    }
}