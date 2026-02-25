#pragma once

#include <pluginauthenticator.h>
#include "MainPage.g.h"
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#include <winrt/Microsoft.UI.Xaml.Documents.h>
#include "CredentialListViewModel.h"
#include "src/SyncSnapshotStore.h"
#include <winrt/Windows.Foundation.h>
#include "Converter/BitwiseFlagToVisibilityConverter.h"
#include <wil\filesystem.h>
#include <atomic>
#include <algorithm>
#include <ctime>
#include <cwctype>
#include <cwchar>
#include <vector>

namespace winrt {
    using namespace Windows::Foundation;
    using namespace Windows::Foundation::Collections;
    using namespace Windows::Storage::Streams;
}

namespace winrt::PasskeyManager::implementation
{
    struct MainPage : MainPageT<MainPage>
    {
        MainPage();
        ~MainPage();

        std::optional<DWORD> m_cookie{};

        PasskeyManager::CredentialListViewModel CredentialList()
        {
            return m_credentialListViewModel;
        }

        winrt::IAsyncAction refreshButton_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::IAsyncAction registerPluginButton_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::IAsyncAction updatePluginButton_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::IAsyncAction unregisterPluginButton_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::IAsyncAction addAllPluginCredentials_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::IAsyncAction addSelectedCredentials_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& e);
        winrt::IAsyncAction deleteAllPluginCredentials_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::IAsyncAction deleteSelectedPluginCredentials_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::IAsyncAction deleteSelectedPluginCredentialsEverywhere_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::IAsyncAction clearLogsButton_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::IAsyncAction deleteAllLocalCredentials_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::IAsyncAction deleteAllCredentials_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::IAsyncAction activatePluginButton_Click(IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e);
        winrt::IAsyncAction VaultUnlockControl_IsCheckedChanged(winrt::Microsoft::UI::Xaml::Controls::ToggleSplitButton const& sender, winrt::Microsoft::UI::Xaml::Controls::ToggleSplitButtonIsCheckedChangedEventArgs const& args);
        winrt::IAsyncAction TestPasskeyVaultUnlock_Click(IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e);
        winrt::IAsyncAction runVaultRecoveryButton_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::IAsyncAction loadSyncSettingsButton_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::IAsyncAction saveSyncSettingsButton_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::IAsyncAction testSyncConnectionButton_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::IAsyncAction manualSyncButton_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::IAsyncAction restoreSyncSnapshotButton_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::IAsyncAction refreshSnapshotCandidatesButton_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::IAsyncAction restoreSelectedSnapshotButton_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::IAsyncAction logsFilterCombo_SelectionChanged(IInspectable const& sender, Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const& args);
        winrt::IAsyncAction copyLatestLogButton_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& args);

        winrt::fire_and_forget UpdateCredentialList();

        winrt::IAsyncAction OnNavigatedTo(Microsoft::UI::Xaml::Navigation::NavigationEventArgs);

        static std::wstring MaskSensitiveLogText(std::wstring text)
        {
            auto applyMaskForKeyValue = [&](std::wstring const& marker)
            {
                std::wstring lowered = text;
                std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });

                std::wstring loweredMarker = marker;
                std::transform(loweredMarker.begin(), loweredMarker.end(), loweredMarker.begin(), [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });

                size_t pos = 0;
                while ((pos = lowered.find(loweredMarker, pos)) != std::wstring::npos)
                {
                    size_t valueStart = pos + marker.size();
                    size_t valueEnd = valueStart;
                    while (valueEnd < text.size() &&
                        !std::iswspace(text[valueEnd]) &&
                        text[valueEnd] != L',' &&
                        text[valueEnd] != L';' &&
                        text[valueEnd] != L'&')
                    {
                        ++valueEnd;
                    }

                    if (valueEnd > valueStart)
                    {
                        constexpr wchar_t kRedacted[] = L"[REDACTED]";
                        text.replace(valueStart, valueEnd - valueStart, kRedacted);
                        lowered.replace(valueStart, valueEnd - valueStart, L"[redacted]");
                        pos = valueStart + wcslen(kRedacted);
                    }
                    else
                    {
                        pos = valueStart;
                    }
                }
            };

            applyMaskForKeyValue(L"token=");
            applyMaskForKeyValue(L"bearer=");
            applyMaskForKeyValue(L"authorization=");
            applyMaskForKeyValue(L"authorization:");
            applyMaskForKeyValue(L"access_token=");
            applyMaskForKeyValue(L"refresh_token=");
            applyMaskForKeyValue(L"client_secret=");

            return text;
        }

        void UpdatePasskeyOperationStatusText(hstring const& statusText)
        {
            std::wstring maskedText = MaskSensitiveLogText(statusText.c_str());
            winrt::hstring maskedStatusText{ maskedText };

            m_logEntries.push_back(maskedStatusText);
            if (!m_isRestoringLogHistory)
            {
                PersistSyncHistoryEntry(maskedStatusText);
            }
            RebuildLogView();

            std::wstring status = maskedText;
            auto nowLabel = []() -> std::wstring
            {
                std::time_t raw = std::time(nullptr);
                std::tm tmLocal{};
                localtime_s(&tmLocal, &raw);
                wchar_t buffer[16]{};
                wcsftime(buffer, ARRAYSIZE(buffer), L"%H:%M:%S", &tmLocal);
                return buffer;
            };

            if (status.find(L"sync result=success") != std::wstring::npos)
            {
                syncStatusTextBlock().Text(winrt::hstring{ L"Sync status: Success at " + nowLabel() });
            }
            else if (status.find(L"sync result=failed") != std::wstring::npos &&
                (status.find(L"status=409") != std::wstring::npos || status.find(L"recovery=manual_resync_now") != std::wstring::npos))
            {
                syncStatusTextBlock().Text(
                    winrt::hstring{
                        L"Sync status: Conflict (409) at " + nowLabel() +
                        L". Click 'Resync Now' to refresh latest server version and retry." });
            }
            else if (status.find(L"sync result=failed") != std::wstring::npos)
            {
                syncStatusTextBlock().Text(winrt::hstring{ L"Sync status: Failed at " + nowLabel() + L" (see Logs)" });
            }
            else if (status.find(L"sync result=skipped") != std::wstring::npos)
            {
                syncStatusTextBlock().Text(winrt::hstring{ L"Sync status: Skipped at " + nowLabel() });
            }

            if (status.find(L"operation=read_encrypted_vault_data") != std::wstring::npos)
            {
                vaultRecoveryHintText().Text(L"Vault recovery: set Unlock Method to Passkey, create the vault passkey again, then retry unlock.");
                vaultRecoveryHintText().Visibility(Microsoft::UI::Xaml::Visibility::Visible);
                runVaultRecoveryButton().Visibility(Microsoft::UI::Xaml::Visibility::Visible);
            }
            else if ((status.find(L"operation=vault_recovery") != std::wstring::npos && status.find(L"outcome=passkey_created") != std::wstring::npos) ||
                (status.find(L"operation=vault_recovery") != std::wstring::npos && status.find(L"outcome=passkey_already_exists") != std::wstring::npos) ||
                status.find(L"Created passkey for Vault Unlock") != std::wstring::npos ||
                status.find(L"Vault Unlock passkey already exists") != std::wstring::npos)
            {
                vaultRecoveryHintText().Visibility(Microsoft::UI::Xaml::Visibility::Collapsed);
                vaultRecoveryHintText().Text(L"");
                runVaultRecoveryButton().Visibility(Microsoft::UI::Xaml::Visibility::Collapsed);
            }
        }
        void LogSuccess(const winrt::hstring& input) {
            UpdatePasskeyOperationStatusText(winrt::hstring{ L"SUCCESS: " + input + L"✅"});
        }
        void LogFailure(const winrt::hstring& input, HRESULT hr) {
            std::wstring inputText = input.c_str();
            std::wstring result = L"FAILED: " + inputText;
            if (inputText.find(L" hr=") == std::wstring::npos)
            {
                result += L" hr=" + std::to_wstring(static_cast<int>(hr));
            }
            result += L"❌";
            UpdatePasskeyOperationStatusText(winrt::hstring{ result });
        }
        void LogInProgress(const winrt::hstring& input) {
            UpdatePasskeyOperationStatusText(winrt::hstring{ L"INFO: " + input + L"⏳"});
        }
        void LogInfo(const winrt::hstring& input) {
            UpdatePasskeyOperationStatusText(winrt::hstring{ L"INFO: " + input + L"ℹ"});
        }
        void LogInfo(const winrt::hstring& input, HRESULT hr) {
            std::wstring inputText = input.c_str();
            std::wstring result = L"INFO: " + inputText;
            if (inputText.find(L" hr=") == std::wstring::npos)
            {
                result += L" hr=" + std::to_wstring(static_cast<int>(hr));
            }
            result += L"ℹ";
            UpdatePasskeyOperationStatusText(winrt::hstring{ result });
        }
        void LogWarning(const winrt::hstring& input, HRESULT hr = S_OK) {
            if (hr == S_OK)
            {
                UpdatePasskeyOperationStatusText(winrt::hstring{ L"WARNING: " + input + L"⚠"});
                return;
            }
            std::wstring inputText = input.c_str();
            std::wstring result = L"WARNING: " + inputText;
            if (inputText.find(L" hr=") == std::wstring::npos)
            {
                result += L" hr=" + std::to_wstring(static_cast<int>(hr));
            }
            result += L"⚠";
            UpdatePasskeyOperationStatusText(winrt::hstring{ result });
        }
        void UpdatePluginStateTextBlock(AUTHENTICATOR_STATE state);
        winrt::IAsyncAction SelectionChanged(IInspectable const& sender, Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const&);
        winrt::fire_and_forget UpdatePluginEnableState();

        winrt::IAsyncAction vaultLockSwitch_Toggled(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& e);
        winrt::IAsyncAction silentOperationSwitch_Toggled(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& e);
    private:
        PasskeyManager::CredentialListViewModel m_credentialListViewModel{ nullptr };
        winrt::IMap<winrt::IBuffer, IInspectable> m_selectedCredentialsSet = winrt::single_threaded_map<winrt::IBuffer, IInspectable>();
        std::vector<winrt::hstring> m_logEntries{};
        wil::unique_registry_watcher m_registryWatcher;
        wil::unique_folder_change_reader_nothrow m_mockCredentialsDBWatcher;
        bool m_suppressVaultLockSwitchToggled = false;
        bool m_isRestoringLogHistory = false;
        bool m_isDeleteEverywhereInProgress = false;
        uint64_t m_deleteEverywhereRequestCounter = 0;
        uint64_t m_deleteEverywhereRunCounter = 0;
        uint64_t m_deleteEverywhereActiveRunId = 0;
        std::vector<tsupasswd::SyncSnapshotRecord> m_syncSnapshotCandidates{};
        void UpdateVaultUnlockControlText(bool isLocked);
        void SetVaultLockSwitchState(bool isOn);
        void RebuildLogView();
        bool ShouldShowLogLine(std::wstring const& line);
        void UpdateLogDetailSummary();
        void ReloadSnapshotCandidates();
        void LoadSyncHistory();
        void PersistSyncHistoryEntry(winrt::hstring const& line);
    };
}

namespace winrt::PasskeyManager::factory_implementation
{
    struct MainPage : MainPageT<MainPage, implementation::MainPage>
    {
    };
}
