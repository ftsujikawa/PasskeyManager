#include "pch.h"
#include "PluginAuthenticatorImpl.h"
#include "PluginManagement/PluginCredentialManager.h"
#include "DelayLoad.h"

#include "../include/cbor-lite/codec.h"

#include <wincrypt.h>
#include <string>
#include <iostream>
#include <fstream>
#include <helpers/buffer_read_write.h>
#include <wil/result.h>
#include <wil/resource.h>
#include <algorithm>
#include <memory>
#include <type_traits>

namespace winrt
{
    using namespace winrt::Windows::Foundation;
    using namespace winrt::Microsoft::UI::Windowing;
    using namespace winrt::Microsoft::UI::Xaml;
    using namespace winrt::Microsoft::UI::Xaml::Controls;
    using namespace winrt::Microsoft::UI::Xaml::Navigation;
    using namespace PasskeyManager;
    using namespace PasskeyManager::implementation;
    using namespace CborLite;
}

namespace winrt::PasskeyManager::implementation
{
    constexpr wchar_t c_pluginRegistryPath[] = L"Software\\HappyFactory\\PasskeyManager";
    constexpr wchar_t c_windowsPluginLastMakeCredentialStatusRegKeyName[] = L"LastMakeCredentialStatus";
    constexpr wchar_t c_windowsPluginLastMakeCredentialSequenceRegKeyName[] = L"LastMakeCredentialSequence";
    constexpr wchar_t c_pluginProtectedHMACSecretInput[] = L"HMACSecretInputProtected";

    namespace {
        bool IsPluginTempPersistenceEnabled() noexcept;

        void AppendTempLogLine(wchar_t const* fileName, std::wstring const& line) noexcept;

        bool TryAcquireOperationInProgressFlag(std::atomic<bool>& flag) noexcept;

        wchar_t const* GetNonEmptyStringOrFallback(wchar_t const* value, wchar_t const* fallback) noexcept;

        void SetPerformOperationStatus(App& app, HRESULT status) noexcept;

        std::vector<uint8_t> GetRequestSigningPubKey();

        HRESULT VerifySignatureHelper(
            std::span<const BYTE> dataBuffer,
            PBYTE pbKeyData,
            DWORD cbKeyData,
            PBYTE pbSignature,
            DWORD cbSignature);

        HRESULT VerifyRequestSignatureIfPresent(
            std::span<const BYTE> requestBuffer,
            PBYTE requestSignature,
            DWORD requestSignatureLength) noexcept;

        HRESULT ComputeHmacSha256(
            std::span<const BYTE> key,
            std::span<const BYTE> data,
            std::array<BYTE, 32>& out) noexcept
        {
            try
            {
                wil::unique_bcrypt_algorithm hAlg;
                RETURN_IF_NTSTATUS_FAILED(BCryptOpenAlgorithmProvider(
                    wil::out_param(hAlg),
                    BCRYPT_SHA256_ALGORITHM,
                    nullptr,
                    BCRYPT_ALG_HANDLE_HMAC_FLAG));

                DWORD objLen = 0;
                DWORD cbResult = 0;
                RETURN_IF_NTSTATUS_FAILED(BCryptGetProperty(
                    hAlg.get(),
                    BCRYPT_OBJECT_LENGTH,
                    reinterpret_cast<PBYTE>(&objLen),
                    sizeof(objLen),
                    &cbResult,
                    0));

                auto hashObject = wil::make_unique_hlocal<BYTE[]>(objLen);
                RETURN_HR_IF_NULL(E_OUTOFMEMORY, hashObject);

                wil::unique_bcrypt_hash hHash;
                RETURN_IF_NTSTATUS_FAILED(BCryptCreateHash(
                    hAlg.get(),
                    wil::out_param(hHash),
                    hashObject.get(),
                    objLen,
                    const_cast<PUCHAR>(key.data()),
                    static_cast<ULONG>(key.size()),
                    0));

                RETURN_IF_NTSTATUS_FAILED(BCryptHashData(
                    hHash.get(),
                    const_cast<PUCHAR>(data.data()),
                    static_cast<ULONG>(data.size()),
                    0));

                RETURN_IF_NTSTATUS_FAILED(BCryptFinishHash(
                    hHash.get(),
                    out.data(),
                    static_cast<ULONG>(out.size()),
                    0));

                return S_OK;
            }
            catch (...)
            {
                return wil::ResultFromCaughtException();
            }
        }

        void PersistProtectedHmacSecret(std::span<const BYTE> secret) noexcept
        {
            if (secret.empty())
            {
                return;
            }

            DATA_BLOB inBlob{};
            if (secret.size() > MAXDWORD)
            {
                return;
            }
            inBlob.cbData = static_cast<DWORD>(secret.size());
            inBlob.pbData = const_cast<BYTE*>(secret.data());

            DATA_BLOB outBlob{};
            if (!CryptProtectData(&inBlob, nullptr, nullptr, nullptr, nullptr, 0, &outBlob))
            {
                return;
            }

            auto freeOut = wil::scope_exit([&]
            {
                if (outBlob.pbData)
                {
                    LocalFree(outBlob.pbData);
                    outBlob.pbData = nullptr;
                    outBlob.cbData = 0;
                }
            });

            wil::unique_hkey hKey;
            if (RegCreateKeyEx(
                HKEY_CURRENT_USER,
                c_pluginRegistryPath,
                0,
                nullptr,
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                nullptr,
                &hKey,
                nullptr) != ERROR_SUCCESS)
            {
                return;
            }

            (void)RegSetValueEx(
                hKey.get(),
                c_pluginProtectedHMACSecretInput,
                0,
                REG_BINARY,
                outBlob.pbData,
                outBlob.cbData);
        }

        void PersistLastMakeCredentialStatus(HRESULT hr) noexcept
        {
            if (IsPluginTempPersistenceEnabled())
            {
                wchar_t line[96]{};
                const int cch = swprintf_s(line, L"0x%08X\r\n", static_cast<DWORD>(hr));
                if (cch > 0)
                {
                    AppendTempLogLine(L"tsupasswd_core_make_credential_status.log", std::wstring(line, cch));
                }
            }

            wil::unique_hkey hKey;
            if (RegCreateKeyEx(
                HKEY_CURRENT_USER,
                c_pluginRegistryPath,
                0,
                nullptr,
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                nullptr,
                &hKey,
                nullptr) != ERROR_SUCCESS)
            {
                return;
            }

            const DWORD status = static_cast<DWORD>(hr);
            (void)RegSetValueEx(
                hKey.get(),
                c_windowsPluginLastMakeCredentialStatusRegKeyName,
                0,
                REG_DWORD,
                reinterpret_cast<const BYTE*>(&status),
                sizeof(status));

            ULONGLONG sequence = 0;
            DWORD sequenceSize = sizeof(sequence);
            if (RegGetValueW(
                hKey.get(),
                nullptr,
                c_windowsPluginLastMakeCredentialSequenceRegKeyName,
                RRF_RT_REG_QWORD,
                nullptr,
                &sequence,
                &sequenceSize) != ERROR_SUCCESS)
            {
                sequence = 0;
            }
            ++sequence;

            (void)RegSetValueEx(
                hKey.get(),
                c_windowsPluginLastMakeCredentialSequenceRegKeyName,
                0,
                REG_QWORD,
                reinterpret_cast<const BYTE*>(&sequence),
                sizeof(sequence));
        }

        void PersistLastGetAssertionStatus(HRESULT hr) noexcept
        {
            if (!IsPluginTempPersistenceEnabled())
            {
                return;
            }

            wchar_t line[128]{};
            const int cch = swprintf_s(line, L"0x%08X\r\n", static_cast<DWORD>(hr));
            if (cch > 0)
            {
                AppendTempLogLine(L"tsupasswd_core_get_assertion_status.log", std::wstring(line, cch));
            }
        }

        bool IsTruthySetting(std::wstring value) noexcept
        {
            std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch)
            {
                return static_cast<wchar_t>(towlower(ch));
            });
            return value == L"1" || value == L"true" || value == L"yes" || value == L"on";
        }

        bool IsPluginTempPersistenceEnabled() noexcept
        {
            wchar_t buffer[16]{};
            DWORD written = GetEnvironmentVariableW(L"TSUPASSWD_PLUGIN_PERSIST_GET_ASSERTION_INFO", buffer, static_cast<DWORD>(std::size(buffer)));
            if (written == 0 || written >= std::size(buffer))
            {
                return false;
            }
            return IsTruthySetting(std::wstring(buffer, written));
        }

        void AppendTempLogLine(wchar_t const* fileName, std::wstring const& line) noexcept
        {
            if (fileName == nullptr || fileName[0] == L'\0' || line.empty())
            {
                return;
            }

            wchar_t tempPath[MAX_PATH]{};
            DWORD tempLen = GetTempPathW(static_cast<DWORD>(std::size(tempPath)), tempPath);
            if (tempLen == 0 || tempLen >= std::size(tempPath))
            {
                return;
            }

            std::wstring filePath(tempPath);
            filePath += fileName;
            HANDLE hFile = CreateFileW(filePath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile == INVALID_HANDLE_VALUE)
            {
                return;
            }

            DWORD cb = 0;
            (void)WriteFile(hFile, line.data(), static_cast<DWORD>(line.size() * sizeof(wchar_t)), &cb, nullptr);
            (void)CloseHandle(hFile);
        }

        bool TryAcquireOperationInProgressFlag(std::atomic<bool>& flag) noexcept
        {
            bool expected = false;
            if (flag.compare_exchange_strong(expected, true))
            {
                return true;
            }

            flag = false;
            expected = false;
            return flag.compare_exchange_strong(expected, true);
        }

        wchar_t const* GetNonEmptyStringOrFallback(wchar_t const* value, wchar_t const* fallback) noexcept
        {
            if (value != nullptr && value[0] != L'\0')
            {
                return value;
            }

            return fallback;
        }

        void SetPerformOperationStatus(App& app, HRESULT status) noexcept
        {
            std::lock_guard<std::mutex> lock(app.m_pluginOperationOptionsMutex);
            app.m_pluginOperationStatus.performOperationStatus = status;
        }

        HRESULT VerifyRequestSignatureIfPresent(
            std::span<const BYTE> requestBuffer,
            PBYTE requestSignature,
            DWORD requestSignatureLength) noexcept
        {
            auto pubKeyData = GetRequestSigningPubKey();
            if (pubKeyData.empty())
            {
                return E_FAIL;
            }

            return VerifySignatureHelper(
                requestBuffer,
                pubKeyData.data(),
                static_cast<DWORD>(pubKeyData.size()),
                requestSignature,
                requestSignatureLength);
        }

        bool IsSupportedRpId(wchar_t const* rpId) noexcept
        {
            if (rpId == nullptr || rpId[0] == L'\0')
            {
                return false;
            }

            static wchar_t const* const kSupportedRpIds[] = {
                c_pluginRpId,
                c_pluginRpIdWebAuthnIo,
                c_pluginRpIdWebAuthnIoWww,
                c_pluginRpIdPasskeyOrg,
                c_pluginRpIdPasskeyOrgWww,
                c_pluginRpIdPasskeysIo,
                c_pluginRpIdPasskeysIoWww,
                c_pluginRpIdPasskeysGuru,
                c_pluginRpIdPasskeysGuruWww,
                c_pluginRpIdWebAuthnPasswordlessId,
                c_pluginRpIdWebAuthnPasswordlessIdWww,
            };

            for (auto const* candidate : kSupportedRpIds)
            {
                if (_wcsicmp(rpId, candidate) == 0)
                {
                    return true;
                }
            }

            return false;
        }

        void PersistGetAssertionInfo(PCWSTR rpId, DWORD credentialIdLen, DWORD userIdLen) noexcept
        {
            if (!IsPluginTempPersistenceEnabled())
            {
                return;
            }

            const wchar_t* rp = (rpId && rpId[0] != L'\0') ? rpId : L"(null)";
            wchar_t line[512]{};
            const int cch = swprintf_s(line, L"rpId=%s credIdLen=%lu userIdLen=%lu\r\n", rp, credentialIdLen, userIdLen);
            if (cch > 0)
            {
                AppendTempLogLine(L"tsupasswd_core_get_assertion_info.log", std::wstring(line, cch));
            }
        }

        static volatile DWORD g_makeCredentialStage = 0;

        static __forceinline void SetMakeCredentialStage(DWORD stage) noexcept
        {
            InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_makeCredentialStage), static_cast<LONG>(stage));
        }

        // Helper function to get request signing public key with proper error handling
        std::vector<uint8_t> GetRequestSigningPubKey()
        {
            DWORD cbKeyData = 0;
            unique_plugin_public_key pbKeyData = nullptr;
            HRESULT hr = WebAuthNPluginGetOperationSigningPublicKey(
                happyfactoryplugin_guid,
                &cbKeyData,
                &pbKeyData);

            if (SUCCEEDED(hr) && pbKeyData && cbKeyData > 0)
            {
                std::vector<BYTE> response(pbKeyData.get(), pbKeyData.get() + cbKeyData);
                return response;
            }

            return {};
        }

        /*
        * This function is used to verify the signature of a request buffer.
        * The public key is part of response to plugin registration.
        */
        HRESULT VerifySignatureHelper(
            std::span<const BYTE> dataBuffer,
            PBYTE pbKeyData,
            DWORD cbKeyData,
            PBYTE pbSignature,
            DWORD cbSignature)
        {
            // Create key provider
            wil::unique_ncrypt_prov hProvider;
            wil::unique_ncrypt_key reqSigningKey;

            // Get the provider
            RETURN_IF_FAILED(NCryptOpenStorageProvider(&hProvider, nullptr, 0));
            
            // Create a NCrypt key handle from the public key
            RETURN_IF_FAILED(NCryptImportKey(
                hProvider.get(),
                NULL,
                BCRYPT_PUBLIC_KEY_BLOB,
                nullptr,
                &reqSigningKey,
                pbKeyData,
                cbKeyData,
                0));

            // Verify the signature over the hash of dataBuffer using the hKey
            DWORD objLenSize = 0;
            DWORD bytesRead = 0;
            RETURN_IF_NTSTATUS_FAILED(BCryptGetProperty(
                BCRYPT_SHA256_ALG_HANDLE,
                BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PBYTE>(&objLenSize),
                sizeof(objLenSize),
                &bytesRead, 
                0));

            auto objLen = wil::make_unique_cotaskmem<BYTE[]>(objLenSize);
            RETURN_HR_IF_NULL(E_OUTOFMEMORY, objLen);

            wil::unique_bcrypt_hash hashHandle;
            RETURN_IF_NTSTATUS_FAILED(BCryptCreateHash(
                BCRYPT_SHA256_ALG_HANDLE,
                wil::out_param(hashHandle),
                objLen.get(),
                objLenSize,
                nullptr, 
                0, 
                0));

            RETURN_IF_NTSTATUS_FAILED(BCryptHashData(
                hashHandle.get(),
                const_cast<PUCHAR>(dataBuffer.data()),
                static_cast<ULONG>(dataBuffer.size()), 
                0));

            DWORD localHashByteCount = 0;
            RETURN_IF_NTSTATUS_FAILED(BCryptGetProperty(
                BCRYPT_SHA256_ALG_HANDLE,
                BCRYPT_HASH_LENGTH,
                reinterpret_cast<PBYTE>(&localHashByteCount),
                sizeof(localHashByteCount),
                &bytesRead, 
                0));

            auto localHashBuffer = wil::make_unique_cotaskmem<BYTE[]>(localHashByteCount);
            RETURN_HR_IF_NULL(E_OUTOFMEMORY, localHashBuffer);

            RETURN_IF_NTSTATUS_FAILED(BCryptFinishHash(
                hashHandle.get(), 
                localHashBuffer.get(), 
                localHashByteCount, 
                0));

            PVOID paddingInfo = nullptr;
            DWORD dwCngFlags = 0;
            RETURN_HR_IF(E_INVALIDARG, cbKeyData < sizeof(BCRYPT_KEY_BLOB));
            
            BCRYPT_KEY_BLOB* pKeyBlob = reinterpret_cast<BCRYPT_KEY_BLOB*>(pbKeyData);
            if (pKeyBlob->Magic == BCRYPT_RSAPUBLIC_MAGIC)
            {
                BCRYPT_PKCS1_PADDING_INFO paddingInfoStruct = {};
                paddingInfoStruct.pszAlgId = BCRYPT_SHA256_ALGORITHM;
                paddingInfo = &paddingInfoStruct;
                dwCngFlags = BCRYPT_PAD_PKCS1;
            }

            RETURN_IF_WIN32_ERROR(NCryptVerifySignature(
                reqSigningKey.get(),
                paddingInfo,
                localHashBuffer.get(),
                localHashByteCount,
                pbSignature,
                cbSignature,
                dwCngFlags));

            return S_OK;
        }

        HRESULT WaitAndCheckVaultUnlockCompleted(const winrt::com_ptr<App>& curApp)
        {
            try
            {
                HANDLE handles[2] = { 
                    curApp->m_hVaultConsentComplete.get(), 
                    curApp->m_hVaultConsentFailed.get() 
                };

                DWORD cWait = ARRAYSIZE(handles);
                DWORD hIndex = 0;
                THROW_IF_FAILED(CoWaitForMultipleHandles(
                    COWAIT_DISPATCH_WINDOW_MESSAGES | COWAIT_DISPATCH_CALLS, 
                    INFINITE, 
                    cWait, 
                    handles, 
                    &hIndex));

                if (hIndex == 1) // Consent failed
                {
                    return E_FAIL;
                }
                return S_OK;
            }
            catch (...)
            {
                return winrt::to_hresult();
            }
        }
    } // anonymous namespace

    HRESULT HappyFactoryPlugin::PerformUserVerification(
        HWND hWnd,
        GUID transactionId,
        PluginOperationType operationType,
        const std::vector<BYTE>& requestBuffer,
        wil::shared_cotaskmem_string rpName,
        wil::shared_cotaskmem_string userName)
    {
        RETURN_HR_IF(E_INVALIDARG, requestBuffer.empty());
        winrt::com_ptr<winrt::PasskeyManager::implementation::App> curApp = m_app;
        RETURN_HR_IF(E_UNEXPECTED, !curApp);
        bool vaultLocked = PluginCredentialManager::getInstance().GetVaultLock();

        try
        {
            RETURN_HR_IF(E_UNEXPECTED, !curApp->GetDispatcherQueue().TryEnqueue([curApp, hWnd, operationType, rpName, userName]()
            {
                curApp->SetPluginPerformOperationOptions(hWnd, operationType, rpName.get(), userName.get());
            }));

            // Trigger a Consent Verifier Dialog to simulate a Windows Hello unlock flow
            // This is to demonstrate a vault unlock flow using Windows Hello and is not the recommended way to secure the vault
            if (PluginCredentialManager::getInstance().GetVaultLock())
            {
                RETURN_HR_IF(E_UNEXPECTED, !curApp->GetDispatcherQueue().TryEnqueue([curApp]()
                {
                    curApp->SimulateUnLockVault();
                }));
                RETURN_IF_FAILED(WaitAndCheckVaultUnlockCompleted(curApp));
            }
            else
            {
                SetEvent(curApp->m_hVaultConsentComplete.get());
            }

            if ((operationType == PluginOperationType::MakeCredential || operationType == PluginOperationType::GetAssertion) && !vaultLocked)
            {
                // For local Vault passkey creation, do not depend on plugin window button clicks.
                // Immediate cancel events can otherwise race and end up as ERROR_CANCELLED.
                SetEvent(curApp->m_hPluginProceedButtonEvent.get());
            }
            else
            {
                // Wait for user confirmation to proceed with the operation Create/Signin/Cancel button
                // This is a mock up for plugin requiring UI.
                HANDLE handles[2] = {
                    curApp->m_hPluginProceedButtonEvent.get(),
                    m_hPluginCancelOperationEvent.get()
                };
                DWORD cWait = ARRAYSIZE(handles);
                DWORD hIndex = 0;

                RETURN_IF_FAILED(CoWaitForMultipleHandles(
                    COWAIT_DISPATCH_WINDOW_MESSAGES | COWAIT_DISPATCH_CALLS,
                    INFINITE,
                    cWait,
                    handles,
                    &hIndex));

                if (hIndex == 1) // Cancel button clicked
                {
                    // User cancelled the operation. NTE_USER_CANCELLED allows Windows to distinguish between user cancellation and other errors.
                    return NTE_USER_CANCELLED;
                }
            }

            // For local Vault passkey creation, rely on the WebAuthN MakeCredential ceremony itself and
            // skip the plugin-specific UV prompt to avoid cancellation races and duplicate prompts.
            if ((operationType == PluginOperationType::MakeCredential || operationType == PluginOperationType::GetAssertion) && !vaultLocked)
            {
                return S_OK;
            }

            // Skip user verification if the user has already performed a gesture to unlock the vault to avoid double prompting
            if (vaultLocked)
            {
                return S_OK;
            }

            // Optional Step: Get the UV count. The UV count tracks the number of times the user has performed a gesture to unlock the vault.
            DWORD uvCount = 0;
            RETURN_IF_FAILED(WebAuthNPluginGetUserVerificationCount(happyfactoryplugin_guid, &uvCount));

            // Step 1: Get the public key.
            DWORD cbPubKeyData = 0;
            unique_plugin_public_key pbPubKeyData = nullptr;
            RETURN_IF_FAILED(WebAuthNPluginGetUserVerificationPublicKey(
                happyfactoryplugin_guid,
                &cbPubKeyData,
                &pbPubKeyData));
            RETURN_HR_IF_NULL(E_FAIL, pbPubKeyData);

            // Step 2: Perform UV. This step uses a Windows Hello prompt to authenticate the user.
            // WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST: This structure defines the request parameters for Windows Hello user verification.
            // Enables plugins to leverage familiar Windows Hello biometric authentication for user verification workflows.
            WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST pluginPerformUv = {
                nullptr,      // hwnd
                transactionId, // rguidTransactionId
                nullptr,      // pwszUsername
                nullptr       // pwszDisplayHint
            };

            if (curApp->GetSilentMode())
            {
                // If the app did not display any UI, use the hwnd of the caller here. This was included in the request to the plugin. 
                // Refer: PCWEBAUTHN_PLUGIN_OPERATION_REQUEST - structure containing operation parameters
                pluginPerformUv.hwnd = hWnd;
            }
            else
            {
                // If the app displayed UI, use the hwnd of the app window here
                pluginPerformUv.hwnd = curApp->GetNativeWindowHandle();
            }

            auto localUserName = wil::make_cotaskmem_string(userName.get());
            pluginPerformUv.pwszUsername = localUserName.get();

            // pwszDisplayHint can be used to provide additional context to the user.
            // This is displayed alongside the username in the Windows Hello passkey user verification dialog.
            auto localDisplayHint = wil::make_cotaskmem_string(L"Context String");
            pluginPerformUv.pwszDisplayHint = localDisplayHint.get();

            DWORD cbResponse = 0;
            PBYTE pbResponse = nullptr;

            RETURN_IF_FAILED(WebAuthNPluginPerformUserVerification(&pluginPerformUv, &cbResponse, &pbResponse));
            auto cleanupUvResponse = wil::scope_exit([&] {
                WebAuthNPluginFreeUserVerificationResponse(pbResponse);
            });

            // Verify the signature over the hash of requestBuffer using the hKey
            auto signatureVerifyResult = VerifySignatureHelper(
                requestBuffer,
                pbPubKeyData.get(),
                cbPubKeyData,
                pbResponse,
                cbResponse);

            RETURN_HR_IF(E_UNEXPECTED, !curApp->GetDispatcherQueue().TryEnqueue([curApp, signatureVerifyResult]()
            {
                if (FAILED(signatureVerifyResult))
                {
                    curApp->m_pluginOperationStatus.uvSignatureVerificationStatus = signatureVerifyResult;
                }
            }));

            return S_OK;
        }
        catch (...)
        {
            return winrt::to_hresult();
        }
    }

    HRESULT CreateAuthenticatorData(
        const NCRYPT_KEY_HANDLE hKey,
        const PluginOperationType operationType,
        DWORD cbRpId,
        PBYTE pbRpId,
        DWORD& pcbPackedAuthenticatorData,
        wil::unique_hlocal_ptr<BYTE[]>& ppbpackedAuthenticatorData,
        std::vector<uint8_t>& vCredentialIdBuffer);

    HRESULT GetAssertionNoSeh(
        HappyFactoryPlugin* self,
        PCWEBAUTHN_PLUGIN_OPERATION_REQUEST pPluginGetAssertionRequest,
        PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept;

    static HRESULT MakeCredentialNoSeh(
        HappyFactoryPlugin* self,
        PCWEBAUTHN_PLUGIN_OPERATION_REQUEST pPluginMakeCredentialRequest,
        PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept
    {
        HRESULT hr = S_OK;
        try
        {
            g_makeCredentialStage = 0x0001;

            // Marker to confirm this binary is executing and the registry sequence advances.
            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D433001));

            // WebAuthn can invoke plugin callbacks on arbitrary threads.
            // Avoid winrt::init_apartment here (can hang depending on thread/COM state).
            // Ensure COM is initialized; tolerate mode mismatch.
            const HRESULT hrCoInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D433002));
            PersistLastMakeCredentialStatus(hrCoInit);
            if (hrCoInit != RPC_E_CHANGED_MODE)
            {
                RETURN_IF_FAILED(hrCoInit);
            }

            RETURN_HR_IF_NULL(E_INVALIDARG, response);
            *response = {};
            RETURN_HR_IF_NULL(E_INVALIDARG, pPluginMakeCredentialRequest);

            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D433003));

            g_makeCredentialStage = 0x0002;

            DWORD hIndex = 0;
            g_makeCredentialStage = 0x0010;

            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D430010));
            THROW_IF_FAILED(CoWaitForMultipleHandles(
                COWAIT_DISPATCH_WINDOW_MESSAGES | COWAIT_DISPATCH_CALLS,
                INFINITE,
                1,
                self->m_hAppReadyForPluginOpEvent.addressof(),
                &hIndex));

            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D430011));

            SetMakeCredentialStage(0x0011);

            // Split stages further to pinpoint AV around m_app access.
            SetMakeCredentialStage(0x0121);
            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D430121));
            App* curApp = nullptr;

            SetMakeCredentialStage(0x0122);
            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D430122));
            curApp = self->m_app.get();

            SetMakeCredentialStage(0x0123);
            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D430123));

            SetMakeCredentialStage(0x0124);
            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D430124));
            if (!curApp)
            {
                PersistLastMakeCredentialStatus(E_UNEXPECTED);
                return E_UNEXPECTED;
            }

            SetMakeCredentialStage(0x0015);
            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D430015));

            SetMakeCredentialStage(0x0016);
            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D430016));

            if (!TryAcquireOperationInProgressFlag(curApp->m_isOperationInProgress))
            {
                SetMakeCredentialStage(0x0017);
                PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D430017));
                PersistLastMakeCredentialStatus(HRESULT_FROM_WIN32(ERROR_BUSY));
                return HRESULT_FROM_WIN32(ERROR_BUSY);
            }

            SetMakeCredentialStage(0x0018);
            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D430018));

            SetMakeCredentialStage(0x0181);
            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D430181));
            const HWND appHwnd = curApp->GetPluginOperationHwnd();

            SetMakeCredentialStage(0x0182);
            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D430182));
            const bool isAppCaller = pPluginMakeCredentialRequest->hWnd != nullptr &&
                pPluginMakeCredentialRequest->hWnd == appHwnd;

            SetMakeCredentialStage(0x0183);
            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D430183));
            const bool silent = curApp->GetSilentMode();

            SetMakeCredentialStage(0x0184);
            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D430184));
            if (silent || isAppCaller)
            {
                PersistLastMakeCredentialStatus(S_FALSE);
            }

            SetMakeCredentialStage(0x0185);
            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D430185));

            auto clearOperationInProgress = wil::scope_exit([&]
            {
                curApp->m_isOperationInProgress = false;
            });

            SetMakeCredentialStage(0x0186);
            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D430186));

            curApp->SetPluginTransactionId(pPluginMakeCredentialRequest->transactionId);
            auto completePluginOperation = wil::SetEvent_scope_exit(self->m_hPluginOpCompletedEvent.get());

            g_makeCredentialStage = 0x0013;

            PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST pDecodedMakeCredentialRequest;

            THROW_IF_FAILED(WebAuthNDecodeMakeCredentialRequest(
                pPluginMakeCredentialRequest->cbEncodedRequest,
                pPluginMakeCredentialRequest->pbEncodedRequest,
                &pDecodedMakeCredentialRequest));

            g_makeCredentialStage = 0x0020;

            auto cleanup = wil::scope_exit([&] {
                WebAuthNFreeDecodedMakeCredentialRequest(pDecodedMakeCredentialRequest);
            });

            THROW_HR_IF_NULL(E_INVALIDARG, pDecodedMakeCredentialRequest->pRpInformation);
            THROW_HR_IF_NULL(E_INVALIDARG, pDecodedMakeCredentialRequest->pUserInformation);

            std::string rpIdFromRequest;
            if (pDecodedMakeCredentialRequest->pbRpId != nullptr && pDecodedMakeCredentialRequest->cbRpId > 0)
            {
                rpIdFromRequest.assign(
                    reinterpret_cast<const char*>(pDecodedMakeCredentialRequest->pbRpId),
                    reinterpret_cast<const char*>(pDecodedMakeCredentialRequest->pbRpId) + pDecodedMakeCredentialRequest->cbRpId);
            }
            THROW_HR_IF(NTE_NOT_SUPPORTED, rpIdFromRequest.empty());

            std::wstring rpIdFromRequestW(rpIdFromRequest.begin(), rpIdFromRequest.end());
            bool rpSupported = IsSupportedRpId(rpIdFromRequestW.c_str());
            THROW_HR_IF(NTE_NOT_SUPPORTED, !rpSupported);
            wchar_t const* rpNameSource = GetNonEmptyStringOrFallback(
                pDecodedMakeCredentialRequest->pRpInformation->pwszName,
                L"Unknown RP");
            auto rpName = wil::make_cotaskmem_string(rpNameSource);

            wchar_t const* userNameSource = GetNonEmptyStringOrFallback(
                pDecodedMakeCredentialRequest->pUserInformation->pwszName,
                L"Unknown User");
            auto userName = wil::make_cotaskmem_string(userNameSource);
            std::vector<BYTE> requestBuffer(
                pPluginMakeCredentialRequest->pbEncodedRequest,
                pPluginMakeCredentialRequest->pbEncodedRequest + pPluginMakeCredentialRequest->cbEncodedRequest);

            HRESULT requestSignResult = VerifyRequestSignatureIfPresent(
                requestBuffer,
                pPluginMakeCredentialRequest->pbRequestSignature,
                pPluginMakeCredentialRequest->cbRequestSignature);

            {
                std::lock_guard<std::mutex> lock(curApp->m_pluginOperationOptionsMutex);
                curApp->m_pluginOperationStatus.requestSignatureVerificationStatus = requestSignResult;
            }

            hr = self->PerformUserVerification(
                pPluginMakeCredentialRequest->hWnd,
                pPluginMakeCredentialRequest->transactionId,
                PluginOperationType::MakeCredential,
                requestBuffer,
                std::move(rpName),
                std::move(userName));
            THROW_IF_FAILED(hr);

            g_makeCredentialStage = 0x0003;

            wil::unique_ncrypt_prov hProvider;
            wil::unique_ncrypt_key hKey;

            THROW_IF_FAILED(NCryptOpenStorageProvider(&hProvider, nullptr, 0));

            std::wstring keyNameStr = happyfactoryplugin_key_domain;
            std::wstringstream keyNameStream;
            THROW_HR_IF(E_INVALIDARG,
                pDecodedMakeCredentialRequest->pUserInformation->cbId > 0 &&
                pDecodedMakeCredentialRequest->pUserInformation->pbId == nullptr);
            for (DWORD idx = 0; idx < pDecodedMakeCredentialRequest->pUserInformation->cbId; idx++)
            {
                keyNameStream << std::hex << std::setw(2) << std::setfill(L'0') <<
                    static_cast<int>(pDecodedMakeCredentialRequest->pUserInformation->pbId[idx]);
            }
            keyNameStr += keyNameStream.str();

            THROW_IF_FAILED(NCryptCreatePersistedKey(
                hProvider.get(),
                &hKey,
                BCRYPT_ECDSA_P256_ALGORITHM,
                keyNameStr.c_str(),
                0,
                NCRYPT_OVERWRITE_KEY_FLAG));

            g_makeCredentialStage = 0x0004;

            DWORD exportPolicy = NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            THROW_IF_FAILED(NCryptSetProperty(
                hKey.get(),
                NCRYPT_EXPORT_POLICY_PROPERTY,
                reinterpret_cast<PBYTE>(&exportPolicy),
                sizeof(exportPolicy),
                NCRYPT_PERSIST_FLAG));

            DWORD keyUsage = NCRYPT_ALLOW_SIGNING_FLAG | NCRYPT_ALLOW_DECRYPT_FLAG;
            THROW_IF_FAILED(NCryptSetProperty(
                hKey.get(),
                NCRYPT_KEY_USAGE_PROPERTY,
                reinterpret_cast<PBYTE>(&keyUsage),
                sizeof(keyUsage),
                NCRYPT_PERSIST_FLAG));

            HWND hWnd;
            if (curApp->GetSilentMode())
            {
                hWnd = curApp->GetPluginOperationHwnd();
            }
            else
            {
                hWnd = curApp->GetNativeWindowHandle();
            }

            THROW_IF_FAILED(NCryptSetProperty(
                hKey.get(),
                NCRYPT_WINDOW_HANDLE_PROPERTY,
                reinterpret_cast<PBYTE>(&hWnd),
                sizeof(HWND),
                0));

            THROW_IF_FAILED(NCryptFinalizeKey(hKey.get(), 0));

            g_makeCredentialStage = 0x0005;

            DWORD cbPackedAuthenticatorData = 0;
            wil::unique_hlocal_ptr<BYTE[]> packedAuthenticatorData;
            std::vector<uint8_t> vCredentialIdBuffer;
            THROW_IF_FAILED(CreateAuthenticatorData(
                hKey.get(),
                PluginOperationType::MakeCredential,
                pDecodedMakeCredentialRequest->cbRpId,
                pDecodedMakeCredentialRequest->pbRpId,
                cbPackedAuthenticatorData,
                packedAuthenticatorData,
                vCredentialIdBuffer));

            g_makeCredentialStage = 0x0006;

            WEBAUTHN_CREDENTIAL_ATTESTATION attestationResponse = {};
            attestationResponse.dwVersion = WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_5;
            attestationResponse.pwszFormatType = WEBAUTHN_ATTESTATION_TYPE_NONE;
            attestationResponse.cbAttestation = 0;
            attestationResponse.pbAttestation = nullptr;
            attestationResponse.cbAuthenticatorData = 0;
            attestationResponse.pbAuthenticatorData = nullptr;
            const bool advertisePrfAndHmacSecret = true;
            attestationResponse.bPrfEnabled = advertisePrfAndHmacSecret ? TRUE : FALSE;
            BOOL hmacSecretExtensionValue = TRUE;
            WEBAUTHN_EXTENSION hmacSecretExtension = {};
            hmacSecretExtension.pwszExtensionIdentifier = WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET;
            hmacSecretExtension.cbExtension = sizeof(BOOL);
            hmacSecretExtension.pvExtension = &hmacSecretExtensionValue;
            attestationResponse.Extensions.cExtensions = advertisePrfAndHmacSecret ? 1 : 0;
            attestationResponse.Extensions.pExtensions = advertisePrfAndHmacSecret ? &hmacSecretExtension : nullptr;
            attestationResponse.pbAuthenticatorData = packedAuthenticatorData.get();
            attestationResponse.cbAuthenticatorData = cbPackedAuthenticatorData;

            DWORD cbAttestationBuffer = 0;
            wil::unique_cotaskmem_ptr<BYTE[]> pbAttestationBuffer;

            HRESULT encodeHr = E_FAIL;
            // Prefer EXPERIMENTAL encoder so VERSION_5 fields (e.g. bPrfEnabled) are preserved.
            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D43E001));
            encodeHr = EXPERIMENTAL_WebAuthNEncodeMakeCredentialResponse(
                &attestationResponse,
                &cbAttestationBuffer,
                wil::out_param(pbAttestationBuffer));
            PersistLastMakeCredentialStatus(encodeHr);

            if (encodeHr == E_NOTIMPL || FAILED(encodeHr))
            {
                // Fallback to the stable encoder for older platforms.
                // Keep PRF/HMAC advertisement enabled for vault recovery compatibility.
                PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D43E002));
                attestationResponse.dwVersion = WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION;
                attestationResponse.bPrfEnabled = advertisePrfAndHmacSecret ? TRUE : FALSE;
                attestationResponse.Extensions.cExtensions = advertisePrfAndHmacSecret ? 1 : 0;
                attestationResponse.Extensions.pExtensions = advertisePrfAndHmacSecret ? &hmacSecretExtension : nullptr;

                encodeHr = WebAuthNEncodeMakeCredentialResponse(
                    &attestationResponse,
                    &cbAttestationBuffer,
                    wil::out_param(pbAttestationBuffer));
                PersistLastMakeCredentialStatus(encodeHr);
            }
            THROW_IF_FAILED(encodeHr);

            g_makeCredentialStage = 0x0007;

            WEBAUTHN_CREDENTIAL_DETAILS credentialDetails = {};
            credentialDetails.dwVersion = WEBAUTHN_CREDENTIAL_DETAILS_CURRENT_VERSION;
            credentialDetails.pUserInformation = const_cast<PWEBAUTHN_USER_ENTITY_INFORMATION>(pDecodedMakeCredentialRequest->pUserInformation);
            credentialDetails.pRpInformation = const_cast<PWEBAUTHN_RP_ENTITY_INFORMATION>(pDecodedMakeCredentialRequest->pRpInformation);
            credentialDetails.cbCredentialID = static_cast<DWORD>(vCredentialIdBuffer.size());
            credentialDetails.pbCredentialID = vCredentialIdBuffer.data();

            auto& credManager = PluginCredentialManager::getInstance();

            if (!credManager.SaveCredentialMetadataToMockDB(credentialDetails))
            {
                std::lock_guard<std::mutex> lock(curApp->m_pluginOperationOptionsMutex);
                curApp->m_pluginOperationStatus.performOperationStatus = E_FAIL;
            }

            credManager.ReloadCredentialManager();
            std::vector<std::vector<UINT8>> credentialIdList{ vCredentialIdBuffer };
            credManager.AddPluginCredentialById(credentialIdList);

            response->cbEncodedResponse = cbAttestationBuffer;
            response->pbEncodedResponse = nullptr;
            if (cbAttestationBuffer > 0)
            {
                response->pbEncodedResponse = reinterpret_cast<byte*>(CoTaskMemAlloc(cbAttestationBuffer));
                THROW_HR_IF_NULL(E_OUTOFMEMORY, response->pbEncodedResponse);
                memcpy_s(response->pbEncodedResponse, cbAttestationBuffer, pbAttestationBuffer.get(), cbAttestationBuffer);
            }

            g_makeCredentialStage = 0x0008;
            PersistLastMakeCredentialStatus(S_OK);
            return S_OK;
        }
        catch (...)
        {
            hr = wil::ResultFromCaughtException();
            PersistLastMakeCredentialStatus(hr);
            try
            {
                com_ptr<App> curApp = self->m_app;
                if (curApp)
                {
                    std::lock_guard<std::mutex> lock(curApp->m_pluginOperationOptionsMutex);
                    curApp->m_pluginOperationStatus.performOperationStatus = hr;
                }
            }
            catch (...)
            {
            }
            return hr;
        }
    }

    /*
    * This function is used to create a simplified version of authenticator data for the webauthn authenticator operations.
    * Refer: https://www.w3.org/TR/webauthn-3/#authenticator-data for more details.
    */
    HRESULT CreateAuthenticatorData(
        const NCRYPT_KEY_HANDLE hKey,
        const PluginOperationType operationType,
        DWORD cbRpId,
        PBYTE pbRpId,
        DWORD& pcbPackedAuthenticatorData,
        wil::unique_hlocal_ptr<BYTE[]>& ppbpackedAuthenticatorData,
        std::vector<uint8_t>& vCredentialIdBuffer)
    {
        try
        {
            // Get the public key blob
            DWORD cbPubKeyBlob = 0;
            THROW_IF_FAILED(NCryptExportKey(
                hKey,
                NULL,
                BCRYPT_ECCPUBLIC_BLOB,
                nullptr,
                nullptr,
                0,
                &cbPubKeyBlob,
                0));

            auto pbPubKeyBlob = std::make_unique<BYTE[]>(cbPubKeyBlob);

            DWORD cbPubKeyBlobOutput = 0;
            THROW_IF_FAILED(NCryptExportKey(
                hKey,
                NULL,
                BCRYPT_ECCPUBLIC_BLOB,
                nullptr,
                pbPubKeyBlob.get(),
                cbPubKeyBlob,
                &cbPubKeyBlobOutput,
                0));

            BCRYPT_ECCKEY_BLOB* pPubKeyBlobHeader = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(pbPubKeyBlob.get());
            DWORD cbXCoord = pPubKeyBlobHeader->cbKey;
            PBYTE pbXCoord = reinterpret_cast<PBYTE>(&pPubKeyBlobHeader[1]);
            DWORD cbYCoord = pPubKeyBlobHeader->cbKey;
            PBYTE pbYCoord = pbXCoord + cbXCoord;

            // create byte span for x and y
            std::span<const BYTE> xCoord(pbXCoord, cbXCoord);
            std::span<const BYTE> yCoord(pbYCoord, cbYCoord);

            // CBOR encode the public key in this order: kty, alg, crv, x, y
            std::vector<BYTE> buffer;

#pragma warning(push)
#pragma warning(disable: 4293)
            size_t bufferSize = CborLite::encodeMapSize(buffer, 5u);
#pragma warning(pop)

            // COSE CBOR encoding format. Refer to https://datatracker.ietf.org/doc/html/rfc9052#section-7 for more details.
            constexpr int8_t ktyIndex = 1;
            constexpr int8_t algIndex = 3;
            constexpr int8_t crvIndex = -1;
            constexpr int8_t xIndex = -2;
            constexpr int8_t yIndex = -3;

            // Example values for EC2 P-256 ES256 Keys. Refer to https://www.w3.org/TR/webauthn-3/#example-bdbd14cc
            // Note that this sample authenticator only supports ES256 keys.
            constexpr int8_t kty = 2; // Key type is EC2
            constexpr int8_t crv = 1; // Curve is P-256
            constexpr int8_t alg = -7; // Algorithm is ES256

            bufferSize += CborLite::encodeInteger(buffer, ktyIndex);
            bufferSize += CborLite::encodeInteger(buffer, kty);
            bufferSize += CborLite::encodeInteger(buffer, algIndex);
            bufferSize += CborLite::encodeInteger(buffer, alg);
            bufferSize += CborLite::encodeInteger(buffer, crvIndex);
            bufferSize += CborLite::encodeInteger(buffer, crv);
            bufferSize += CborLite::encodeInteger(buffer, xIndex);
            bufferSize += CborLite::encodeBytes(buffer, xCoord);
            bufferSize += CborLite::encodeInteger(buffer, yIndex);
            bufferSize += CborLite::encodeBytes(buffer, yCoord);

            wil::unique_bcrypt_hash hashHandle;
            THROW_IF_NTSTATUS_FAILED(BCryptCreateHash(
                BCRYPT_SHA256_ALG_HANDLE,
                wil::out_param(hashHandle),
                nullptr,
                0,
                nullptr,
                0,
                0));

            THROW_IF_NTSTATUS_FAILED(BCryptHashData(
                hashHandle.get(), 
                reinterpret_cast<PUCHAR>(pbXCoord), 
                cbXCoord, 
                0));

            THROW_IF_NTSTATUS_FAILED(BCryptHashData(
                hashHandle.get(), 
                reinterpret_cast<PUCHAR>(pbYCoord), 
                cbYCoord, 
                0));

            DWORD cbHash = 0;
            DWORD bytesRead = 0;
            THROW_IF_NTSTATUS_FAILED(BCryptGetProperty(
                hashHandle.get(),
                BCRYPT_HASH_LENGTH,
                reinterpret_cast<PBYTE>(&cbHash),
                sizeof(cbHash),
                &bytesRead,
                0));

            wil::unique_hlocal_ptr<BYTE[]> pbCredentialId = wil::make_unique_hlocal<BYTE[]>(cbHash);

            THROW_IF_NTSTATUS_FAILED(BCryptFinishHash(
                hashHandle.get(), 
                pbCredentialId.get(), 
                cbHash, 
                0));

            // Refer to learn about packing credential data https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data
            constexpr DWORD rpidsha256Size = 32; // SHA256 hash of rpId
            constexpr DWORD flagsSize = 1; // flags
            constexpr DWORD signCountSize = 4; // signCount
            DWORD cbPackedAuthenticatorData = rpidsha256Size + flagsSize + signCountSize;

            std::vector<BYTE> extensionsCbor;
            const bool includeMakeCredentialExtensions = false;
            if (includeMakeCredentialExtensions && operationType == PluginOperationType::MakeCredential)
            {
                (void)CborLite::encodeMapSize(extensionsCbor, 0u);
            }

            if (operationType == PluginOperationType::MakeCredential)
            {
                cbPackedAuthenticatorData += sizeof(GUID); // aaGuid
                cbPackedAuthenticatorData += sizeof(WORD); // credentialId length
                cbPackedAuthenticatorData += cbHash; // credentialId
                cbPackedAuthenticatorData += static_cast<DWORD>(buffer.size()); // public key
                cbPackedAuthenticatorData += static_cast<DWORD>(extensionsCbor.size()); // extensions
            }

            std::vector<BYTE> vPackedAuthenticatorData(cbPackedAuthenticatorData);
            auto writer = buffer_writer{ vPackedAuthenticatorData };

            auto rgbRpIdHash = writer.reserve_space<std::array<BYTE, rpidsha256Size>>(); // 32 bytes of rpIdHash which is SHA256 hash of rpName. https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data
            DWORD cbRpIdHash = rpidsha256Size;
            THROW_IF_WIN32_BOOL_FALSE(CryptHashCertificate2(
                BCRYPT_SHA256_ALGORITHM,
                0,
                nullptr,
                pbRpId,
                cbRpId,
                rgbRpIdHash->data(),
                &cbRpIdHash));

            // Flags uv, up, be, and at are set
            if (operationType == PluginOperationType::GetAssertion)
            {
                // Refer https://www.w3.org/TR/webauthn-3/#authdata-flags
                // Minimal flags: UP + UV (do not claim BE/BS backup state bits).
                *writer.reserve_space<uint8_t>() = 0x05; // UP(0x01) | UV(0x04)

                // signCount (4 bytes, big-endian)
                writer.add(std::span<const BYTE>({ 0x00, 0x00, 0x00, 0x00 }));

                vCredentialIdBuffer.assign(pbCredentialId.get(), pbCredentialId.get() + cbHash);
            }
            else
            {
                // Refer https://www.w3.org/TR/webauthn-3/#authdata-flags
                // Minimal flags: UP + UV + AT (+ED if extensions are present)
                uint8_t flags = 0x45; // UP(0x01) | UV(0x04) | AT(0x40)
                if (!extensionsCbor.empty())
                {
                    flags = static_cast<uint8_t>(flags | 0x80); // ED
                }
                *writer.reserve_space<uint8_t>() = flags;

                // signCount (4 bytes, big-endian)
                writer.add(std::span<const BYTE>({ 0x00, 0x00, 0x00, 0x00 }));

                // aaGuid of size 16 bytes is set to predefined bytes in big-endian. Refer https://www.w3.org/TR/webauthn-3/#aaguid
                writer.add(std::span<const BYTE>(c_pluginAaguidBytes, sizeof(c_pluginAaguidBytes)));

                // Retrieve credential id
                WORD cbCredentialId = static_cast<WORD>(cbHash);
                WORD cbCredentialIdBigEndian = _byteswap_ushort(cbCredentialId);

                *writer.reserve_space<WORD>() = cbCredentialIdBigEndian; // Size of credential id in unsigned big endian of size 2 bytes

                writer.add(std::span<BYTE>(pbCredentialId.get(), cbHash)); // Set credential id

                vCredentialIdBuffer.assign(pbCredentialId.get(), pbCredentialId.get() + cbHash);

                writer.add(std::span<BYTE>(buffer.data(), buffer.size())); // Set CBOR encoded public key

                // Append extensions (ED flag set above)
                writer.add(std::span<BYTE>(extensionsCbor.data(), extensionsCbor.size()));
            }

            pcbPackedAuthenticatorData = static_cast<DWORD>(vPackedAuthenticatorData.size());
            ppbpackedAuthenticatorData = wil::make_unique_hlocal<BYTE[]>(pcbPackedAuthenticatorData);

            memcpy_s(ppbpackedAuthenticatorData.get(), pcbPackedAuthenticatorData, vPackedAuthenticatorData.data(), pcbPackedAuthenticatorData);

            return S_OK;
        }
        catch (...)
        {
            return winrt::to_hresult();
        }
    }

    /*
    * This function is invoked by the platform to request the plugin to handle a make credential operation.
    * Refer: pluginauthenticator.h/pluginauthenticator.idl
    */
    HRESULT STDMETHODCALLTYPE HappyFactoryPlugin::MakeCredential(
        /* [in] */ __RPC__in PCWEBAUTHN_PLUGIN_OPERATION_REQUEST pPluginMakeCredentialRequest,
        /* [out] */ __RPC__out PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept
    {
        // Entry marker: helps determine whether the plugin is invoked at all in browser flows.
        PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D434D01));
        __try
        {
            return MakeCredentialNoSeh(this, pPluginMakeCredentialRequest, response);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            const DWORD exCode = GetExceptionCode();
            if (response)
            {
                *response = {};
            }
            PersistLastMakeCredentialStatus(static_cast<HRESULT>((exCode & 0xFFFF0000) | (g_makeCredentialStage & 0x0000FFFF)));
            return E_FAIL;
        }
    }

    /*
    * This function is invoked by the platform to request the plugin to handle a get assertion operation.
    * Refer: pluginauthenticator.h/pluginauthenticator.idl
    */
    HRESULT STDMETHODCALLTYPE HappyFactoryPlugin::GetAssertion(
        /* [in] */ __RPC__in PCWEBAUTHN_PLUGIN_OPERATION_REQUEST pPluginGetAssertionRequest,
        /* [out] */ __RPC__out PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept
    {
        HRESULT hr = S_OK;
        // Also log to the MakeCredential status file, which we know is observable outside the package.
        PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x47414D01));
        PersistLastGetAssertionStatus(static_cast<HRESULT>(0x47410001));
        __try
        {
            // Entry markers are written via PersistLastGetAssertionStatus.
            return GetAssertionNoSeh(this, pPluginGetAssertionRequest, response);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            hr = wil::ResultFromCaughtException();
            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x47414DFF));
            PersistLastGetAssertionStatus(hr);
            return hr;
        }
    }

    HRESULT GetAssertionNoSeh(
        HappyFactoryPlugin* self,
        PCWEBAUTHN_PLUGIN_OPERATION_REQUEST pPluginGetAssertionRequest,
        PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept
    {
        HRESULT hr = S_OK;
        try
        {
            RETURN_HR_IF_NULL(E_INVALIDARG, response);
            *response = {};
            RETURN_HR_IF_NULL(E_INVALIDARG, pPluginGetAssertionRequest);

            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x47414D02));
            PersistLastGetAssertionStatus(static_cast<HRESULT>(0x47410002));

            com_ptr<App> curApp = self->m_app;
            if (!curApp)
            {
                return E_UNEXPECTED;
            }

            // Atomically check if an operation is already in progress.
            if (!TryAcquireOperationInProgressFlag(curApp->m_isOperationInProgress))
            {
                return HRESULT_FROM_WIN32(ERROR_BUSY); // Another operation is running.
            }
            // Ensure the flag is cleared when the function exits, for any reason.
            auto clearOperationInProgress = wil::scope_exit([&]
            {
                curApp->m_isOperationInProgress = false;
            });

            curApp->SetPluginTransactionId(pPluginGetAssertionRequest->transactionId);
            auto completePluginOperation = wil::SetEvent_scope_exit(self->m_hPluginOpCompletedEvent.get());

            PWEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST pDecodedAssertionRequest;

            THROW_IF_FAILED(WebAuthNDecodeGetAssertionRequest(
                pPluginGetAssertionRequest->cbEncodedRequest,
                pPluginGetAssertionRequest->pbEncodedRequest,
                &pDecodedAssertionRequest));

            auto cleanup = wil::scope_exit([&] {
                WebAuthNFreeDecodedGetAssertionRequest(pDecodedAssertionRequest);
            });

            wil::shared_cotaskmem_string rpName = wil::make_cotaskmem_string(pDecodedAssertionRequest->pwszRpId);

            //load the user handle
            auto& credManager = PluginCredentialManager::getInstance();
            credManager.ReloadCredentialManager();
            credManager.ReloadRegistryValues();
            const WEBAUTHN_CREDENTIAL_DETAILS* selectedCredential = nullptr;
            // create a list of credentials
            std::vector<const WEBAUTHN_CREDENTIAL_DETAILS*> selectedCredentials;

            // Wait for credentials to be loaded with timeout
            constexpr int kCredentialMetadataLoadWaitIterations = 100;
            constexpr int kCredentialMetadataLoadWaitIntervalMs = 100;
            int waitCount = 0;
            
            while (waitCount < kCredentialMetadataLoadWaitIterations)
            {
                Sleep(kCredentialMetadataLoadWaitIntervalMs);
                if (credManager.IsLocalCredentialMetadataLoaded())
                {
                    credManager.GetLocalCredsByRpIdAndAllowList(pDecodedAssertionRequest->pwszRpId,
                        pDecodedAssertionRequest->CredentialList.ppCredentials,
                        pDecodedAssertionRequest->CredentialList.cCredentials,
                        selectedCredentials);
                    break;
                }
                ++waitCount;
            }

            if (selectedCredentials.empty())
            {
                SetPerformOperationStatus(*curApp, NTE_NOT_FOUND);
                THROW_HR(NTE_NOT_FOUND);
            }
            else if (selectedCredentials.size() == 1)
            {
                selectedCredential = selectedCredentials[0];
            }
            else
            {
                RETURN_HR_IF(E_UNEXPECTED, !curApp->GetDispatcherQueue().TryEnqueue([
                    curApp,
                    rpId = std::wstring(pDecodedAssertionRequest->pwszRpId),
                    selectedCredentials,
                    hWnd = pPluginGetAssertionRequest->hWnd]()
                {
                    curApp->SetMatchingCredentials(rpId, selectedCredentials, hWnd);
                }));

                DWORD hIndex = 0;
                constexpr DWORD kCredentialSelectionWaitTimeoutMs = 15000;
                HRESULT hrSelection = CoWaitForMultipleHandles(
                    COWAIT_DISPATCH_WINDOW_MESSAGES | COWAIT_DISPATCH_CALLS, 
                    kCredentialSelectionWaitTimeoutMs,
                    1, 
                    curApp->m_hPluginCredentialSelected.addressof(), 
                    &hIndex);

                bool selectionTimedOut =
                    hrSelection == RPC_S_CALLPENDING ||
                    hrSelection == HRESULT_FROM_WIN32(ERROR_TIMEOUT);

                if (selectionTimedOut)
                {
                    selectedCredential = selectedCredentials[0];
                }
                else
                {
                    THROW_IF_FAILED(hrSelection);

                    {
                        std::lock_guard<std::mutex> lock(curApp->m_pluginOperationOptionsMutex);
                        selectedCredential = curApp->m_pluginOperationOptions.selectedCredential;
                    }
                }

                // Failed to select a credential
                if (!selectedCredential ||
                    selectedCredential->cbCredentialID == 0 ||
                    selectedCredential->pbCredentialID == nullptr ||
                    selectedCredential->pUserInformation == nullptr ||
                    selectedCredential->pUserInformation->pwszName == nullptr)
                {
                    SetPerformOperationStatus(*curApp, NTE_NOT_FOUND);
                    THROW_HR(NTE_NOT_FOUND);
                }
            }

            wil::shared_cotaskmem_string userName = wil::make_cotaskmem_string(selectedCredential->pUserInformation->pwszName);

            std::vector<BYTE> requestBuffer(
                pPluginGetAssertionRequest->pbEncodedRequest,
                pPluginGetAssertionRequest->pbEncodedRequest + pPluginGetAssertionRequest->cbEncodedRequest);

            HRESULT requestSignResult = VerifyRequestSignatureIfPresent(
                requestBuffer,
                pPluginGetAssertionRequest->pbRequestSignature,
                pPluginGetAssertionRequest->cbRequestSignature);

            {
                std::lock_guard<std::mutex> lock(curApp->m_pluginOperationOptionsMutex);
                curApp->m_pluginOperationStatus.requestSignatureVerificationStatus = requestSignResult;
            }

            hr = self->PerformUserVerification(
                pPluginGetAssertionRequest->hWnd,
                pPluginGetAssertionRequest->transactionId,
                PluginOperationType::GetAssertion,
                requestBuffer,
                rpName,
                userName);
            THROW_IF_FAILED(hr);

            PersistGetAssertionInfo(
                pDecodedAssertionRequest->pwszRpId,
                selectedCredential ? selectedCredential->cbCredentialID : 0,
                (selectedCredential && selectedCredential->pUserInformation) ? selectedCredential->pUserInformation->cbId : 0);

            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x47414D03));

            // convert user handle to a string
            std::wstring keyNameStr = happyfactoryplugin_key_domain;
            std::wstringstream keyNameStream;
            for (DWORD idx = 0; idx < selectedCredential->pUserInformation->cbId; idx++)
            {
                keyNameStream << std::hex << std::setw(2) << std::setfill(L'0') <<
                    static_cast<int>(selectedCredential->pUserInformation->pbId[idx]);
            }
            keyNameStr += keyNameStream.str();

            //open the key using ncrypt and sign the data
            wil::unique_ncrypt_prov hProvider;
            wil::shared_ncrypt_key hKey;

            // get the provider
            THROW_IF_FAILED(NCryptOpenStorageProvider(&hProvider, nullptr, 0));

            // open the key
            THROW_IF_FAILED(NCryptOpenKey(hProvider.get(), &hKey, keyNameStr.c_str(), 0, 0));

            // set hwnd property
            HWND hWnd;
            if (curApp->GetSilentMode())
            {
                hWnd = curApp->m_pluginOperationOptions.hWnd;
            }
            else
            {
                hWnd = curApp->GetNativeWindowHandle();
            }

            THROW_IF_FAILED(NCryptSetProperty(
                hKey.get(),
                NCRYPT_WINDOW_HANDLE_PROPERTY,
                reinterpret_cast<PBYTE>(&hWnd),
                sizeof(HWND),
                0));

            // create authenticator data
            DWORD cbPackedAuthenticatorData = 0;
            wil::unique_hlocal_ptr<BYTE[]> packedAuthenticatorData;
            std::vector<uint8_t> vCredentialIdBuffer;
            THROW_IF_FAILED(CreateAuthenticatorData(
                hKey.get(),
                PluginOperationType::GetAssertion,
                pDecodedAssertionRequest->cbRpId,
                pDecodedAssertionRequest->pbRpId,
                cbPackedAuthenticatorData,
                packedAuthenticatorData,
                vCredentialIdBuffer));

            wil::unique_hlocal_ptr<BYTE[]> pbSignature = nullptr;
            DWORD cbSignature = 0;

            {
                wil::unique_bcrypt_hash hashHandle;

                THROW_IF_NTSTATUS_FAILED(BCryptCreateHash(
                    BCRYPT_SHA256_ALG_HANDLE,
                    &hashHandle,
                    nullptr,
                    0,
                    nullptr,
                    0,
                    0));

                THROW_IF_NTSTATUS_FAILED(BCryptHashData(
                    hashHandle.get(), 
                    const_cast<PUCHAR>(packedAuthenticatorData.get()), 
                    cbPackedAuthenticatorData, 
                    0));

                THROW_IF_NTSTATUS_FAILED(BCryptHashData(
                    hashHandle.get(), 
                    const_cast<PUCHAR>(pDecodedAssertionRequest->pbClientDataHash), 
                    pDecodedAssertionRequest->cbClientDataHash, 
                    0));

                DWORD bytesRead = 0;
                DWORD cbSignatureBuffer = 0;
                THROW_IF_NTSTATUS_FAILED(BCryptGetProperty(
                    hashHandle.get(),
                    BCRYPT_HASH_LENGTH,
                    reinterpret_cast<PBYTE>(&cbSignatureBuffer),
                    sizeof(cbSignatureBuffer),
                    &bytesRead,
                    0));

                wil::unique_hlocal_ptr<BYTE[]> signatureBuffer = wil::make_unique_hlocal<BYTE[]>(cbSignatureBuffer);

                THROW_IF_NTSTATUS_FAILED(BCryptFinishHash(
                    hashHandle.get(), 
                    signatureBuffer.get(), 
                    cbSignatureBuffer, 
                    0));

                // sign the data
                THROW_IF_FAILED(NCryptSignHash(
                    hKey.get(), 
                    nullptr, 
                    signatureBuffer.get(), 
                    cbSignatureBuffer, 
                    nullptr, 
                    0, 
                    &cbSignature, 
                    0));

                pbSignature = wil::make_unique_hlocal<BYTE[]>(cbSignature);

                THROW_IF_FAILED(NCryptSignHash(
                    hKey.get(), 
                    nullptr, 
                    signatureBuffer.get(), 
                    cbSignatureBuffer, 
                    pbSignature.get(), 
                    cbSignature, 
                    &cbSignature, 
                    0));

                // CNG ECDSA signature output format can vary by provider/algorithm:
                // - raw signature: R||S (fixed size)
                // - DER signature: 0x30 ... (ASN.1 SEQUENCE)
                // passkey.org expects DER. If we already got DER, do not re-encode.
                const bool looksLikeDer = (cbSignature >= 2 && pbSignature && pbSignature.get()[0] == 0x30);
                if (!looksLikeDer)
                {
                    RETURN_HR_IF(E_UNEXPECTED, cbSignature < 2);
                    RETURN_HR_IF(E_UNEXPECTED, (cbSignature % 2) != 0);

                    auto appendDerLength = [](std::vector<BYTE>& out, size_t len)
                        {
                            if (len < 0x80)
                            {
                                out.push_back(static_cast<BYTE>(len));
                                return;
                            }

                            BYTE buf[sizeof(size_t)]{};
                            size_t n = 0;
                            size_t v = len;
                            while (v > 0)
                            {
                                buf[n++] = static_cast<BYTE>(v & 0xFF);
                                v >>= 8;
                            }
                            out.push_back(static_cast<BYTE>(0x80 | n));
                            for (size_t i = 0; i < n; ++i)
                            {
                                out.push_back(buf[n - 1 - i]);
                            }
                        };

                    auto encodeDerInteger = [&](PBYTE signature, size_t signatureSize) -> std::vector<BYTE>
                        {
                            // Trim leading zeros for minimal DER encoding.
                            size_t start = 0;
                            while (start < signatureSize && signature[start] == 0x00)
                            {
                                ++start;
                            }
                            const bool allZero = (start == signatureSize);

                            const BYTE* p = allZero ? signature : (signature + start);
                            const size_t n = allZero ? 1 : (signatureSize - start);

                            const bool needsPad = !allZero && WI_IsFlagSet(p[0], 0x80);

                            std::vector<BYTE> out;
                            out.push_back(0x02); // INTEGER
                            appendDerLength(out, n + (needsPad ? 1 : 0));
                            if (needsPad)
                            {
                                out.push_back(0x00);
                            }
                            if (allZero)
                            {
                                out.push_back(0x00);
                            }
                            else
                            {
                                out.insert(out.end(), p, p + n);
                            }
                            return out;
                        };

                    const size_t half = cbSignature / 2;
                    auto signatureR = encodeDerInteger(pbSignature.get(), half);
                    auto signatureS = encodeDerInteger(pbSignature.get() + half, half);

                    std::vector<BYTE> encodedSignature;
                    encodedSignature.push_back(0x30); // SEQUENCE
                    appendDerLength(encodedSignature, signatureR.size() + signatureS.size());
                    encodedSignature.insert(encodedSignature.end(), signatureR.begin(), signatureR.end());
                    encodedSignature.insert(encodedSignature.end(), signatureS.begin(), signatureS.end());

                    cbSignature = static_cast<DWORD>(encodedSignature.size());
                    pbSignature.reset();
                    pbSignature = wil::make_unique_hlocal<BYTE[]>(cbSignature);

                    memcpy_s(pbSignature.get(), cbSignature, encodedSignature.data(), cbSignature);
                }
            }

            auto assertionResponse = wil::make_unique_cotaskmem<WEBAUTHN_ASSERTION>();
            THROW_HR_IF_NULL(E_OUTOFMEMORY, assertionResponse);

            *assertionResponse = {};

            assertionResponse->dwVersion = WEBAUTHN_ASSERTION_CURRENT_VERSION;

            // Provide PRF/HMAC-secret output for vault recovery.
            // For now we derive a stable 32-byte secret from the persisted private key and the fixed salt.
            const bool hasHmacSaltInput =
                pDecodedAssertionRequest->pbHmacSecretSaltValues != nullptr &&
                pDecodedAssertionRequest->cbHmacSecretSaltValues >= WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH;

            std::array<BYTE, 32> prfSecret{};
            if (hasHmacSaltInput)
            {
                std::span<const BYTE> prfSaltBytes(
                    pDecodedAssertionRequest->pbHmacSecretSaltValues,
                    WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH);

                DWORD cbPriv = 0;
                THROW_IF_FAILED(NCryptExportKey(
                    hKey.get(),
                    0,
                    BCRYPT_ECCPRIVATE_BLOB,
                    nullptr,
                    nullptr,
                    0,
                    &cbPriv,
                    0));

                std::vector<BYTE> priv(cbPriv);
                THROW_IF_FAILED(NCryptExportKey(
                    hKey.get(),
                    0,
                    BCRYPT_ECCPRIVATE_BLOB,
                    nullptr,
                    priv.data(),
                    cbPriv,
                    &cbPriv,
                    0));
                priv.resize(cbPriv);

                THROW_IF_FAILED(ComputeHmacSha256(priv, prfSaltBytes, prfSecret));

                PersistProtectedHmacSecret(std::span<const BYTE>(prfSecret.data(), prfSecret.size()));

                using HmacSecretOut = std::remove_pointer_t<decltype(assertionResponse->pHmacSecret)>;

                wil::unique_cotaskmem_ptr<BYTE[]> hmacOutBytes(
                    reinterpret_cast<BYTE*>(CoTaskMemAlloc(sizeof(HmacSecretOut))));
                THROW_HR_IF_NULL(E_OUTOFMEMORY, hmacOutBytes);
                auto hmacOut = reinterpret_cast<decltype(assertionResponse->pHmacSecret)>(hmacOutBytes.get());
                *hmacOut = {};
                hmacOut->cbFirst = static_cast<DWORD>(prfSecret.size());

                wil::unique_cotaskmem_ptr<BYTE[]> hmacFirst(
                    reinterpret_cast<BYTE*>(CoTaskMemAlloc(hmacOut->cbFirst)));
                THROW_HR_IF_NULL(E_OUTOFMEMORY, hmacFirst);
                memcpy_s(hmacFirst.get(), hmacOut->cbFirst, prfSecret.data(), prfSecret.size());

                hmacOut->pbFirst = hmacFirst.get();
                hmacOut->cbSecond = 0;
                hmacOut->pbSecond = nullptr;
                assertionResponse->pHmacSecret = hmacOut;
            }
            else
            {
                assertionResponse->pHmacSecret = nullptr;
            }

            // [1] Credential (optional)
            assertionResponse->Credential.dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
            assertionResponse->Credential.cbId = selectedCredential->cbCredentialID;
            assertionResponse->Credential.pbId = selectedCredential->pbCredentialID;
            assertionResponse->Credential.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;

            // [2] AuthenticatorData
            assertionResponse->cbAuthenticatorData = cbPackedAuthenticatorData;
            assertionResponse->pbAuthenticatorData = packedAuthenticatorData.get();

            // [3] Signature
            assertionResponse->cbSignature = cbSignature;
            assertionResponse->pbSignature = pbSignature.get();

            // [4] User (optional)
            wil::unique_cotaskmem_ptr<BYTE[]> userIdBytes;
            if (selectedCredential &&
                selectedCredential->pUserInformation != nullptr &&
                selectedCredential->pUserInformation->cbId > 0 &&
                selectedCredential->pUserInformation->pbId != nullptr)
            {
                userIdBytes.reset(reinterpret_cast<BYTE*>(
                    CoTaskMemAlloc(selectedCredential->pUserInformation->cbId)));
                THROW_HR_IF_NULL(E_OUTOFMEMORY, userIdBytes);
                memcpy_s(
                    userIdBytes.get(),
                    selectedCredential->pUserInformation->cbId,
                    selectedCredential->pUserInformation->pbId,
                    selectedCredential->pUserInformation->cbId);
                assertionResponse->cbUserId = selectedCredential->pUserInformation->cbId;
                assertionResponse->pbUserId = userIdBytes.get();
            }
            else
            {
                assertionResponse->cbUserId = 0;
                assertionResponse->pbUserId = nullptr;
            }

            wil::unique_cotaskmem_ptr<WEBAUTHN_USER_ENTITY_INFORMATION> userInfo;
            wil::unique_cotaskmem_string userInfoName;
            wil::unique_cotaskmem_string userInfoDisplayName;
            if (selectedCredential && selectedCredential->pUserInformation)
            {
                userInfo.reset(reinterpret_cast<WEBAUTHN_USER_ENTITY_INFORMATION*>(
                    CoTaskMemAlloc(sizeof(WEBAUTHN_USER_ENTITY_INFORMATION))));
                THROW_HR_IF_NULL(E_OUTOFMEMORY, userInfo);
                *userInfo = {};
                userInfo->dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;

                userInfo->cbId = assertionResponse->cbUserId;
                userInfo->pbId = assertionResponse->pbUserId;

                if (selectedCredential->pUserInformation->pwszName)
                {
                    userInfoName = wil::make_cotaskmem_string(selectedCredential->pUserInformation->pwszName);
                    userInfo->pwszName = userInfoName.get();
                }
                if (selectedCredential->pUserInformation->pwszDisplayName)
                {
                    userInfoDisplayName = wil::make_cotaskmem_string(selectedCredential->pUserInformation->pwszDisplayName);
                    userInfo->pwszDisplayName = userInfoDisplayName.get();
                }
            }

            // WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE: This structure represents the complete get assertion
            // response including WebAuthn assertion, user information, and credential count.
            // Used for encoding into CBOR format for platform consumption.
            auto ctapGetAssertionResponse = wil::make_unique_cotaskmem<WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE>();
            THROW_HR_IF_NULL(E_OUTOFMEMORY, ctapGetAssertionResponse);

            *ctapGetAssertionResponse = {};

            ctapGetAssertionResponse->WebAuthNAssertion = *(assertionResponse.get()); // [1] Credential, [2] AuthenticatorData, [3] Signature
            ctapGetAssertionResponse->pUserInformation = userInfo.get(); // [4] User
            ctapGetAssertionResponse->dwNumberOfCredentials = 1; // [5] NumberOfCredentials

            std::vector<BYTE> ext;
            wil::unique_cotaskmem_ptr<BYTE[]> extBytes;
            if (hasHmacSaltInput)
            {
                // Encode: { "hmac-secret": { 1: <32-byte output> } }
                (void)CborLite::encodeMapSize(ext, 1u);
                (void)CborLite::encodeText(ext, std::string("hmac-secret"));
                (void)CborLite::encodeMapSize(ext, 1u);
                (void)CborLite::encodeUnsigned(ext, 1u);
                (void)CborLite::encodeBytes(ext, std::span<const BYTE>(prfSecret.data(), prfSecret.size()));

                extBytes.reset(reinterpret_cast<BYTE*>(
                    CoTaskMemAlloc(static_cast<SIZE_T>(ext.size()))));
                THROW_HR_IF_NULL(E_OUTOFMEMORY, extBytes);
                memcpy_s(extBytes.get(), ext.size(), ext.data(), ext.size());
            }

            // Prefer experimental encoder.
            DWORD cbAssertionBuffer = 0;
            wil::unique_cotaskmem_ptr<BYTE[]> pbAssertionBuffer;
            HRESULT encodeHr = E_NOTIMPL;
            {
                EXPERIMENTAL_WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE experimentalResponse = {};
                experimentalResponse.WebAuthNAssertion = *(assertionResponse.get());
                experimentalResponse.pUserInformation = userInfo.get();
                experimentalResponse.dwNumberOfCredentials = 1;
                experimentalResponse.cbUnsignedExtensionOutputs = static_cast<DWORD>(ext.size());
                experimentalResponse.pbUnsignedExtensionOutputs = extBytes.get();

                encodeHr = EXPERIMENTAL_WebAuthNEncodeGetAssertionResponse(
                    &experimentalResponse,
                    &cbAssertionBuffer,
                    wil::out_param(pbAssertionBuffer));
            }

            if (encodeHr == E_NOTIMPL || FAILED(encodeHr))
            {
                ctapGetAssertionResponse->cbUnsignedExtensionOutputs = static_cast<DWORD>(ext.size());
                ctapGetAssertionResponse->pbUnsignedExtensionOutputs = extBytes.get();

                PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x47414E02));
                encodeHr = WebAuthNEncodeGetAssertionResponse(
                    (PCWEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE)(ctapGetAssertionResponse.get()),
                    &cbAssertionBuffer,
                    wil::out_param(pbAssertionBuffer));
                PersistLastMakeCredentialStatus(encodeHr);
            }
            else
            {
                PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x47414E01));
                PersistLastMakeCredentialStatus(encodeHr);
            }

            THROW_IF_FAILED(encodeHr);

            response->cbEncodedResponse = cbAssertionBuffer;
            response->pbEncodedResponse = nullptr;
            if (cbAssertionBuffer > 0)
            {
                response->pbEncodedResponse = reinterpret_cast<byte*>(CoTaskMemAlloc(cbAssertionBuffer));
                THROW_HR_IF_NULL(E_OUTOFMEMORY, response->pbEncodedResponse);
                memcpy_s(response->pbEncodedResponse, cbAssertionBuffer, pbAssertionBuffer.get(), cbAssertionBuffer);
            }
            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x47414D04));
            PersistLastMakeCredentialStatus(S_OK);
            return S_OK;
        }
        catch (...)
        {
            hr = wil::ResultFromCaughtException();
            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x47414D04));
            PersistLastMakeCredentialStatus(hr);
            try
            {
                winrt::com_ptr<App> curApp = self->m_app;
                if (curApp)
                {
                    std::lock_guard<std::mutex> lock(curApp->m_pluginOperationOptionsMutex);
                    curApp->m_pluginOperationStatus.performOperationStatus = hr;
                }
            }
            catch (...)
            {
                // Ignore errors during cleanup
            }
            return hr;
        }
    }

    /*
    * This function is invoked by the platform to fetch the state of the plugin's vault
    */
    HRESULT STDMETHODCALLTYPE HappyFactoryPlugin::GetLockStatus(
        /* [out] */ __RPC__out PLUGIN_LOCK_STATUS* vaultState) noexcept
    {
        auto& credManager = PluginCredentialManager::getInstance();
        credManager.ReloadRegistryValues();
        *vaultState = credManager.GetVaultLock() ? PluginLocked : PluginUnlocked;
        return S_OK;
    }

    /*
    * This function is invoked by the platform to request the plugin to cancel an ongoing operation.
    */
    HRESULT STDMETHODCALLTYPE HappyFactoryPlugin::CancelOperation(
        /* [out] */ __RPC__in PCWEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST pCancelRequest)
    {
        try
        {
            RETURN_HR_IF_NULL(E_INVALIDARG, pCancelRequest);

            com_ptr<App> curApp = m_app;
            if (!curApp)
            {
                return S_OK;
            }

            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D43CA01));
            if (curApp->GetPluginTransactionId() != pCancelRequest->transactionId)
            {
                // Cancellation can legitimately arrive after the operation already completed/reset.
                // Treat this as a no-op success to avoid surfacing a platform error dialog.
                return S_OK;
            }

            // Notify the operation thread that cancellation was requested.
            // HandlePluginOperations will consume this and execute PluginCancelAction in one place.
            SetEvent(m_hPluginCancelOperationEvent.get());
            return S_OK;
        }
        catch (...)
        {
            return winrt::to_hresult();
        }
    }

    /*
    * This is a sample implementation of a factory method that creates an instance of the Class that implements
    * the IPluginAuthenticator interface. The IPluginAuthenticator interface is the core COM interface that
    * third-party passkey authenticator plugins must implement for Windows. This interface enables plugins to
    * participate in WebAuthn operations by handling make credential, get assertion, lock status, and operation
    * cancellation requests.
    * Refer: pluginauthenticator.h/pluginauthenticator.idl for the interface definition.
    */
    HRESULT __stdcall HappyFactoryPluginFactory::CreateInstance(
        ::IUnknown* outer,
        GUID const& iid,
        void** result) noexcept
    {
        try
        {
            // Factory marker: confirms COM activation reached the server and factory.
            PersistLastMakeCredentialStatus(static_cast<HRESULT>(0x4D434F01));
            RETURN_HR_IF_NULL(E_INVALIDARG, result);
            *result = nullptr;

            if (outer)
            {
                return CLASS_E_NOAGGREGATION;
            }

            return make<HappyFactoryPlugin>(m_app, m_hPluginOpCompletedEvent, m_hAppReadyForPluginOpEvent, m_hPluginCancelOperationEvent)->QueryInterface(iid, result);
        }
        catch (...)
        {
            return winrt::to_hresult();
        }
    }

    HRESULT __stdcall HappyFactoryPluginFactory::LockServer(BOOL) noexcept
    {
        return S_OK;
    }
}
