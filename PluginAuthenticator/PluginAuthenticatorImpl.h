#pragma once
#include <pch.h>
#include <pluginauthenticator.h>
#include <winrt/Microsoft.UI.Xaml.h>
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#include <vector>

// 新しいGUIDを生成し、下記の値に置き換えてください。
// 例: guidgen.exe で生成した値を使用
static constexpr GUID contosoplugin_guid
{
    0x12345678, 0x9abc, 0x4def, { 0x80, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde }
};
static_assert(contosoplugin_guid.Data1 != 0x7fa07696, "{5DE9572F-EA2C-4178-9CA5-8C957B874E98}");

static constexpr wchar_t contosoplugin_key_domain[] = L"contoso/";

namespace winrt::PasskeyManager::implementation
{
    enum class PluginOperationType
    {
        MakeCredential = 0,
        GetAssertion = 1
    };

    struct ContosoPlugin : winrt::implements<ContosoPlugin, IPluginAuthenticator>
    {
        HRESULT __stdcall MakeCredential(__RPC__in PCWEBAUTHN_PLUGIN_OPERATION_REQUEST pPluginMakeCredentialRequest, __RPC__out PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept;
        HRESULT __stdcall GetAssertion(__RPC__in PCWEBAUTHN_PLUGIN_OPERATION_REQUEST pPluginGetAssertionRequest, __RPC__out PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept;
        HRESULT __stdcall CancelOperation(__RPC__in PCWEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST pCancelRequest);
        HRESULT __stdcall GetLockStatus(__RPC__out PLUGIN_LOCK_STATUS* lockStatus) noexcept;

        HRESULT PerformUserVerification(
            HWND hWnd,
            GUID transactionId,
            PluginOperationType operationType,
            const std::vector<BYTE>& requestBuffer,
            wil::shared_cotaskmem_string rpName,
            wil::shared_cotaskmem_string userName);

        wil::shared_event m_hPluginOpCompletedEvent;
        wil::shared_event m_hAppReadyForPluginOpEvent;
        wil::shared_event m_hPluginCancelOperationEvent;
        ContosoPlugin() = delete;
        // Contructor that takes in the event that set hPluginOpCompletedEvent
        ContosoPlugin(wil::shared_event hPluginOpCompletedEvent,
            wil::shared_event hAppReadyForPluginOpEvent,
            wil::shared_event hPluginUserCancelEvent) :
            m_hPluginOpCompletedEvent(hPluginOpCompletedEvent),
            m_hAppReadyForPluginOpEvent(hAppReadyForPluginOpEvent),
            m_hPluginCancelOperationEvent(hPluginUserCancelEvent)
        {
        }
    };

    struct ContosoPluginFactory : implements<ContosoPluginFactory, IClassFactory>
    {
        HRESULT __stdcall CreateInstance(::IUnknown* outer, GUID const& iid, void** result) noexcept;
        HRESULT __stdcall LockServer(BOOL) noexcept;
        wil::shared_event m_hPluginOpCompletedEvent;
        wil::shared_event m_hAppReadyForPluginOpEvent;
        wil::shared_event m_hPluginCancelOperationEvent;
        ContosoPluginFactory() = delete;
        ContosoPluginFactory(wil::shared_event hPluginOpCompletedEvent,
            wil::shared_event hAppReadyForPluginOpEvent,
            wil::shared_event hPluginUserCancelEvent) :
            m_hPluginOpCompletedEvent(hPluginOpCompletedEvent),
            m_hAppReadyForPluginOpEvent(hAppReadyForPluginOpEvent),
            m_hPluginCancelOperationEvent(hPluginUserCancelEvent)
        {
        }
    };
}
