#pragma once

#include <cstdint>
#include <string>

namespace tsupasswd
{
    struct VaultBlob
    {
        std::wstring CiphertextBase64{};
        std::wstring NonceBase64{};
        std::wstring AadBase64{};
        std::wstring Algorithm{ L"AES-256-GCM" };
    };

    struct KeyEnvelope
    {
        std::wstring KekScheme{ L"passkey+recovery_code_v1" };
        std::wstring WrappedDekBase64{};
        std::wstring WrapNonceBase64{};
        std::wstring KdfSaltBase64{};
        std::wstring KdfInfo{ L"vault-dek-wrap" };
    };

    struct VaultMeta
    {
        std::wstring CreatedAt{};
        std::wstring UpdatedAt{};
        std::wstring LastWriterDeviceId{};
        std::wstring BlobSha256Base64{};
    };

    struct VaultRecord
    {
        std::wstring UserId{};
        int64_t VaultVersion{ 0 };
        std::wstring DeviceClock{};
        VaultBlob Blob{};
        KeyEnvelope Envelope{};
        VaultMeta Meta{};
    };

    struct PutVaultRequest
    {
        int64_t ExpectedVersion{ 0 };
        int64_t NewVersion{ 0 };
        std::wstring DeviceId{};
        VaultBlob Blob{};
        KeyEnvelope Envelope{};
        VaultMeta Meta{};
    };

    struct PutVaultResponse
    {
        bool Ok{ false };
        int64_t VaultVersion{ 0 };
        std::wstring UpdatedAt{};
    };

    struct SyncHttpStatus
    {
        int32_t StatusCode{ 0 };
        int64_t ServerVersion{ -1 };
        std::wstring ErrorCode{};
        std::wstring ErrorMessage{};
    };

    // 自前同期 API クライアントの最小雛形。
    // NOTE: 現時点ではHTTP実装は未接続。E_NOTIMPL を返す。
    class SyncClient final
    {
    public:
        explicit SyncClient(std::wstring baseUrl);

        void SetBearerToken(std::wstring bearerToken);
        void SetTimeoutMs(int32_t timeoutMs);

        HRESULT GetVault(
            std::wstring const& userId,
            VaultRecord& outRecord,
            SyncHttpStatus* outStatus = nullptr) const noexcept;

        HRESULT PutVault(
            std::wstring const& userId,
            PutVaultRequest const& request,
            PutVaultResponse& outResponse,
            SyncHttpStatus* outStatus = nullptr) const noexcept;

    private:
        std::wstring m_baseUrl;
        std::wstring m_bearerToken;
        int32_t m_timeoutMs{ 15000 };
    };
}
