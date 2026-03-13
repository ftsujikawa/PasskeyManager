#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tsupasswd
{
    enum class VaultItemType : uint8_t
    {
        Login = 1,
        PasskeyMetadata = 2,
    };

    struct VaultItemLoginV1
    {
        std::wstring Username;
        std::wstring Password;
        std::wstring Url;
        std::wstring TotpSecret;
    };

    struct VaultItemPasskeyMetadataV1
    {
        std::wstring CredentialIdBase64;
        std::wstring UserIdBase64;
        std::wstring RpId;
        std::wstring RpName;
        std::wstring UserName;
        std::wstring UserDisplayName;
        uint64_t CreatedAtUnixSeconds{ 0 };
        uint64_t UpdatedAtUnixSeconds{ 0 };
    };

    struct VaultItemV1
    {
        std::wstring ItemId;
        VaultItemType ItemType{ VaultItemType::Login };
        std::wstring Title;
        std::wstring Notes;
        std::wstring CreatedAt;
        std::wstring UpdatedAt;
        VaultItemLoginV1 Login{};
        VaultItemPasskeyMetadataV1 PasskeyMetadata{};
    };

    struct VaultDocumentV1
    {
        int32_t SchemaVersion{ 1 };
        std::wstring VaultId;
        int64_t Revision{ 0 };
        std::vector<VaultItemV1> Items;
    };
}
