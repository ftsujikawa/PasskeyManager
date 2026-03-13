#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tsupasswd
{
    enum class VaultItemType : uint8_t
    {
        Login = 1,
    };

    struct VaultItemLoginV1
    {
        std::wstring Username;
        std::wstring Password;
        std::wstring Url;
        std::wstring TotpSecret;
    };

    struct VaultItemV1
    {
        std::wstring ItemId;
        VaultItemType ItemType{ VaultItemType::Login };
        std::wstring Title;
        std::wstring Notes;
        std::wstring CreatedAt;
        std::wstring UpdatedAt;
        bool Deleted{ false };
        std::wstring DeletedAt;
        VaultItemLoginV1 Login{};
    };

    struct VaultDocumentV1
    {
        int32_t SchemaVersion{ 1 };
        std::wstring VaultId;
        int64_t Revision{ 0 };
        std::vector<VaultItemV1> Items;
    };
}
