#include "pch.h"
#include "VaultSerialization.h"

#include <winrt/Windows.Data.Json.h>

namespace tsupasswd
{
    namespace
    {
        using namespace winrt::Windows::Data::Json;

        bool TryGetString(JsonObject const& obj, wchar_t const* key, std::wstring& out)
        {
            if (!obj.HasKey(key))
            {
                return false;
            }

            auto value = obj.GetNamedValue(key, nullptr);
            if (!value || value.ValueType() != JsonValueType::String)
            {
                return false;
            }

            out = value.GetString().c_str();
            return true;
        }

        bool TryGetNumber(JsonObject const& obj, wchar_t const* key, double& out)
        {
            if (!obj.HasKey(key))
            {
                return false;
            }

            auto value = obj.GetNamedValue(key, nullptr);
            if (!value || value.ValueType() != JsonValueType::Number)
            {
                return false;
            }

            out = value.GetNumber();
            return true;
        }

        bool ParseVaultItemType(std::wstring const& value, VaultItemType& outType)
        {
            if (value == L"login")
            {
                outType = VaultItemType::Login;
                return true;
            }
            return false;
        }

        std::wstring VaultItemTypeToString(VaultItemType type)
        {
            switch (type)
            {
            case VaultItemType::Login:
                return L"login";
            default:
                return L"unknown";
            }
        }

        bool ValidateRequiredFields(VaultDocumentV1 const& doc, std::wstring& outError)
        {
            if (doc.SchemaVersion != 1)
            {
                outError = L"unsupported_schema_version";
                return false;
            }
            if (doc.VaultId.empty())
            {
                outError = L"vault_id_required";
                return false;
            }

            for (auto const& item : doc.Items)
            {
                if (item.ItemId.empty())
                {
                    outError = L"item_id_required";
                    return false;
                }
                if (item.ItemType != VaultItemType::Login)
                {
                    outError = L"unsupported_item_type";
                    return false;
                }
                if (item.Title.empty())
                {
                    outError = L"title_required";
                    return false;
                }
                if (item.Login.Username.empty())
                {
                    outError = L"login_username_required";
                    return false;
                }
                if (item.Login.Password.empty())
                {
                    outError = L"login_password_required";
                    return false;
                }
            }

            return true;
        }
    }

    bool SerializeVaultDocumentV1(VaultDocumentV1 const& doc, std::wstring& outJson)
    {
        std::wstring validationError;
        if (!ValidateRequiredFields(doc, validationError))
        {
            outJson.clear();
            return false;
        }

        JsonObject root;
        root.SetNamedValue(L"schema_version", JsonValue::CreateNumberValue(static_cast<double>(doc.SchemaVersion)));
        root.SetNamedValue(L"vault_id", JsonValue::CreateStringValue(doc.VaultId));
        root.SetNamedValue(L"revision", JsonValue::CreateNumberValue(static_cast<double>(doc.Revision)));

        JsonArray items;
        for (auto const& item : doc.Items)
        {
            JsonObject itemObj;
            itemObj.SetNamedValue(L"item_id", JsonValue::CreateStringValue(item.ItemId));
            itemObj.SetNamedValue(L"item_type", JsonValue::CreateStringValue(VaultItemTypeToString(item.ItemType)));
            itemObj.SetNamedValue(L"title", JsonValue::CreateStringValue(item.Title));
            itemObj.SetNamedValue(L"notes", JsonValue::CreateStringValue(item.Notes));
            itemObj.SetNamedValue(L"created_at", JsonValue::CreateStringValue(item.CreatedAt));
            itemObj.SetNamedValue(L"updated_at", JsonValue::CreateStringValue(item.UpdatedAt));

            JsonObject login;
            login.SetNamedValue(L"username", JsonValue::CreateStringValue(item.Login.Username));
            login.SetNamedValue(L"password", JsonValue::CreateStringValue(item.Login.Password));
            login.SetNamedValue(L"url", JsonValue::CreateStringValue(item.Login.Url));
            login.SetNamedValue(L"totp_secret", JsonValue::CreateStringValue(item.Login.TotpSecret));
            itemObj.SetNamedValue(L"login", login);

            items.Append(itemObj);
        }

        root.SetNamedValue(L"items", items);
        outJson = root.Stringify().c_str();
        return true;
    }

    bool SerializeVaultDocumentV1ToUtf8Bytes(
        VaultDocumentV1 const& doc,
        std::vector<BYTE>& outBytes)
    {
        std::wstring json;
        if (!SerializeVaultDocumentV1(doc, json))
        {
            outBytes.clear();
            return false;
        }

        std::string utf8 = winrt::to_string(winrt::hstring{ json });
        outBytes.assign(utf8.begin(), utf8.end());
        return true;
    }

    bool DeserializeVaultDocumentV1(
        std::wstring const& json,
        VaultDocumentV1& outDoc,
        std::wstring& outError)
    {
        outDoc = {};
        outError.clear();

        if (json.empty())
        {
            outError = L"empty_json";
            return false;
        }

        JsonObject root;
        try
        {
            root = JsonObject::Parse(json);
        }
        catch (...)
        {
            outError = L"json_parse_failed";
            return false;
        }

        double schemaVersion = 0;
        if (!TryGetNumber(root, L"schema_version", schemaVersion))
        {
            outError = L"schema_version_required";
            return false;
        }
        outDoc.SchemaVersion = static_cast<int32_t>(schemaVersion);

        if (!TryGetString(root, L"vault_id", outDoc.VaultId))
        {
            outError = L"vault_id_required";
            return false;
        }

        double revision = 0;
        if (TryGetNumber(root, L"revision", revision))
        {
            outDoc.Revision = static_cast<int64_t>(revision);
        }

        auto itemsValue = root.GetNamedValue(L"items", nullptr);
        if (!itemsValue || itemsValue.ValueType() != JsonValueType::Array)
        {
            outError = L"items_required";
            return false;
        }

        auto items = itemsValue.GetArray();
        outDoc.Items.reserve(items.Size());

        for (uint32_t i = 0; i < items.Size(); ++i)
        {
            auto itemValue = items.GetAt(i);
            if (!itemValue || itemValue.ValueType() != JsonValueType::Object)
            {
                outError = L"item_object_required";
                return false;
            }

            auto itemObj = itemValue.GetObjectW();
            VaultItemV1 item{};

            if (!TryGetString(itemObj, L"item_id", item.ItemId))
            {
                outError = L"item_id_required";
                return false;
            }

            std::wstring itemType;
            if (!TryGetString(itemObj, L"item_type", itemType) || !ParseVaultItemType(itemType, item.ItemType))
            {
                outError = L"unsupported_item_type";
                return false;
            }

            if (!TryGetString(itemObj, L"title", item.Title))
            {
                outError = L"title_required";
                return false;
            }

            (void)TryGetString(itemObj, L"notes", item.Notes);
            (void)TryGetString(itemObj, L"created_at", item.CreatedAt);
            (void)TryGetString(itemObj, L"updated_at", item.UpdatedAt);

            auto loginValue = itemObj.GetNamedValue(L"login", nullptr);
            if (!loginValue || loginValue.ValueType() != JsonValueType::Object)
            {
                outError = L"login_required";
                return false;
            }
            auto loginObj = loginValue.GetObjectW();

            if (!TryGetString(loginObj, L"username", item.Login.Username))
            {
                outError = L"login_username_required";
                return false;
            }
            if (!TryGetString(loginObj, L"password", item.Login.Password))
            {
                outError = L"login_password_required";
                return false;
            }
            (void)TryGetString(loginObj, L"url", item.Login.Url);
            (void)TryGetString(loginObj, L"totp_secret", item.Login.TotpSecret);

            outDoc.Items.push_back(std::move(item));
        }

        return ValidateRequiredFields(outDoc, outError);
    }

    bool DeserializeVaultDocumentV1FromUtf8Bytes(
        BYTE const* data,
        size_t dataSize,
        VaultDocumentV1& outDoc,
        std::wstring& outError)
    {
        outDoc = {};
        outError.clear();

        if (data == nullptr || dataSize == 0)
        {
            outError = L"empty_json";
            return false;
        }

        std::string utf8(
            reinterpret_cast<char const*>(data),
            reinterpret_cast<char const*>(data) + dataSize);

        std::wstring json;
        try
        {
            json = winrt::to_hstring(utf8).c_str();
        }
        catch (...)
        {
            outError = L"json_utf8_decode_failed";
            return false;
        }

        return DeserializeVaultDocumentV1(json, outDoc, outError);
    }

    bool RunVaultSerializationV1RegressionTests(std::wstring& outError)
    {
        outError.clear();

        VaultDocumentV1 input{};
        input.SchemaVersion = 1;
        input.VaultId = L"regression-vault";
        input.Revision = 7;

        VaultItemV1 item{};
        item.ItemId = L"item-1";
        item.ItemType = VaultItemType::Login;
        item.Title = L"GitHub";
        item.Notes = L"sample";
        item.CreatedAt = L"2026-01-01T00:00:00Z";
        item.UpdatedAt = L"2026-01-01T00:00:00Z";
        item.Login.Username = L"alice";
        item.Login.Password = L"secret";
        item.Login.Url = L"https://github.com";
        item.Login.TotpSecret = L"JBSWY3DPEHPK3PXP";
        input.Items.push_back(item);

        std::vector<BYTE> utf8;
        if (!SerializeVaultDocumentV1ToUtf8Bytes(input, utf8))
        {
            outError = L"roundtrip_serialize_failed";
            return false;
        }

        VaultDocumentV1 roundtrip{};
        if (!DeserializeVaultDocumentV1FromUtf8Bytes(utf8.data(), utf8.size(), roundtrip, outError))
        {
            if (outError.empty())
            {
                outError = L"roundtrip_deserialize_failed";
            }
            return false;
        }

        if (roundtrip.SchemaVersion != 1 ||
            roundtrip.VaultId != input.VaultId ||
            roundtrip.Revision != input.Revision ||
            roundtrip.Items.size() != 1 ||
            roundtrip.Items[0].ItemId != item.ItemId ||
            roundtrip.Items[0].Title != item.Title ||
            roundtrip.Items[0].Login.Username != item.Login.Username ||
            roundtrip.Items[0].Login.Password != item.Login.Password)
        {
            outError = L"roundtrip_value_mismatch";
            return false;
        }

        VaultDocumentV1 invalid{};
        std::wstring invalidError;
        std::wstring invalidJson =
            L"{\"schema_version\":2,\"vault_id\":\"v\",\"revision\":1,\"items\":[]}";
        if (DeserializeVaultDocumentV1(invalidJson, invalid, invalidError))
        {
            outError = L"invalid_schema_should_fail";
            return false;
        }
        if (invalidError != L"unsupported_schema_version")
        {
            outError = L"invalid_schema_error_unexpected";
            return false;
        }

        auto expectDeserializeFailure = [&](std::wstring const& json, std::wstring const& expectedError, std::wstring const& context)
        {
            VaultDocumentV1 local{};
            std::wstring localError;
            if (DeserializeVaultDocumentV1(json, local, localError))
            {
                outError = context + L"_should_fail";
                return false;
            }
            if (localError != expectedError)
            {
                outError = context + L"_unexpected_error";
                return false;
            }
            return true;
        };

        if (!expectDeserializeFailure(
            L"{\"schema_version\":1,\"vault_id\":\"v\",\"revision\":1,\"items\":[{\"item_type\":\"login\",\"title\":\"t\",\"login\":{\"username\":\"u\",\"password\":\"p\"}}]}",
            L"item_id_required",
            L"missing_item_id"))
        {
            return false;
        }

        if (!expectDeserializeFailure(
            L"{\"schema_version\":1,\"vault_id\":\"v\",\"revision\":1,\"items\":[{\"item_id\":\"i\",\"item_type\":\"login\",\"login\":{\"username\":\"u\",\"password\":\"p\"}}]}",
            L"title_required",
            L"missing_title"))
        {
            return false;
        }

        if (!expectDeserializeFailure(
            L"{\"schema_version\":1,\"vault_id\":\"v\",\"revision\":1,\"items\":[{\"item_id\":\"i\",\"item_type\":\"login\",\"title\":\"t\",\"login\":{\"password\":\"p\"}}]}",
            L"login_username_required",
            L"missing_login_username"))
        {
            return false;
        }

        if (!expectDeserializeFailure(
            L"{\"schema_version\":1,\"vault_id\":\"v\",\"revision\":1,\"items\":[{\"item_id\":\"i\",\"item_type\":\"login\",\"title\":\"t\",\"login\":{\"username\":\"u\"}}]}",
            L"login_password_required",
            L"missing_login_password"))
        {
            return false;
        }

        if (!expectDeserializeFailure(
            L"{\"schema_version\":1,\"revision\":1,\"items\":[]}",
            L"vault_id_required",
            L"missing_vault_id"))
        {
            return false;
        }

        if (!expectDeserializeFailure(
            L"{\"schema_version\":1,\"vault_id\":\"v\",\"revision\":1}",
            L"items_required",
            L"missing_items"))
        {
            return false;
        }

        if (!expectDeserializeFailure(
            L"{\"schema_version\":1,\"vault_id\":\"v\",\"revision\":1,\"items\":{}}",
            L"items_required",
            L"invalid_items_type"))
        {
            return false;
        }

        if (!expectDeserializeFailure(
            L"{\"schema_version\":1,\"vault_id\":\"v\",\"revision\":1,\"items\":[{\"item_id\":\"i\",\"item_type\":\"login\",\"title\":\"t\"}]}",
            L"login_required",
            L"missing_login_object"))
        {
            return false;
        }

        return true;
    }
}
