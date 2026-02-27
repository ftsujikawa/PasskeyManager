#pragma once

#include "VaultModel.h"

namespace tsupasswd
{
    bool SerializeVaultDocumentV1(VaultDocumentV1 const& doc, std::wstring& outJson);

    bool SerializeVaultDocumentV1ToUtf8Bytes(
        VaultDocumentV1 const& doc,
        std::vector<BYTE>& outBytes);

    bool DeserializeVaultDocumentV1(
        std::wstring const& json,
        VaultDocumentV1& outDoc,
        std::wstring& outError);

    bool DeserializeVaultDocumentV1FromUtf8Bytes(
        BYTE const* data,
        size_t dataSize,
        VaultDocumentV1& outDoc,
        std::wstring& outError);

    bool RunVaultSerializationV1RegressionTests(std::wstring& outError);
}
