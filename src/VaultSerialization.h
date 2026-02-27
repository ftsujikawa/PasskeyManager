#pragma once

#include "VaultModel.h"

namespace tsupasswd
{
    bool SerializeVaultDocumentV1(VaultDocumentV1 const& doc, std::wstring& outJson);

    bool DeserializeVaultDocumentV1(
        std::wstring const& json,
        VaultDocumentV1& outDoc,
        std::wstring& outError);
}
