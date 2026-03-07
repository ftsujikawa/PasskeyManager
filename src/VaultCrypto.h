#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tsupasswd
{
    struct VaultCryptoError
    {
        std::wstring Code;
        std::wstring Detail;
    };

    bool EncryptVaultV2(
        std::vector<uint8_t> const& plaintext,
        std::vector<uint8_t> const& prfSecret,
        std::vector<uint8_t> const& recoveryCodeBytes,
        std::vector<uint8_t>& outCipherPackage,
        VaultCryptoError& outError);

    bool DecryptVaultV2(
        std::vector<uint8_t> const& cipherPackage,
        std::vector<uint8_t> const& prfSecret,
        std::vector<uint8_t> const& recoveryCodeBytes,
        std::vector<uint8_t>& outPlaintext,
        VaultCryptoError& outError);
}
