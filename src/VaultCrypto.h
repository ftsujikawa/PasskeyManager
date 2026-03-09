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

    bool WrapVaultCipherForSyncV1(
        std::vector<uint8_t> const& vaultCipherPackage,
        std::vector<uint8_t> const& sessionKeyBytes,
        std::vector<uint8_t>& outWrappedPackage,
        VaultCryptoError& outError);

    bool UnwrapVaultCipherForSyncV1(
        std::vector<uint8_t> const& wrappedPackage,
        std::vector<uint8_t> const& sessionKeyBytes,
        std::vector<uint8_t>& outVaultCipherPackage,
        VaultCryptoError& outError);

    bool EncryptVaultV3(
        std::vector<uint8_t> const& plaintext,
        std::vector<uint8_t> const& recoveryCodeBytes,
        std::vector<uint8_t>& outCipherPackage,
        VaultCryptoError& outError);

    bool DecryptVaultV3(
        std::vector<uint8_t> const& cipherPackage,
        std::vector<uint8_t> const& recoveryCodeBytes,
        std::vector<uint8_t>& outPlaintext,
        VaultCryptoError& outError);

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
