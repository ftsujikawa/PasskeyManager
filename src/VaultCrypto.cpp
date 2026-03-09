#include "pch.h"
#include "VaultCrypto.h"

#include <bcrypt.h>
#include <cstring>
#include <wil/safecast.h>

#pragma comment(lib, "Bcrypt.lib")

namespace tsupasswd
{
    namespace
    {
        constexpr uint8_t kVaultV2Magic[4] = { 'T', 'V', '2', '0' };
        constexpr uint8_t kVaultV2Version = 1;
        constexpr uint8_t kVaultV3Magic[4] = { 'T', 'V', '3', '0' };
        constexpr uint8_t kVaultV3Version = 1;
        constexpr size_t kAesGcmNonceBytes = 12;
        constexpr size_t kAesGcmTagBytes = 16;
        constexpr size_t kDekBytes = 32;
        constexpr size_t kKekBytes = 32;
        constexpr size_t kHkdfSaltBytes = 16;
        constexpr size_t kWrapNonceBytes = 12;

        void AppendUint32LE(std::vector<uint8_t>& out, uint32_t value)
        {
            out.push_back(static_cast<uint8_t>(value & 0xFF));
            out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
            out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
        }

        bool ReadUint32LE(std::vector<uint8_t> const& bytes, size_t offset, uint32_t& outValue)
        {
            if (offset + sizeof(uint32_t) > bytes.size())
            {
                return false;
            }
            outValue =
                static_cast<uint32_t>(bytes[offset]) |
                (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
                (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
                (static_cast<uint32_t>(bytes[offset + 3]) << 24);
            return true;
        }

        bool GenRandom(std::vector<uint8_t>& out, size_t bytes)
        {
            out.assign(bytes, 0);
            NTSTATUS st = BCryptGenRandom(nullptr, out.data(), wil::safe_cast<ULONG>(out.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            return st == 0;
        }

        bool HmacSha256(std::vector<uint8_t> const& key, std::vector<uint8_t> const& data, std::vector<uint8_t>& outMac)
        {
            outMac.assign(32, 0);

            BCRYPT_ALG_HANDLE hAlg = nullptr;
            if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
            {
                return false;
            }
            auto algCleanup = wil::scope_exit([&]() {
                BCryptCloseAlgorithmProvider(hAlg, 0);
            });

            DWORD objLen = 0;
            DWORD cbResult = 0;
            if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &cbResult, 0) != 0)
            {
                return false;
            }
            std::vector<uint8_t> obj(objLen);

            BCRYPT_HASH_HANDLE hHash = nullptr;
            if (BCryptCreateHash(hAlg,
                &hHash,
                obj.data(),
                wil::safe_cast<ULONG>(obj.size()),
                const_cast<PUCHAR>(key.data()),
                wil::safe_cast<ULONG>(key.size()),
                0) != 0)
            {
                return false;
            }
            auto hashCleanup = wil::scope_exit([&]() {
                BCryptDestroyHash(hHash);
            });

            if (!data.empty())
            {
                if (BCryptHashData(hHash, const_cast<PUCHAR>(data.data()), wil::safe_cast<ULONG>(data.size()), 0) != 0)
                {
                    return false;
                }
            }

            if (BCryptFinishHash(hHash, outMac.data(), wil::safe_cast<ULONG>(outMac.size()), 0) != 0)
            {
                return false;
            }

            return true;
        }

        bool HkdfSha256(
            std::vector<uint8_t> const& salt,
            std::vector<uint8_t> const& ikm,
            std::vector<uint8_t> const& info,
            std::vector<uint8_t>& outKey,
            size_t outKeyBytes)
        {
            // HKDF-Extract
            std::vector<uint8_t> prk;
            if (!HmacSha256(salt, ikm, prk))
            {
                return false;
            }

            // HKDF-Expand
            outKey.clear();
            outKey.reserve(outKeyBytes);

            std::vector<uint8_t> t;
            uint8_t counter = 1;
            while (outKey.size() < outKeyBytes)
            {
                std::vector<uint8_t> msg;
                msg.reserve(t.size() + info.size() + 1);
                msg.insert(msg.end(), t.begin(), t.end());
                msg.insert(msg.end(), info.begin(), info.end());
                msg.push_back(counter);

                if (!HmacSha256(prk, msg, t))
                {
                    return false;
                }

                size_t need = outKeyBytes - outKey.size();
                size_t take = (need < t.size()) ? need : t.size();
                outKey.insert(outKey.end(), t.begin(), t.begin() + take);
                ++counter;
            }

            return outKey.size() == outKeyBytes;
        }

        bool Aes256GcmEncrypt(
            std::vector<uint8_t> const& key,
            std::vector<uint8_t> const& nonce,
            std::vector<uint8_t> const& aad,
            std::vector<uint8_t> const& plaintext,
            std::vector<uint8_t>& outCiphertext,
            std::vector<uint8_t>& outTag)
        {
            outCiphertext.clear();
            outTag.clear();

            if (key.size() != kDekBytes || nonce.size() != kAesGcmNonceBytes)
            {
                return false;
            }

            BCRYPT_ALG_HANDLE hAlg = nullptr;
            if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
            {
                return false;
            }
            auto algCleanup = wil::scope_exit([&]() {
                BCryptCloseAlgorithmProvider(hAlg, 0);
            });

            if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)), sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0)
            {
                return false;
            }

            DWORD objLen = 0;
            DWORD cbResult = 0;
            if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &cbResult, 0) != 0)
            {
                return false;
            }
            std::vector<uint8_t> obj(objLen);

            BCRYPT_KEY_HANDLE hKey = nullptr;
            if (BCryptGenerateSymmetricKey(
                hAlg,
                &hKey,
                obj.data(),
                wil::safe_cast<ULONG>(obj.size()),
                const_cast<PUCHAR>(key.data()),
                wil::safe_cast<ULONG>(key.size()),
                0) != 0)
            {
                return false;
            }
            auto keyCleanup = wil::scope_exit([&]() {
                BCryptDestroyKey(hKey);
            });

            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo{};
            BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
            authInfo.pbNonce = const_cast<PUCHAR>(nonce.data());
            authInfo.cbNonce = wil::safe_cast<ULONG>(nonce.size());
            authInfo.pbAuthData = aad.empty() ? nullptr : const_cast<PUCHAR>(aad.data());
            authInfo.cbAuthData = wil::safe_cast<ULONG>(aad.size());

            outTag.assign(kAesGcmTagBytes, 0);
            authInfo.pbTag = outTag.data();
            authInfo.cbTag = wil::safe_cast<ULONG>(outTag.size());

            ULONG cbCipher = 0;
            NTSTATUS st = BCryptEncrypt(
                hKey,
                plaintext.empty() ? nullptr : const_cast<PUCHAR>(plaintext.data()),
                wil::safe_cast<ULONG>(plaintext.size()),
                &authInfo,
                nullptr,
                0,
                nullptr,
                0,
                &cbCipher,
                0);
            if (st != 0)
            {
                outTag.clear();
                return false;
            }

            outCiphertext.assign(cbCipher, 0);
            st = BCryptEncrypt(
                hKey,
                plaintext.empty() ? nullptr : const_cast<PUCHAR>(plaintext.data()),
                wil::safe_cast<ULONG>(plaintext.size()),
                &authInfo,
                nullptr,
                0,
                outCiphertext.data(),
                cbCipher,
                &cbCipher,
                0);
            if (st != 0)
            {
                outCiphertext.clear();
                outTag.clear();
                return false;
            }

            outCiphertext.resize(cbCipher);
            return true;
        }

        bool Aes256GcmDecrypt(
            std::vector<uint8_t> const& key,
            std::vector<uint8_t> const& nonce,
            std::vector<uint8_t> const& aad,
            std::vector<uint8_t> const& ciphertext,
            std::vector<uint8_t> const& tag,
            std::vector<uint8_t>& outPlaintext)
        {
            outPlaintext.clear();

            if (key.size() != kDekBytes || nonce.size() != kAesGcmNonceBytes || tag.size() != kAesGcmTagBytes)
            {
                return false;
            }

            BCRYPT_ALG_HANDLE hAlg = nullptr;
            if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
            {
                return false;
            }
            auto algCleanup = wil::scope_exit([&]() {
                BCryptCloseAlgorithmProvider(hAlg, 0);
            });

            if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)), sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0)
            {
                return false;
            }

            DWORD objLen = 0;
            DWORD cbResult = 0;
            if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &cbResult, 0) != 0)
            {
                return false;
            }
            std::vector<uint8_t> obj(objLen);

            BCRYPT_KEY_HANDLE hKey = nullptr;
            if (BCryptGenerateSymmetricKey(
                hAlg,
                &hKey,
                obj.data(),
                wil::safe_cast<ULONG>(obj.size()),
                const_cast<PUCHAR>(key.data()),
                wil::safe_cast<ULONG>(key.size()),
                0) != 0)
            {
                return false;
            }
            auto keyCleanup = wil::scope_exit([&]() {
                BCryptDestroyKey(hKey);
            });

            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo{};
            BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
            authInfo.pbNonce = const_cast<PUCHAR>(nonce.data());
            authInfo.cbNonce = wil::safe_cast<ULONG>(nonce.size());
            authInfo.pbAuthData = aad.empty() ? nullptr : const_cast<PUCHAR>(aad.data());
            authInfo.cbAuthData = wil::safe_cast<ULONG>(aad.size());
            authInfo.pbTag = const_cast<PUCHAR>(tag.data());
            authInfo.cbTag = wil::safe_cast<ULONG>(tag.size());

            ULONG cbPlain = 0;
            NTSTATUS st = BCryptDecrypt(
                hKey,
                ciphertext.empty() ? nullptr : const_cast<PUCHAR>(ciphertext.data()),
                wil::safe_cast<ULONG>(ciphertext.size()),
                &authInfo,
                nullptr,
                0,
                nullptr,
                0,
                &cbPlain,
                0);
            if (st != 0)
            {
                return false;
            }

            outPlaintext.assign(cbPlain, 0);
            st = BCryptDecrypt(
                hKey,
                ciphertext.empty() ? nullptr : const_cast<PUCHAR>(ciphertext.data()),
                wil::safe_cast<ULONG>(ciphertext.size()),
                &authInfo,
                nullptr,
                0,
                outPlaintext.data(),
                cbPlain,
                &cbPlain,
                0);
            if (st != 0)
            {
                outPlaintext.clear();
                return false;
            }

            outPlaintext.resize(cbPlain);
            return true;
        }

        void SetError(VaultCryptoError& err, wchar_t const* code, wchar_t const* detail)
        {
            err.Code = code ? code : L"";
            err.Detail = detail ? detail : L"";
        }

        bool BuildKek(
            std::vector<uint8_t> const& prfSecret,
            std::vector<uint8_t> const& recoveryCodeBytes,
            std::vector<uint8_t> const& hkdfSalt,
            std::vector<uint8_t>& outKek)
        {
            if (prfSecret.empty() || recoveryCodeBytes.empty() || hkdfSalt.size() != kHkdfSaltBytes)
            {
                return false;
            }

            std::vector<uint8_t> ikm;
            ikm.reserve(prfSecret.size() + recoveryCodeBytes.size());
            ikm.insert(ikm.end(), prfSecret.begin(), prfSecret.end());
            ikm.insert(ikm.end(), recoveryCodeBytes.begin(), recoveryCodeBytes.end());

            std::vector<uint8_t> info;
            char const* label = "tsupasswd/vault-v2-kek";
            info.assign(label, label + strlen(label));

            return HkdfSha256(hkdfSalt, ikm, info, outKek, kKekBytes);
        }

        bool BuildKekV3(
            std::vector<uint8_t> const& recoveryCodeBytes,
            std::vector<uint8_t> const& hkdfSalt,
            std::vector<uint8_t>& outKek)
        {
            if (recoveryCodeBytes.empty() || hkdfSalt.size() != kHkdfSaltBytes)
            {
                return false;
            }

            std::vector<uint8_t> info;
            char const* label = "tsupasswd/vault-v3-kek";
            info.assign(label, label + strlen(label));

            std::vector<uint8_t> ikm = recoveryCodeBytes;
            return HkdfSha256(hkdfSalt, ikm, info, outKek, kKekBytes);
        }

        bool BuildRecoveryCodeBytes(std::wstring const& codeWide, std::vector<uint8_t>& outBytes)
        {
            outBytes.clear();
            if (codeWide.empty())
            {
                return false;
            }

            // Keep it simple: use UTF-8 bytes of the provided code.
            std::string codeUtf8 = winrt::to_string(codeWide);
            if (codeUtf8.empty())
            {
                return false;
            }
            outBytes.assign(codeUtf8.begin(), codeUtf8.end());
            return true;
        }

        constexpr uint8_t kSyncWrapMagic[4] = { 'S', 'W', '1', '0' };
        constexpr uint8_t kSyncWrapVersion = 1;

        bool Sha256(std::vector<uint8_t> const& data, std::vector<uint8_t>& outHash)
        {
            outHash.assign(32, 0);

            BCRYPT_ALG_HANDLE hAlg = nullptr;
            if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
            {
                return false;
            }
            auto algCleanup = wil::scope_exit([&]() {
                BCryptCloseAlgorithmProvider(hAlg, 0);
            });

            DWORD objLen = 0;
            DWORD cbResult = 0;
            if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &cbResult, 0) != 0)
            {
                return false;
            }
            std::vector<uint8_t> obj(objLen);

            BCRYPT_HASH_HANDLE hHash = nullptr;
            if (BCryptCreateHash(hAlg, &hHash, obj.data(), wil::safe_cast<ULONG>(obj.size()), nullptr, 0, 0) != 0)
            {
                return false;
            }
            auto hashCleanup = wil::scope_exit([&]() {
                BCryptDestroyHash(hHash);
            });

            if (!data.empty())
            {
                if (BCryptHashData(hHash, const_cast<PUCHAR>(data.data()), wil::safe_cast<ULONG>(data.size()), 0) != 0)
                {
                    return false;
                }
            }

            if (BCryptFinishHash(hHash, outHash.data(), wil::safe_cast<ULONG>(outHash.size()), 0) != 0)
            {
                return false;
            }

            return true;
        }

        bool DeriveSyncWrapKey(std::vector<uint8_t> const& sessionKeyBytes, std::vector<uint8_t>& outKey32)
        {
            if (sessionKeyBytes.empty())
            {
                return false;
            }
            return Sha256(sessionKeyBytes, outKey32);
        }
    }

    bool WrapVaultCipherForSyncV1(
        std::vector<uint8_t> const& vaultCipherPackage,
        std::vector<uint8_t> const& sessionKeyBytes,
        std::vector<uint8_t>& outWrappedPackage,
        VaultCryptoError& outError)
    {
        outWrappedPackage.clear();
        outError = {};

        if (vaultCipherPackage.empty())
        {
            SetError(outError, L"empty_cipher", L"vaultCipherPackage is required");
            return false;
        }

        std::vector<uint8_t> wrapKey;
        if (!DeriveSyncWrapKey(sessionKeyBytes, wrapKey))
        {
            SetError(outError, L"invalid_session_key", L"sessionKeyBytes must be non-empty");
            return false;
        }

        std::vector<uint8_t> nonce;
        if (!GenRandom(nonce, kAesGcmNonceBytes))
        {
            SetError(outError, L"rng_failed", L"BCryptGenRandom(nonce) failed");
            return false;
        }

        std::vector<uint8_t> aad;
        std::vector<uint8_t> wrappedCipher;
        std::vector<uint8_t> wrappedTag;
        if (!Aes256GcmEncrypt(wrapKey, nonce, aad, vaultCipherPackage, wrappedCipher, wrappedTag))
        {
            SetError(outError, L"wrap_failed", L"AES-256-GCM wrap failed");
            return false;
        }

        outWrappedPackage.clear();
        outWrappedPackage.insert(outWrappedPackage.end(), std::begin(kSyncWrapMagic), std::end(kSyncWrapMagic));
        outWrappedPackage.push_back(kSyncWrapVersion);

        AppendUint32LE(outWrappedPackage, wil::safe_cast<uint32_t>(nonce.size()));
        outWrappedPackage.insert(outWrappedPackage.end(), nonce.begin(), nonce.end());

        AppendUint32LE(outWrappedPackage, wil::safe_cast<uint32_t>(wrappedCipher.size()));
        outWrappedPackage.insert(outWrappedPackage.end(), wrappedCipher.begin(), wrappedCipher.end());

        AppendUint32LE(outWrappedPackage, wil::safe_cast<uint32_t>(wrappedTag.size()));
        outWrappedPackage.insert(outWrappedPackage.end(), wrappedTag.begin(), wrappedTag.end());

        return true;
    }

    bool UnwrapVaultCipherForSyncV1(
        std::vector<uint8_t> const& wrappedPackage,
        std::vector<uint8_t> const& sessionKeyBytes,
        std::vector<uint8_t>& outVaultCipherPackage,
        VaultCryptoError& outError)
    {
        outVaultCipherPackage.clear();
        outError = {};

        if (wrappedPackage.size() < 5)
        {
            SetError(outError, L"invalid_package", L"too small");
            return false;
        }
        if (!std::equal(std::begin(kSyncWrapMagic), std::end(kSyncWrapMagic), wrappedPackage.begin()))
        {
            SetError(outError, L"not_wrapped", L"magic mismatch");
            return false;
        }
        if (wrappedPackage[4] != kSyncWrapVersion)
        {
            SetError(outError, L"unsupported_version", L"version mismatch");
            return false;
        }

        std::vector<uint8_t> wrapKey;
        if (!DeriveSyncWrapKey(sessionKeyBytes, wrapKey))
        {
            SetError(outError, L"invalid_session_key", L"sessionKeyBytes must be non-empty");
            return false;
        }

        size_t cursor = 5;
        auto readBlob = [&](std::vector<uint8_t>& out) -> bool
        {
            uint32_t len = 0;
            if (!ReadUint32LE(wrappedPackage, cursor, len))
            {
                return false;
            }
            cursor += sizeof(uint32_t);
            if (cursor + len > wrappedPackage.size())
            {
                return false;
            }
            out.assign(wrappedPackage.begin() + cursor, wrappedPackage.begin() + cursor + len);
            cursor += len;
            return true;
        };

        std::vector<uint8_t> nonce;
        std::vector<uint8_t> cipher;
        std::vector<uint8_t> tag;
        if (!readBlob(nonce) || !readBlob(cipher) || !readBlob(tag))
        {
            SetError(outError, L"invalid_package", L"field parse failed");
            return false;
        }
        if (nonce.size() != kAesGcmNonceBytes || tag.size() != kAesGcmTagBytes)
        {
            SetError(outError, L"invalid_package", L"field size invalid");
            return false;
        }

        std::vector<uint8_t> aad;
        if (!Aes256GcmDecrypt(wrapKey, nonce, aad, cipher, tag, outVaultCipherPackage))
        {
            SetError(outError, L"unwrap_failed", L"AES-256-GCM unwrap failed");
            return false;
        }

        return true;
    }

    bool EncryptVaultV3(
        std::vector<uint8_t> const& plaintext,
        std::vector<uint8_t> const& recoveryCodeBytes,
        std::vector<uint8_t>& outCipherPackage,
        VaultCryptoError& outError)
    {
        outCipherPackage.clear();
        outError = {};

        if (plaintext.empty())
        {
            SetError(outError, L"empty_plaintext", L"plaintext is required");
            return false;
        }
        if (recoveryCodeBytes.empty())
        {
            SetError(outError, L"kek_material_missing", L"recoveryCodeBytes is required");
            return false;
        }

        std::vector<uint8_t> dek;
        if (!GenRandom(dek, kDekBytes))
        {
            SetError(outError, L"rng_failed", L"BCryptGenRandom(dek) failed");
            return false;
        }

        std::vector<uint8_t> nonce;
        if (!GenRandom(nonce, kAesGcmNonceBytes))
        {
            SetError(outError, L"rng_failed", L"BCryptGenRandom(nonce) failed");
            return false;
        }

        std::vector<uint8_t> aad;
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> tag;
        if (!Aes256GcmEncrypt(dek, nonce, aad, plaintext, ciphertext, tag))
        {
            SetError(outError, L"encrypt_failed", L"AES-256-GCM encrypt failed");
            return false;
        }

        std::vector<uint8_t> hkdfSalt;
        if (!GenRandom(hkdfSalt, kHkdfSaltBytes))
        {
            SetError(outError, L"rng_failed", L"BCryptGenRandom(hkdfSalt) failed");
            return false;
        }

        std::vector<uint8_t> kek;
        if (!BuildKekV3(recoveryCodeBytes, hkdfSalt, kek))
        {
            SetError(outError, L"kdf_failed", L"HKDF-SHA256 failed");
            return false;
        }

        std::vector<uint8_t> wrapNonce;
        if (!GenRandom(wrapNonce, kWrapNonceBytes))
        {
            SetError(outError, L"rng_failed", L"BCryptGenRandom(wrapNonce) failed");
            return false;
        }

        std::vector<uint8_t> wrappedDekCipher;
        std::vector<uint8_t> wrappedDekTag;
        std::vector<uint8_t> dekAsPlain = dek;
        if (!Aes256GcmEncrypt(kek, wrapNonce, aad, dekAsPlain, wrappedDekCipher, wrappedDekTag))
        {
            SetError(outError, L"wrap_failed", L"AES-256-GCM wrap(DEK) failed");
            return false;
        }

        outCipherPackage.clear();
        outCipherPackage.insert(outCipherPackage.end(), std::begin(kVaultV3Magic), std::end(kVaultV3Magic));
        outCipherPackage.push_back(kVaultV3Version);

        AppendUint32LE(outCipherPackage, wil::safe_cast<uint32_t>(hkdfSalt.size()));
        outCipherPackage.insert(outCipherPackage.end(), hkdfSalt.begin(), hkdfSalt.end());

        AppendUint32LE(outCipherPackage, wil::safe_cast<uint32_t>(wrapNonce.size()));
        outCipherPackage.insert(outCipherPackage.end(), wrapNonce.begin(), wrapNonce.end());

        AppendUint32LE(outCipherPackage, wil::safe_cast<uint32_t>(wrappedDekCipher.size()));
        outCipherPackage.insert(outCipherPackage.end(), wrappedDekCipher.begin(), wrappedDekCipher.end());

        AppendUint32LE(outCipherPackage, wil::safe_cast<uint32_t>(wrappedDekTag.size()));
        outCipherPackage.insert(outCipherPackage.end(), wrappedDekTag.begin(), wrappedDekTag.end());

        AppendUint32LE(outCipherPackage, wil::safe_cast<uint32_t>(nonce.size()));
        outCipherPackage.insert(outCipherPackage.end(), nonce.begin(), nonce.end());

        AppendUint32LE(outCipherPackage, wil::safe_cast<uint32_t>(ciphertext.size()));
        outCipherPackage.insert(outCipherPackage.end(), ciphertext.begin(), ciphertext.end());

        AppendUint32LE(outCipherPackage, wil::safe_cast<uint32_t>(tag.size()));
        outCipherPackage.insert(outCipherPackage.end(), tag.begin(), tag.end());

        return true;
    }

    bool DecryptVaultV3(
        std::vector<uint8_t> const& cipherPackage,
        std::vector<uint8_t> const& recoveryCodeBytes,
        std::vector<uint8_t>& outPlaintext,
        VaultCryptoError& outError)
    {
        outPlaintext.clear();
        outError = {};

        if (cipherPackage.size() < 5)
        {
            SetError(outError, L"invalid_package", L"too small");
            return false;
        }

        if (!std::equal(std::begin(kVaultV3Magic), std::end(kVaultV3Magic), cipherPackage.begin()))
        {
            SetError(outError, L"not_v3", L"magic mismatch");
            return false;
        }
        if (cipherPackage[4] != kVaultV3Version)
        {
            SetError(outError, L"unsupported_version", L"version mismatch");
            return false;
        }
        if (recoveryCodeBytes.empty())
        {
            SetError(outError, L"kek_material_missing", L"recoveryCodeBytes is required");
            return false;
        }

        size_t cursor = 5;
        auto readBlob = [&](std::vector<uint8_t>& out) -> bool
        {
            uint32_t len = 0;
            if (!ReadUint32LE(cipherPackage, cursor, len))
            {
                return false;
            }
            cursor += sizeof(uint32_t);
            if (cursor + len > cipherPackage.size())
            {
                return false;
            }
            out.assign(cipherPackage.begin() + cursor, cipherPackage.begin() + cursor + len);
            cursor += len;
            return true;
        };

        std::vector<uint8_t> hkdfSalt;
        std::vector<uint8_t> wrapNonce;
        std::vector<uint8_t> wrappedDekCipher;
        std::vector<uint8_t> wrappedDekTag;
        std::vector<uint8_t> vaultNonce;
        std::vector<uint8_t> vaultCipher;
        std::vector<uint8_t> vaultTag;

        if (!readBlob(hkdfSalt) || !readBlob(wrapNonce) || !readBlob(wrappedDekCipher) || !readBlob(wrappedDekTag) || !readBlob(vaultNonce) || !readBlob(vaultCipher) || !readBlob(vaultTag))
        {
            SetError(outError, L"invalid_package", L"field parse failed");
            return false;
        }

        if (hkdfSalt.size() != kHkdfSaltBytes || wrapNonce.size() != kWrapNonceBytes || wrappedDekTag.size() != kAesGcmTagBytes || vaultNonce.size() != kAesGcmNonceBytes || vaultTag.size() != kAesGcmTagBytes)
        {
            SetError(outError, L"invalid_package", L"field size invalid");
            return false;
        }

        std::vector<uint8_t> kek;
        if (!BuildKekV3(recoveryCodeBytes, hkdfSalt, kek))
        {
            SetError(outError, L"kdf_failed", L"HKDF-SHA256 failed");
            return false;
        }

        std::vector<uint8_t> aad;
        std::vector<uint8_t> dek;
        if (!Aes256GcmDecrypt(kek, wrapNonce, aad, wrappedDekCipher, wrappedDekTag, dek))
        {
            SetError(outError, L"unwrap_failed", L"DEK unwrap failed");
            return false;
        }
        if (dek.size() != kDekBytes)
        {
            SetError(outError, L"unwrap_failed", L"DEK length mismatch");
            return false;
        }

        if (!Aes256GcmDecrypt(dek, vaultNonce, aad, vaultCipher, vaultTag, outPlaintext))
        {
            SetError(outError, L"decrypt_failed", L"Vault decrypt failed");
            return false;
        }

        return true;
    }

    bool EncryptVaultV2(
        std::vector<uint8_t> const& plaintext,
        std::vector<uint8_t> const& prfSecret,
        std::vector<uint8_t> const& recoveryCodeBytes,
        std::vector<uint8_t>& outCipherPackage,
        VaultCryptoError& outError)
    {
        outCipherPackage.clear();
        outError = {};

        if (plaintext.empty())
        {
            SetError(outError, L"empty_plaintext", L"plaintext is required");
            return false;
        }
        if (prfSecret.empty() || recoveryCodeBytes.empty())
        {
            SetError(outError, L"kek_material_missing", L"prfSecret and recoveryCodeBytes are required");
            return false;
        }

        std::vector<uint8_t> dek;
        if (!GenRandom(dek, kDekBytes))
        {
            SetError(outError, L"rng_failed", L"BCryptGenRandom(dek) failed");
            return false;
        }

        std::vector<uint8_t> nonce;
        if (!GenRandom(nonce, kAesGcmNonceBytes))
        {
            SetError(outError, L"rng_failed", L"BCryptGenRandom(nonce) failed");
            return false;
        }

        std::vector<uint8_t> aad;
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> tag;
        if (!Aes256GcmEncrypt(dek, nonce, aad, plaintext, ciphertext, tag))
        {
            SetError(outError, L"encrypt_failed", L"AES-256-GCM encrypt failed");
            return false;
        }

        std::vector<uint8_t> hkdfSalt;
        if (!GenRandom(hkdfSalt, kHkdfSaltBytes))
        {
            SetError(outError, L"rng_failed", L"BCryptGenRandom(hkdfSalt) failed");
            return false;
        }

        std::vector<uint8_t> kek;
        if (!BuildKek(prfSecret, recoveryCodeBytes, hkdfSalt, kek))
        {
            SetError(outError, L"kdf_failed", L"HKDF-SHA256 failed");
            return false;
        }

        std::vector<uint8_t> wrapNonce;
        if (!GenRandom(wrapNonce, kWrapNonceBytes))
        {
            SetError(outError, L"rng_failed", L"BCryptGenRandom(wrapNonce) failed");
            return false;
        }

        std::vector<uint8_t> wrappedDekCipher;
        std::vector<uint8_t> wrappedDekTag;
        std::vector<uint8_t> dekAsPlain = dek;
        if (!Aes256GcmEncrypt(kek, wrapNonce, aad, dekAsPlain, wrappedDekCipher, wrappedDekTag))
        {
            SetError(outError, L"wrap_failed", L"AES-256-GCM wrap(DEK) failed");
            return false;
        }

        // Package format:
        // magic(4) version(1)
        // hkdf_salt_len(4) hkdf_salt
        // wrap_nonce_len(4) wrap_nonce
        // wrapped_dek_len(4) wrapped_dek_cipher
        // wrapped_dek_tag_len(4) wrapped_dek_tag
        // vault_nonce_len(4) vault_nonce
        // vault_cipher_len(4) vault_cipher
        // vault_tag_len(4) vault_tag
        outCipherPackage.clear();
        outCipherPackage.insert(outCipherPackage.end(), std::begin(kVaultV2Magic), std::end(kVaultV2Magic));
        outCipherPackage.push_back(kVaultV2Version);

        AppendUint32LE(outCipherPackage, wil::safe_cast<uint32_t>(hkdfSalt.size()));
        outCipherPackage.insert(outCipherPackage.end(), hkdfSalt.begin(), hkdfSalt.end());

        AppendUint32LE(outCipherPackage, wil::safe_cast<uint32_t>(wrapNonce.size()));
        outCipherPackage.insert(outCipherPackage.end(), wrapNonce.begin(), wrapNonce.end());

        AppendUint32LE(outCipherPackage, wil::safe_cast<uint32_t>(wrappedDekCipher.size()));
        outCipherPackage.insert(outCipherPackage.end(), wrappedDekCipher.begin(), wrappedDekCipher.end());

        AppendUint32LE(outCipherPackage, wil::safe_cast<uint32_t>(wrappedDekTag.size()));
        outCipherPackage.insert(outCipherPackage.end(), wrappedDekTag.begin(), wrappedDekTag.end());

        AppendUint32LE(outCipherPackage, wil::safe_cast<uint32_t>(nonce.size()));
        outCipherPackage.insert(outCipherPackage.end(), nonce.begin(), nonce.end());

        AppendUint32LE(outCipherPackage, wil::safe_cast<uint32_t>(ciphertext.size()));
        outCipherPackage.insert(outCipherPackage.end(), ciphertext.begin(), ciphertext.end());

        AppendUint32LE(outCipherPackage, wil::safe_cast<uint32_t>(tag.size()));
        outCipherPackage.insert(outCipherPackage.end(), tag.begin(), tag.end());

        return true;
    }

    bool DecryptVaultV2(
        std::vector<uint8_t> const& cipherPackage,
        std::vector<uint8_t> const& prfSecret,
        std::vector<uint8_t> const& recoveryCodeBytes,
        std::vector<uint8_t>& outPlaintext,
        VaultCryptoError& outError)
    {
        outPlaintext.clear();
        outError = {};

        if (cipherPackage.size() < 5)
        {
            SetError(outError, L"invalid_package", L"too small");
            return false;
        }

        if (!std::equal(std::begin(kVaultV2Magic), std::end(kVaultV2Magic), cipherPackage.begin()))
        {
            SetError(outError, L"not_v2", L"magic mismatch");
            return false;
        }
        if (cipherPackage[4] != kVaultV2Version)
        {
            SetError(outError, L"unsupported_version", L"version mismatch");
            return false;
        }
        if (prfSecret.empty() || recoveryCodeBytes.empty())
        {
            SetError(outError, L"kek_material_missing", L"prfSecret and recoveryCodeBytes are required");
            return false;
        }

        size_t cursor = 5;
        auto readBlob = [&](std::vector<uint8_t>& out) -> bool
        {
            uint32_t len = 0;
            if (!ReadUint32LE(cipherPackage, cursor, len))
            {
                return false;
            }
            cursor += sizeof(uint32_t);
            if (cursor + len > cipherPackage.size())
            {
                return false;
            }
            out.assign(cipherPackage.begin() + cursor, cipherPackage.begin() + cursor + len);
            cursor += len;
            return true;
        };

        std::vector<uint8_t> hkdfSalt;
        std::vector<uint8_t> wrapNonce;
        std::vector<uint8_t> wrappedDekCipher;
        std::vector<uint8_t> wrappedDekTag;
        std::vector<uint8_t> vaultNonce;
        std::vector<uint8_t> vaultCipher;
        std::vector<uint8_t> vaultTag;

        if (!readBlob(hkdfSalt) || !readBlob(wrapNonce) || !readBlob(wrappedDekCipher) || !readBlob(wrappedDekTag) || !readBlob(vaultNonce) || !readBlob(vaultCipher) || !readBlob(vaultTag))
        {
            SetError(outError, L"invalid_package", L"field parse failed");
            return false;
        }

        if (hkdfSalt.size() != kHkdfSaltBytes || wrapNonce.size() != kWrapNonceBytes || wrappedDekTag.size() != kAesGcmTagBytes || vaultNonce.size() != kAesGcmNonceBytes || vaultTag.size() != kAesGcmTagBytes)
        {
            SetError(outError, L"invalid_package", L"field size invalid");
            return false;
        }

        std::vector<uint8_t> kek;
        if (!BuildKek(prfSecret, recoveryCodeBytes, hkdfSalt, kek))
        {
            SetError(outError, L"kdf_failed", L"HKDF-SHA256 failed");
            return false;
        }

        std::vector<uint8_t> aad;
        std::vector<uint8_t> dek;
        if (!Aes256GcmDecrypt(kek, wrapNonce, aad, wrappedDekCipher, wrappedDekTag, dek))
        {
            SetError(outError, L"unwrap_failed", L"DEK unwrap failed");
            return false;
        }
        if (dek.size() != kDekBytes)
        {
            SetError(outError, L"unwrap_failed", L"DEK length mismatch");
            return false;
        }

        if (!Aes256GcmDecrypt(dek, vaultNonce, aad, vaultCipher, vaultTag, outPlaintext))
        {
            SetError(outError, L"decrypt_failed", L"Vault decrypt failed");
            return false;
        }

        return true;
    }
}
