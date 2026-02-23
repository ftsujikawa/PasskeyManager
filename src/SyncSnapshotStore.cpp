#include "pch.h"

#include "SyncSnapshotStore.h"

#include <fstream>

namespace
{
    std::wstring BuildStorePath()
    {
        wil::unique_cotaskmem_string localAppData;
        THROW_IF_FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &localAppData));

        std::wstring root = localAppData.get();
        if (!root.empty() && root.back() != L'\\')
        {
            root.push_back(L'\\');
        }
        root += L"PasskeyManager";

        auto createResult = CreateDirectoryW(root.c_str(), nullptr);
        if (!createResult)
        {
            auto error = GetLastError();
            if (error != ERROR_ALREADY_EXISTS)
            {
                THROW_HR(HRESULT_FROM_WIN32(error));
            }
        }

        root += L"\\sync_snapshots.log";
        return root;
    }

    std::string Base64UrlEncode(std::vector<BYTE> const& data)
    {
        if (data.empty())
        {
            return {};
        }

        DWORD requiredSize = 0;
        if (!CryptBinaryToStringA(
            data.data(),
            static_cast<DWORD>(data.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            nullptr,
            &requiredSize))
        {
            return {};
        }

        std::string encoded(requiredSize, '\0');
        if (!CryptBinaryToStringA(
            data.data(),
            static_cast<DWORD>(data.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            encoded.data(),
            &requiredSize))
        {
            return {};
        }

        if (!encoded.empty() && encoded.back() == '\0')
        {
            encoded.pop_back();
        }

        std::replace(encoded.begin(), encoded.end(), '+', '-');
        std::replace(encoded.begin(), encoded.end(), '/', '_');
        while (!encoded.empty() && encoded.back() == '=')
        {
            encoded.pop_back();
        }

        return encoded;
    }

    bool Base64UrlDecode(std::string encoded, std::vector<BYTE>& outBytes)
    {
        outBytes.clear();
        if (encoded.empty())
        {
            return false;
        }

        std::replace(encoded.begin(), encoded.end(), '-', '+');
        std::replace(encoded.begin(), encoded.end(), '_', '/');
        while ((encoded.size() % 4) != 0)
        {
            encoded.push_back('=');
        }

        DWORD required = 0;
        if (!CryptStringToBinaryA(
            encoded.c_str(),
            static_cast<DWORD>(encoded.size()),
            CRYPT_STRING_BASE64,
            nullptr,
            &required,
            nullptr,
            nullptr))
        {
            return false;
        }

        outBytes.resize(required);
        if (!CryptStringToBinaryA(
            encoded.c_str(),
            static_cast<DWORD>(encoded.size()),
            CRYPT_STRING_BASE64,
            outBytes.data(),
            &required,
            nullptr,
            nullptr))
        {
            outBytes.clear();
            return false;
        }

        outBytes.resize(required);
        return !outBytes.empty();
    }

    std::wstring SanitizeField(std::wstring value)
    {
        std::replace(value.begin(), value.end(), L'\t', L' ');
        std::replace(value.begin(), value.end(), L'\r', L' ');
        std::replace(value.begin(), value.end(), L'\n', L' ');
        return value;
    }

    std::wstring BuildLine(tsupasswd::SyncSnapshotRecord const& record)
    {
        std::wstring line = SanitizeField(record.SnapshotId) +
            L"\t" +
            SanitizeField(record.CapturedAt) +
            L"\t" +
            SanitizeField(record.UserId) +
            L"\t" +
            std::to_wstring(record.ServerVersion) +
            L"\t" +
            SanitizeField(record.Source) +
            L"\t" +
            winrt::to_hstring(Base64UrlEncode(record.CipherBytes)).c_str();
        return line;
    }

    bool ParseLine(std::wstring const& line, tsupasswd::SyncSnapshotRecord& outRecord)
    {
        std::vector<std::wstring> fields;
        size_t start = 0;
        while (start <= line.size())
        {
            size_t end = line.find(L'\t', start);
            if (end == std::wstring::npos)
            {
                fields.push_back(line.substr(start));
                break;
            }
            fields.push_back(line.substr(start, end - start));
            start = end + 1;
        }

        if (fields.size() != 6)
        {
            return false;
        }

        tsupasswd::SyncSnapshotRecord record{};
        record.SnapshotId = fields[0];
        record.CapturedAt = fields[1];
        record.UserId = fields[2];
        record.ServerVersion = _wtoi64(fields[3].c_str());
        record.Source = fields[4];

        std::vector<BYTE> bytes;
        if (!Base64UrlDecode(winrt::to_string(fields[5]), bytes))
        {
            return false;
        }

        record.CipherBytes = std::move(bytes);
        outRecord = std::move(record);
        return true;
    }
}

namespace tsupasswd
{
    std::wstring SyncSnapshotStore::ResolveStoreFilePath()
    {
        return BuildStorePath();
    }

    HRESULT SyncSnapshotStore::Append(SyncSnapshotRecord const& record, size_t maxEntries)
    {
        try
        {
            auto records = Load(maxEntries);
            records.push_back(record);
            if (records.size() > maxEntries)
            {
                records.erase(records.begin(), records.begin() + static_cast<ptrdiff_t>(records.size() - maxEntries));
            }

            std::ofstream out(ResolveStoreFilePath(), std::ios::binary | std::ios::trunc);
            if (!out.is_open())
            {
                return HRESULT_FROM_WIN32(ERROR_WRITE_FAULT);
            }

            for (auto const& item : records)
            {
                out << winrt::to_string(BuildLine(item)) << "\n";
            }
            return S_OK;
        }
        catch (...)
        {
            return wil::ResultFromCaughtException();
        }
    }

    std::vector<SyncSnapshotRecord> SyncSnapshotStore::Load(size_t maxEntries)
    {
        std::vector<SyncSnapshotRecord> records;
        try
        {
            std::ifstream in(ResolveStoreFilePath(), std::ios::binary);
            if (!in.is_open())
            {
                return records;
            }

            std::string line;
            while (std::getline(in, line))
            {
                if (line.empty())
                {
                    continue;
                }

                SyncSnapshotRecord record{};
                if (ParseLine(winrt::to_hstring(line).c_str(), record))
                {
                    records.push_back(std::move(record));
                }
            }

            if (records.size() > maxEntries)
            {
                records.erase(records.begin(), records.begin() + static_cast<ptrdiff_t>(records.size() - maxEntries));
            }

            return records;
        }
        catch (...)
        {
            return records;
        }
    }

    bool SyncSnapshotStore::TryGetById(std::wstring const& snapshotId, SyncSnapshotRecord& outRecord, size_t maxEntries)
    {
        auto records = Load(maxEntries);
        for (auto it = records.rbegin(); it != records.rend(); ++it)
        {
            if (it->SnapshotId == snapshotId)
            {
                outRecord = *it;
                return true;
            }
        }
        return false;
    }

    HRESULT SyncSnapshotStore::Clear()
    {
        try
        {
            auto deleteResult = DeleteFileW(ResolveStoreFilePath().c_str());
            if (!deleteResult)
            {
                auto error = GetLastError();
                if (error != ERROR_FILE_NOT_FOUND)
                {
                    return HRESULT_FROM_WIN32(error);
                }
            }
            return S_OK;
        }
        catch (...)
        {
            return wil::ResultFromCaughtException();
        }
    }
}
