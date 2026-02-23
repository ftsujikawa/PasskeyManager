#include "pch.h"

#include "SyncHistoryStore.h"

#include <fstream>

namespace
{
    std::wstring BuildHistoryPath()
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

        root += L"\\sync_history.log";
        return root;
    }

    std::string ToUtf8(std::wstring const& value)
    {
        std::wstring line = value;
        std::replace(line.begin(), line.end(), L'\r', L' ');
        std::replace(line.begin(), line.end(), L'\n', L' ');
        return winrt::to_string(line);
    }

    std::wstring SanitizeField(std::wstring value)
    {
        std::replace(value.begin(), value.end(), L'\t', L' ');
        std::replace(value.begin(), value.end(), L'\r', L' ');
        std::replace(value.begin(), value.end(), L'\n', L' ');
        return value;
    }

    std::vector<std::wstring> SplitTabFields(std::wstring const& line)
    {
        std::vector<std::wstring> fields;
        size_t start = 0;
        while (start <= line.size())
        {
            auto end = line.find(L'\t', start);
            if (end == std::wstring::npos)
            {
                fields.push_back(line.substr(start));
                break;
            }
            fields.push_back(line.substr(start, end - start));
            start = end + 1;
        }
        return fields;
    }

    std::wstring ExtractTokenValue(std::wstring const& line, std::wstring const& token)
    {
        auto start = line.find(token);
        if (start == std::wstring::npos)
        {
            return {};
        }

        start += token.size();
        auto end = line.find_first_of(L" .,\n\r\t", start);
        std::wstring value = line.substr(start, end == std::wstring::npos ? std::wstring::npos : end - start);
        while (!value.empty() && (value.back() == L'.' || value.back() == L','))
        {
            value.pop_back();
        }
        return value;
    }

    int32_t ParseInt32(std::wstring const& value, int32_t fallback = 0)
    {
        if (value.empty())
        {
            return fallback;
        }
        return static_cast<int32_t>(_wtoi(value.c_str()));
    }

    int64_t ParseInt64(std::wstring const& value, int64_t fallback = -1)
    {
        if (value.empty())
        {
            return fallback;
        }
        return _wtoi64(value.c_str());
    }

    std::wstring InferResult(std::wstring const& rawLine)
    {
        if (rawLine.rfind(L"SUCCESS:", 0) == 0)
        {
            return L"success";
        }
        if (rawLine.rfind(L"FAILED:", 0) == 0)
        {
            return L"failed";
        }
        if (rawLine.rfind(L"WARNING:", 0) == 0)
        {
            return L"warning";
        }
        if (rawLine.rfind(L"INFO:", 0) == 0)
        {
            return L"info";
        }
        return L"unknown";
    }

    std::wstring InferOperation(std::wstring const& rawLine)
    {
        if (rawLine.find(L"Self-hosted") != std::wstring::npos || rawLine.find(L"sync") != std::wstring::npos)
        {
            return L"sync";
        }
        if (rawLine.find(L"Snapshot") != std::wstring::npos)
        {
            return L"snapshot";
        }
        if (rawLine.find(L"Queue") != std::wstring::npos)
        {
            return L"queue";
        }
        return L"general";
    }

    tsupasswd::SyncHistoryEntry ParseLegacyEntry(std::wstring const& line)
    {
        tsupasswd::SyncHistoryEntry entry{};
        entry.RawLine = line;
        entry.Operation = InferOperation(line);
        entry.Result = InferResult(line);
        entry.StatusCode = ParseInt32(ExtractTokenValue(line, L"status="), 0);
        entry.ErrorCode = ExtractTokenValue(line, L"code=");
        entry.ErrorMessage = ExtractTokenValue(line, L"message=");
        entry.ServerVersion = ParseInt64(ExtractTokenValue(line, L"server_version="), -1);
        entry.RequestId = ExtractTokenValue(line, L"request_id=");
        return entry;
    }

    std::wstring SerializeEntry(tsupasswd::SyncHistoryEntry const& entry)
    {
        return SanitizeField(entry.Timestamp) +
            L"\t" +
            SanitizeField(entry.Operation) +
            L"\t" +
            SanitizeField(entry.Result) +
            L"\t" +
            std::to_wstring(entry.StatusCode) +
            L"\t" +
            SanitizeField(entry.ErrorCode) +
            L"\t" +
            SanitizeField(entry.ErrorMessage) +
            L"\t" +
            std::to_wstring(entry.ServerVersion) +
            L"\t" +
            SanitizeField(entry.RequestId) +
            L"\t" +
            SanitizeField(entry.RawLine);
    }

    bool TryParseEntry(std::wstring const& line, tsupasswd::SyncHistoryEntry& outEntry)
    {
        auto fields = SplitTabFields(line);
        if (fields.size() != 9)
        {
            outEntry = ParseLegacyEntry(line);
            return true;
        }

        tsupasswd::SyncHistoryEntry entry{};
        entry.Timestamp = fields[0];
        entry.Operation = fields[1];
        entry.Result = fields[2];
        entry.StatusCode = ParseInt32(fields[3], 0);
        entry.ErrorCode = fields[4];
        entry.ErrorMessage = fields[5];
        entry.ServerVersion = ParseInt64(fields[6], -1);
        entry.RequestId = fields[7];
        entry.RawLine = fields[8];
        outEntry = std::move(entry);
        return true;
    }

    tsupasswd::SyncHistoryEntry BuildEntryFromRawLine(winrt::hstring const& line)
    {
        auto entry = ParseLegacyEntry(line.c_str());
        std::time_t now = std::time(nullptr);
        std::tm tmLocal{};
        localtime_s(&tmLocal, &now);
        wchar_t timestamp[32]{};
        wcsftime(timestamp, ARRAYSIZE(timestamp), L"%Y-%m-%d %H:%M:%S", &tmLocal);
        entry.Timestamp = timestamp;
        return entry;
    }
}

namespace tsupasswd
{
    std::wstring SyncHistoryStore::ResolveHistoryFilePath()
    {
        return BuildHistoryPath();
    }

    HRESULT SyncHistoryStore::Append(SyncHistoryEntry const& entry, size_t maxEntries)
    {
        try
        {
            auto path = ResolveHistoryFilePath();
            auto entries = LoadEntries(maxEntries);
            entries.push_back(entry);

            if (entries.size() > maxEntries)
            {
                entries.erase(entries.begin(), entries.begin() + static_cast<ptrdiff_t>(entries.size() - maxEntries));
            }

            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            if (!out.is_open())
            {
                return HRESULT_FROM_WIN32(ERROR_WRITE_FAULT);
            }

            for (auto const& storedEntry : entries)
            {
                out << ToUtf8(SerializeEntry(storedEntry)) << "\n";
            }

            return S_OK;
        }
        catch (...)
        {
            return wil::ResultFromCaughtException();
        }
    }

    std::vector<SyncHistoryEntry> SyncHistoryStore::LoadEntries(size_t maxEntries)
    {
        std::vector<SyncHistoryEntry> entries;

        try
        {
            auto path = ResolveHistoryFilePath();
            std::ifstream in(path, std::ios::binary);
            if (!in.is_open())
            {
                return entries;
            }

            std::string line;
            while (std::getline(in, line))
            {
                if (line.empty())
                {
                    continue;
                }

                SyncHistoryEntry entry{};
                if (TryParseEntry(winrt::to_hstring(line).c_str(), entry))
                {
                    entries.push_back(std::move(entry));
                }
            }

            if (entries.size() > maxEntries)
            {
                entries.erase(entries.begin(), entries.begin() + static_cast<ptrdiff_t>(entries.size() - maxEntries));
            }

            return entries;
        }
        catch (...)
        {
            return entries;
        }
    }

    HRESULT SyncHistoryStore::Append(winrt::hstring const& line, size_t maxEntries)
    {
        return Append(BuildEntryFromRawLine(line), maxEntries);
    }

    std::vector<winrt::hstring> SyncHistoryStore::Load(size_t maxEntries)
    {
        std::vector<winrt::hstring> lines;
        auto entries = LoadEntries(maxEntries);
        lines.reserve(entries.size());
        for (auto const& entry : entries)
        {
            if (!entry.RawLine.empty())
            {
                lines.push_back(winrt::hstring{ entry.RawLine });
            }
        }
        return lines;
    }

    HRESULT SyncHistoryStore::Clear()
    {
        try
        {
            auto path = ResolveHistoryFilePath();

            auto deleteResult = DeleteFileW(path.c_str());
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
