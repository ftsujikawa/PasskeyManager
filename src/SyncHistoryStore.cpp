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

    std::string ToUtf8(winrt::hstring const& value)
    {
        std::wstring line = value.c_str();
        std::replace(line.begin(), line.end(), L'\r', L' ');
        std::replace(line.begin(), line.end(), L'\n', L' ');
        return winrt::to_string(line);
    }
}

namespace tsupasswd
{
    std::wstring SyncHistoryStore::ResolveHistoryFilePath()
    {
        return BuildHistoryPath();
    }

    HRESULT SyncHistoryStore::Append(winrt::hstring const& line, size_t maxEntries)
    {
        try
        {
            auto path = ResolveHistoryFilePath();
            auto entries = Load(maxEntries);
            entries.push_back(line);

            if (entries.size() > maxEntries)
            {
                entries.erase(entries.begin(), entries.begin() + static_cast<ptrdiff_t>(entries.size() - maxEntries));
            }

            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            if (!out.is_open())
            {
                return HRESULT_FROM_WIN32(ERROR_WRITE_FAULT);
            }

            for (auto const& entry : entries)
            {
                out << ToUtf8(entry) << "\n";
            }

            return S_OK;
        }
        catch (...)
        {
            return wil::ResultFromCaughtException();
        }
    }

    std::vector<winrt::hstring> SyncHistoryStore::Load(size_t maxEntries)
    {
        std::vector<winrt::hstring> entries;

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
                entries.push_back(winrt::to_hstring(line));
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
