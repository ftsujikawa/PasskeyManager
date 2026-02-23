#pragma once

#include "pch.h"

#include <vector>

namespace tsupasswd
{
    struct SyncHistoryEntry
    {
        std::wstring Timestamp{};
        std::wstring Operation{};
        std::wstring Result{};
        int32_t StatusCode{ 0 };
        std::wstring ErrorCode{};
        std::wstring ErrorMessage{};
        int64_t ServerVersion{ -1 };
        std::wstring RequestId{};
        std::wstring RawLine{};
    };

    class SyncHistoryStore
    {
    public:
        static constexpr size_t kDefaultMaxEntries = 1000;

        static HRESULT Append(SyncHistoryEntry const& entry, size_t maxEntries = kDefaultMaxEntries);
        static std::vector<SyncHistoryEntry> LoadEntries(size_t maxEntries = kDefaultMaxEntries);

        // Backward compatible APIs for existing UI call sites.
        static HRESULT Append(winrt::hstring const& line, size_t maxEntries = kDefaultMaxEntries);
        static std::vector<winrt::hstring> Load(size_t maxEntries = kDefaultMaxEntries);
        static HRESULT Clear();

    private:
        static std::wstring ResolveHistoryFilePath();
    };
}
