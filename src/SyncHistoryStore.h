#pragma once

#include "pch.h"

#include <vector>

namespace tsupasswd
{
    class SyncHistoryStore
    {
    public:
        static constexpr size_t kDefaultMaxEntries = 1000;

        static HRESULT Append(winrt::hstring const& line, size_t maxEntries = kDefaultMaxEntries);
        static std::vector<winrt::hstring> Load(size_t maxEntries = kDefaultMaxEntries);
        static HRESULT Clear();

    private:
        static std::wstring ResolveHistoryFilePath();
    };
}
