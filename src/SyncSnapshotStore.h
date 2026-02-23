#pragma once

#include "pch.h"

#include <vector>

namespace tsupasswd
{
    struct SyncSnapshotRecord
    {
        std::wstring SnapshotId{};
        std::wstring CapturedAt{};
        std::wstring UserId{};
        int64_t ServerVersion{ -1 };
        std::wstring Source{};
        std::vector<BYTE> CipherBytes{};
    };

    class SyncSnapshotStore
    {
    public:
        static constexpr size_t kDefaultMaxEntries = 50;

        static HRESULT Append(SyncSnapshotRecord const& record, size_t maxEntries = kDefaultMaxEntries);
        static std::vector<SyncSnapshotRecord> Load(size_t maxEntries = kDefaultMaxEntries);
        static bool TryGetById(std::wstring const& snapshotId, SyncSnapshotRecord& outRecord, size_t maxEntries = kDefaultMaxEntries);
        static HRESULT Clear();

    private:
        static std::wstring ResolveStoreFilePath();
    };
}
