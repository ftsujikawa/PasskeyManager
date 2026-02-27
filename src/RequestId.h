#pragma once

#include <string>

namespace tsupasswd
{
    inline std::wstring BuildRequestId(std::wstring const& operation)
    {
        SYSTEMTIME st{};
        GetSystemTime(&st);

        wchar_t timestamp[40]{};
        swprintf_s(
            timestamp,
            L"%04u%02u%02uT%02u%02u%02u%03uZ",
            st.wYear,
            st.wMonth,
            st.wDay,
            st.wHour,
            st.wMinute,
            st.wSecond,
            st.wMilliseconds);

        return std::wstring{ timestamp } + L"-" + operation;
    }
}
