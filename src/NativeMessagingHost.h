#pragma once

#include <string>

namespace tsupasswd
{
    bool IsNativeMessagingHostMode(std::wstring const& args);
    int RunNativeMessagingHost(std::wstring const& args);
}
