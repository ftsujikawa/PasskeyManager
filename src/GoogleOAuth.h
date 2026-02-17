#pragma once

#include <string>
#include <vector>

namespace tsupasswd
{
    struct OAuthTokenResponse
    {
        std::wstring AccessToken{};
        std::wstring RefreshToken{};
        int32_t ExpiresInSeconds{ 0 };
        std::wstring TokenType{};
        std::wstring Scope{};
        std::wstring Error{};
        std::wstring ErrorDescription{};
    };

    // Starts a loopback OAuth flow (PKCE) using the system browser.
    // On success, returns a token response including refresh_token (when Google returns it).
    // Throws on failure.
    OAuthTokenResponse PerformGoogleOAuthLoopback();

    // DPAPI persist/restore refresh token.
    bool TrySaveGoogleRefreshToken(std::wstring const& refreshToken);
    bool TryLoadGoogleRefreshToken(std::wstring& refreshToken);
    bool TryDeleteGoogleRefreshToken();
    std::wstring GetGoogleRefreshTokenStoragePath();

    // Last diagnostics for OAuth flow (token endpoint error/response summary).
    std::wstring GetLastGoogleOAuthDebugInfo();
}
