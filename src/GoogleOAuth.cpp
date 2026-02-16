#include "pch.h"
#include "GoogleOAuth.h"

#include "Config.h"

#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <fstream>
#include <sstream>
#include <iomanip>
#include <random>
#include <future>
#include <array>

#include <winrt/Windows.Data.Json.h>

#pragma comment(lib, "Winhttp.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Shlwapi.lib")

namespace tsupasswd
{
    namespace
    {
        std::wstring g_lastGoogleOAuthDebugInfo;

        constexpr wchar_t kLoopbackPath[] = L"/oauth2/callback";
        constexpr wchar_t kGoogleAuthHost[] = L"accounts.google.com";
        constexpr wchar_t kGoogleAuthPath[] = L"/o/oauth2/v2/auth";
        constexpr wchar_t kGoogleTokenHost[] = L"oauth2.googleapis.com";
        constexpr wchar_t kGoogleTokenPath[] = L"/token";

        std::wstring UrlEncode(std::wstring const& s)
        {
            // Encode as UTF-8 then percent-encode.
            std::string utf8 = winrt::to_string(s);
            std::ostringstream oss;
            oss << std::uppercase << std::hex;
            for (unsigned char c : utf8)
            {
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~')
                {
                    oss << static_cast<char>(c);
                }
                else
                {
                    oss << '%' << std::setw(2) << std::setfill('0') << static_cast<int>(c);
                }
            }
            return winrt::to_hstring(oss.str()).c_str();
        }

        std::wstring Base64UrlEncode(std::vector<uint8_t> const& bytes)
        {
            DWORD cch = 0;
            if (!CryptBinaryToStringW(bytes.data(), static_cast<DWORD>(bytes.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &cch))
            {
                THROW_LAST_ERROR();
            }

            std::wstring b64;
            b64.resize(cch);
            if (!CryptBinaryToStringW(bytes.data(), static_cast<DWORD>(bytes.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64.data(), &cch))
            {
                THROW_LAST_ERROR();
            }
            if (!b64.empty() && b64.back() == L'\0')
            {
                b64.pop_back();
            }

            // base64url
            for (auto& ch : b64)
            {
                if (ch == L'+') ch = L'-';
                else if (ch == L'/') ch = L'_';
            }
            while (!b64.empty() && b64.back() == L'=')
            {
                b64.pop_back();
            }
            return b64;
        }

        std::wstring RandomUrlSafeString(size_t byteLen)
        {
            std::vector<uint8_t> buf(byteLen);
            NTSTATUS st = BCryptGenRandom(nullptr, buf.data(), static_cast<ULONG>(buf.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            THROW_IF_NTSTATUS_FAILED(st);
            return Base64UrlEncode(buf);
        }

        std::vector<uint8_t> Sha256(std::string const& utf8)
        {
            BCRYPT_ALG_HANDLE hAlg{};
            THROW_IF_NTSTATUS_FAILED(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0));
            auto closeAlg = wil::scope_exit([&] { BCryptCloseAlgorithmProvider(hAlg, 0); });

            DWORD cbHashObject = 0;
            DWORD cbData = 0;
            THROW_IF_NTSTATUS_FAILED(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&cbHashObject), sizeof(cbHashObject), &cbData, 0));

            DWORD cbHash = 0;
            THROW_IF_NTSTATUS_FAILED(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&cbHash), sizeof(cbHash), &cbData, 0));

            std::vector<uint8_t> hashObject(cbHashObject);
            BCRYPT_HASH_HANDLE hHash{};
            THROW_IF_NTSTATUS_FAILED(BCryptCreateHash(hAlg, &hHash, hashObject.data(), cbHashObject, nullptr, 0, 0));
            auto destroyHash = wil::scope_exit([&] { BCryptDestroyHash(hHash); });

            THROW_IF_NTSTATUS_FAILED(BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(utf8.data())), static_cast<ULONG>(utf8.size()), 0));

            std::vector<uint8_t> hash(cbHash);
            THROW_IF_NTSTATUS_FAILED(BCryptFinishHash(hHash, hash.data(), cbHash, 0));
            return hash;
        }

        std::wstring BuildRedirectUri(int32_t port)
        {
            std::wostringstream oss;
            oss << L"http://127.0.0.1:" << port << kLoopbackPath;
            return oss.str();
        }

        std::wstring JoinScopes(std::vector<std::wstring> const& scopes)
        {
            std::wstring out;
            for (size_t i = 0; i < scopes.size(); ++i)
            {
                if (i) out += L" ";
                out += scopes[i];
            }
            return out;
        }

        void OpenBrowser(std::wstring const& url)
        {
            HINSTANCE h = ShellExecuteW(nullptr, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            if (reinterpret_cast<INT_PTR>(h) <= 32)
            {
                THROW_HR(E_FAIL);
            }
        }

        struct LoopbackResult
        {
            std::wstring Code;
            std::wstring State;
            std::wstring Error;
        };

        std::wstring Utf8ToWide(std::string const& s)
        {
            int cch = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
            if (cch <= 0) return L"";
            std::wstring w;
            w.resize(cch);
            MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), cch);
            return w;
        }

        std::string WideToUtf8(std::wstring const& w)
        {
            return winrt::to_string(w);
        }

        // Very small HTTP server for GET /oauth2/callback?code=...&state=...
        LoopbackResult WaitForLoopbackRedirect(int32_t port)
        {
            WSADATA wsa{};
            if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            {
                THROW_LAST_ERROR();
            }
            auto wsaCleanup = wil::scope_exit([&] { WSACleanup(); });

            wil::unique_socket listenSock;
            {
                SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s == INVALID_SOCKET)
                {
                    THROW_LAST_ERROR();
                }
                listenSock.reset(s);

                sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                addr.sin_port = htons(static_cast<u_short>(port));

                int opt = 1;
                setsockopt(listenSock.get(), SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

                if (bind(listenSock.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
                {
                    THROW_LAST_ERROR();
                }
                if (listen(listenSock.get(), 1) == SOCKET_ERROR)
                {
                    THROW_LAST_ERROR();
                }
            }

            SOCKET client = accept(listenSock.get(), nullptr, nullptr);
            if (client == INVALID_SOCKET)
            {
                THROW_LAST_ERROR();
            }
            wil::unique_socket clientSock(client);

            char buf[8192]{};
            int n = recv(clientSock.get(), buf, sizeof(buf) - 1, 0);
            if (n <= 0)
            {
                THROW_HR(E_FAIL);
            }
            std::string req(buf, buf + n);

            // Parse first line: GET /path?query HTTP/1.1
            auto lineEnd = req.find("\r\n");
            if (lineEnd == std::string::npos)
            {
                THROW_HR(E_FAIL);
            }
            std::string firstLine = req.substr(0, lineEnd);
            if (firstLine.rfind("GET ", 0) != 0)
            {
                THROW_HR(E_FAIL);
            }
            size_t pathStart = 4;
            size_t pathEnd = firstLine.find(' ', pathStart);
            if (pathEnd == std::string::npos)
            {
                THROW_HR(E_FAIL);
            }
            std::string pathQuery = firstLine.substr(pathStart, pathEnd - pathStart);

            // Must match /oauth2/callback
            if (pathQuery.rfind("/oauth2/callback", 0) != 0)
            {
                // still respond
                const char* resp = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\n\r\nNot Found";
                send(clientSock.get(), resp, static_cast<int>(strlen(resp)), 0);
                THROW_HR(E_FAIL);
            }

            std::string query;
            auto qpos = pathQuery.find('?');
            if (qpos != std::string::npos)
            {
                query = pathQuery.substr(qpos + 1);
            }

            auto getParam = [&](char const* key) -> std::wstring {
                std::string k = std::string(key) + "=";
                size_t start = 0;
                while (start < query.size())
                {
                    size_t amp = query.find('&', start);
                    std::string part = query.substr(start, amp == std::string::npos ? std::string::npos : (amp - start));
                    if (part.rfind(k, 0) == 0)
                    {
                        std::string val = part.substr(k.size());
                        // URL decode (only minimal for + and %xx)
                        std::string out;
                        out.reserve(val.size());
                        for (size_t i = 0; i < val.size(); ++i)
                        {
                            char c = val[i];
                            if (c == '+')
                            {
                                out.push_back(' ');
                            }
                            else if (c == '%' && i + 2 < val.size())
                            {
                                auto hex = val.substr(i + 1, 2);
                                char* endp = nullptr;
                                int v = static_cast<int>(strtol(hex.c_str(), &endp, 16));
                                if (endp && *endp == 0)
                                {
                                    out.push_back(static_cast<char>(v));
                                    i += 2;
                                }
                                else
                                {
                                    out.push_back(c);
                                }
                            }
                            else
                            {
                                out.push_back(c);
                            }
                        }
                        return Utf8ToWide(out);
                    }
                    if (amp == std::string::npos) break;
                    start = amp + 1;
                }
                return L"";
            };

            LoopbackResult result{};
            result.Code = getParam("code");
            result.State = getParam("state");
            result.Error = getParam("error");

            std::string body = "You can close this window.";
            std::ostringstream oss;
            oss << "HTTP/1.1 200 OK\r\n"
                << "Content-Type: text/plain\r\n"
                << "Content-Length: " << body.size() << "\r\n\r\n"
                << body;
            std::string resp = oss.str();
            send(clientSock.get(), resp.data(), static_cast<int>(resp.size()), 0);

            return result;
        }

        std::string WinHttpReadAll(HINTERNET hRequest)
        {
            std::string out;
            DWORD size = 0;
            while (WinHttpQueryDataAvailable(hRequest, &size) && size > 0)
            {
                std::string chunk;
                chunk.resize(size);
                DWORD read = 0;
                if (!WinHttpReadData(hRequest, chunk.data(), size, &read))
                {
                    THROW_LAST_ERROR();
                }
                chunk.resize(read);
                out += chunk;
                size = 0;
            }
            return out;
        }

        std::string HttpPostFormUrlEncoded(std::wstring const& host, std::wstring const& path, std::wstring const& body)
        {
            std::string bodyUtf8 = winrt::to_string(body);
            HINTERNET hSession = WinHttpOpen(L"PasskeyManager/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            if (!hSession)
            {
                THROW_LAST_ERROR();
            }
            auto closeSession = wil::scope_exit([&] { WinHttpCloseHandle(hSession); });

            HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
            if (!hConnect)
            {
                THROW_LAST_ERROR();
            }
            auto closeConnect = wil::scope_exit([&] { WinHttpCloseHandle(hConnect); });

            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
            if (!hRequest)
            {
                THROW_LAST_ERROR();
            }
            auto closeRequest = wil::scope_exit([&] { WinHttpCloseHandle(hRequest); });

            std::wstring headers = L"Content-Type: application/x-www-form-urlencoded";
            BOOL ok = WinHttpSendRequest(
                hRequest,
                headers.c_str(),
                static_cast<DWORD>(headers.size()),
                (LPVOID)bodyUtf8.data(),
                static_cast<DWORD>(bodyUtf8.size()),
                static_cast<DWORD>(bodyUtf8.size()),
                0);
            if (!ok)
            {
                THROW_LAST_ERROR();
            }

            ok = WinHttpReceiveResponse(hRequest, nullptr);
            if (!ok)
            {
                THROW_LAST_ERROR();
            }

            return WinHttpReadAll(hRequest);
        }

        OAuthTokenResponse ParseTokenResponseJson(std::string const& jsonUtf8)
        {
            OAuthTokenResponse out{};
            std::wstring jsonW = winrt::to_hstring(jsonUtf8).c_str();
            auto root = winrt::Windows::Data::Json::JsonObject::Parse(jsonW);

            auto getString = [&](wchar_t const* k) -> std::wstring {
                if (!root.HasKey(k)) return L"";
                auto v = root.GetNamedValue(k, nullptr);
                if (!v || v.ValueType() != winrt::Windows::Data::Json::JsonValueType::String) return L"";
                return v.GetString().c_str();
            };
            auto getInt = [&](wchar_t const* k) -> int32_t {
                if (!root.HasKey(k)) return 0;
                auto v = root.GetNamedValue(k, nullptr);
                if (!v || v.ValueType() != winrt::Windows::Data::Json::JsonValueType::Number) return 0;
                return static_cast<int32_t>(v.GetNumber());
            };

            out.AccessToken = getString(L"access_token");
            out.RefreshToken = getString(L"refresh_token");
            out.TokenType = getString(L"token_type");
            out.Scope = getString(L"scope");
            out.ExpiresInSeconds = getInt(L"expires_in");
            out.Error = getString(L"error");
            out.ErrorDescription = getString(L"error_description");
            return out;
        }

        std::wstring GetTokensFilePath()
        {
            std::wstring dir = GetConfigDirectoryPath();
            if (dir.empty())
            {
                return L"";
            }
            if (dir.back() != L'\\')
            {
                dir.push_back(L'\\');
            }
            return dir + L"google_refresh_token.bin";
        }

        void EnsureDirectoryExistsForFilePath(std::wstring const& filePath)
        {
            if (filePath.empty())
            {
                return;
            }
            std::wstring dir = filePath;
            auto pos = dir.find_last_of(L"\\/");
            if (pos == std::wstring::npos)
            {
                return;
            }
            dir.resize(pos);

            // Creates intermediate directories as needed.
            (void)SHCreateDirectoryExW(nullptr, dir.c_str(), nullptr);
        }

        std::wstring TryGetGoogleClientIdFromJsonFile(std::wstring const& filePath)
        {
            if (filePath.empty() || !PathFileExistsW(filePath.c_str()))
            {
                return L"";
            }

            std::ifstream ifs(filePath, std::ios::binary);
            if (!ifs)
            {
                return L"";
            }

            std::ostringstream oss;
            oss << ifs.rdbuf();
            std::string json = oss.str();
            if (json.size() >= 3 &&
                static_cast<unsigned char>(json[0]) == 0xEF &&
                static_cast<unsigned char>(json[1]) == 0xBB &&
                static_cast<unsigned char>(json[2]) == 0xBF)
            {
                json.erase(0, 3);
            }
            if (json.empty())
            {
                return L"";
            }

            try
            {
                std::wstring jsonW = winrt::to_hstring(json).c_str();
                auto root = winrt::Windows::Data::Json::JsonObject::Parse(jsonW);
                if (!root.HasKey(L"google"))
                {
                    return L"";
                }

                auto g = root.GetNamedObject(L"google", nullptr);
                if (!g || !g.HasKey(L"client_id"))
                {
                    return L"";
                }

                auto cid = g.GetNamedValue(L"client_id", nullptr);
                if (!cid || cid.ValueType() != winrt::Windows::Data::Json::JsonValueType::String)
                {
                    return L"";
                }

                return std::wstring(cid.GetString().c_str());
            }
            catch (...)
            {
                return L"";
            }
        }

        std::wstring TryResolveGoogleClientIdFallback()
        {
            std::array<std::wstring, 12> candidates{};

            wchar_t cwd[MAX_PATH]{};
            DWORD cwdLen = GetCurrentDirectoryW(ARRAYSIZE(cwd), cwd);
            std::wstring cwdDir = (cwdLen != 0 && cwdLen < ARRAYSIZE(cwd)) ? std::wstring(cwd, cwdLen) : L"";

            wchar_t mod[MAX_PATH]{};
            DWORD modLen = GetModuleFileNameW(nullptr, mod, ARRAYSIZE(mod));
            std::wstring modDir;
            if (modLen != 0 && modLen < ARRAYSIZE(mod))
            {
                modDir.assign(mod, modLen);
                auto pos = modDir.find_last_of(L"\\/");
                if (pos != std::wstring::npos)
                {
                    modDir.resize(pos);
                }
            }

            wil::unique_cotaskmem_string localAppData;
            std::wstring localConfig;
            if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &localAppData)) && localAppData)
            {
                localConfig = std::wstring(localAppData.get()) + L"\\tsupasswd\\config.json";
            }

            auto join = [](std::wstring const& dir, std::wstring const& name) {
                if (dir.empty()) return std::wstring{};
                if (dir.back() == L'\\' || dir.back() == L'/') return dir + name;
                return dir + L"\\" + name;
            };

            candidates[0] = join(cwdDir, L"appsettings.local.json");
            candidates[1] = join(cwdDir, L"appsetting.local.json");
            candidates[2] = join(cwdDir, L"appsettings.json");
            candidates[3] = join(cwdDir, L"appsetting.json");
            candidates[4] = join(modDir, L"appsettings.local.json");
            candidates[5] = join(modDir, L"appsetting.local.json");
            candidates[6] = join(modDir, L"appsettings.json");
            candidates[7] = join(modDir, L"appsetting.json");
            candidates[8] = join(modDir + L"\\..", L"appsettings.local.json");
            candidates[9] = join(modDir + L"\\..", L"appsetting.local.json");
            candidates[10] = join(modDir + L"\\..", L"appsettings.json");
            candidates[11] = localConfig;

            for (auto const& p : candidates)
            {
                std::wstring cid = TryGetGoogleClientIdFromJsonFile(p);
                if (!cid.empty())
                {
                    return cid;
                }
            }
            return L"";
        }
    }

    bool TrySaveGoogleRefreshToken(std::wstring const& refreshToken)
    {
        if (refreshToken.empty())
        {
            return false;
        }

        std::wstring path = GetTokensFilePath();
        if (path.empty())
        {
            return false;
        }

        std::vector<uint8_t> plain(refreshToken.size() * sizeof(wchar_t));
        memcpy(plain.data(), refreshToken.data(), plain.size());

        DATA_BLOB in{};
        in.cbData = static_cast<DWORD>(plain.size());
        in.pbData = plain.data();

        DATA_BLOB out{};
        if (!CryptProtectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
        {
            return false;
        }
        auto cleanup = wil::scope_exit([&] {
            if (out.pbData)
            {
                LocalFree(out.pbData);
            }
        });

        // ensure directory exists
        EnsureDirectoryExistsForFilePath(path);

        wil::unique_handle h(CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!h)
        {
            return false;
        }

        DWORD written = 0;
        if (!WriteFile(h.get(), out.pbData, out.cbData, &written, nullptr) || written != out.cbData)
        {
            return false;
        }
        return true;
    }

    bool TryLoadGoogleRefreshToken(std::wstring& refreshToken)
    {
        refreshToken.clear();

        std::wstring path = GetTokensFilePath();
        if (path.empty() || !PathFileExistsW(path.c_str()))
        {
            return false;
        }

        wil::unique_handle h(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!h)
        {
            return false;
        }

        LARGE_INTEGER size{};
        if (!GetFileSizeEx(h.get(), &size) || size.QuadPart <= 0 || size.QuadPart > (1024 * 1024))
        {
            return false;
        }

        std::vector<uint8_t> cipher(static_cast<size_t>(size.QuadPart));
        DWORD read = 0;
        if (!ReadFile(h.get(), cipher.data(), static_cast<DWORD>(cipher.size()), &read, nullptr) || read != cipher.size())
        {
            return false;
        }

        DATA_BLOB in{};
        in.cbData = static_cast<DWORD>(cipher.size());
        in.pbData = cipher.data();

        DATA_BLOB out{};
        if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
        {
            return false;
        }
        auto cleanup = wil::scope_exit([&] {
            if (out.pbData)
            {
                LocalFree(out.pbData);
            }
        });

        if (out.cbData % sizeof(wchar_t) != 0)
        {
            return false;
        }

        refreshToken.assign(reinterpret_cast<wchar_t*>(out.pbData), out.cbData / sizeof(wchar_t));
        return !refreshToken.empty();
    }

    std::wstring GetLastGoogleOAuthDebugInfo()
    {
        return g_lastGoogleOAuthDebugInfo;
    }

    OAuthTokenResponse PerformGoogleOAuthLoopback()
    {
        winrt::init_apartment(winrt::apartment_type::multi_threaded);
        g_lastGoogleOAuthDebugInfo.clear();

        AppConfig cfg = LoadConfig();
        if (cfg.Google.ClientId.empty())
        {
            cfg.Google.ClientId = TryResolveGoogleClientIdFallback();
            if (cfg.Google.ClientId.empty())
            {
                THROW_HR(E_INVALIDARG);
            }
        }
        int32_t loopbackPort = cfg.Google.LoopbackRedirectPort > 0 ? cfg.Google.LoopbackRedirectPort : 53682;

        std::wstring state = RandomUrlSafeString(16);
        std::wstring codeVerifier = RandomUrlSafeString(64);
        std::vector<uint8_t> digest = Sha256(WideToUtf8(codeVerifier));
        std::wstring codeChallenge = Base64UrlEncode(digest);

        std::wstring redirectUri = BuildRedirectUri(loopbackPort);
        std::wstring scope = JoinScopes(cfg.Google.Scopes);

        std::wstring authUrl = std::wstring(L"https://") + kGoogleAuthHost + kGoogleAuthPath +
            L"?response_type=code" +
            L"&client_id=" + UrlEncode(cfg.Google.ClientId) +
            L"&redirect_uri=" + UrlEncode(redirectUri) +
            L"&scope=" + UrlEncode(scope) +
            L"&state=" + UrlEncode(state) +
            L"&code_challenge=" + UrlEncode(codeChallenge) +
            L"&code_challenge_method=S256" +
            L"&access_type=offline" +
            L"&prompt=consent";

        // Start listening first to avoid race.
        std::future<LoopbackResult> listener = std::async(std::launch::async, [port = loopbackPort] {
            return WaitForLoopbackRedirect(port);
        });

        OpenBrowser(authUrl);

        LoopbackResult lr = listener.get();
        if (!lr.Error.empty())
        {
            // Example: access_denied when user cancels consent.
            THROW_HR(HRESULT_FROM_WIN32(ERROR_CANCELLED));
        }
        if (lr.State != state)
        {
            THROW_HR(HRESULT_FROM_WIN32(ERROR_INVALID_DATA));
        }
        if (lr.Code.empty())
        {
            THROW_HR(HRESULT_FROM_WIN32(ERROR_NOT_FOUND));
        }

        // Exchange code for tokens.
        std::wstring body =
            L"code=" + UrlEncode(lr.Code) +
            L"&client_id=" + UrlEncode(cfg.Google.ClientId) +
            L"&redirect_uri=" + UrlEncode(redirectUri) +
            L"&grant_type=authorization_code" +
            L"&code_verifier=" + UrlEncode(codeVerifier);
        if (!cfg.Google.ClientSecret.empty())
        {
            body += L"&client_secret=" + UrlEncode(cfg.Google.ClientSecret);
        }

        std::string resp = HttpPostFormUrlEncoded(kGoogleTokenHost, kGoogleTokenPath, body);
        OAuthTokenResponse tokens = ParseTokenResponseJson(resp);
        if (!tokens.Error.empty())
        {
            std::wstring msg = L"Google OAuth token error: error='" + tokens.Error +
                L"' description='" + tokens.ErrorDescription + L"'";
            OutputDebugStringW(msg.c_str());
            OutputDebugStringW(L"\n");
            g_lastGoogleOAuthDebugInfo = msg;

            std::wstring raw = std::wstring(L"Google OAuth token response: ") + winrt::to_hstring(resp).c_str();
            OutputDebugStringW(raw.c_str());
            OutputDebugStringW(L"\n");
            g_lastGoogleOAuthDebugInfo += L" | " + raw;
            THROW_HR(HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER));
        }

        if (tokens.RefreshToken.empty())
        {
            // Google may omit refresh_token on subsequent consents.
            // If we already have one persisted, continue with existing token.
            std::wstring existingRefreshToken;
            if (TryLoadGoogleRefreshToken(existingRefreshToken))
            {
                tokens.RefreshToken = existingRefreshToken;
                return tokens;
            }

            // Initial provisioning still requires refresh_token.
            std::wstring raw = std::wstring(L"Google OAuth token response (no refresh_token): ") + winrt::to_hstring(resp).c_str();
            OutputDebugStringW(raw.c_str());
            OutputDebugStringW(L"\n");
            if (!g_lastGoogleOAuthDebugInfo.empty())
            {
                g_lastGoogleOAuthDebugInfo += L" | ";
            }
            g_lastGoogleOAuthDebugInfo += raw;
            THROW_HR(HRESULT_FROM_WIN32(ERROR_NO_TOKEN));
        }

        (void)TrySaveGoogleRefreshToken(tokens.RefreshToken);
        return tokens;
    }
}
