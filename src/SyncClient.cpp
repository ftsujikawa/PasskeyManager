#include "pch.h"
#include "SyncClient.h"

#include <wincrypt.h>
#include <winhttp.h>
#include <winrt/Windows.Data.Json.h>

#include "tsupasswd_opaque_raii.hpp"

#pragma comment(lib, "Winhttp.lib")

#pragma comment(lib, "Crypt32.lib")

namespace tsupasswd
{
    namespace
    {
        class WinHttpHandle
        {
        public:
            WinHttpHandle() noexcept = default;
            explicit WinHttpHandle(HINTERNET handle) noexcept :
                m_handle(handle)
            {
            }

            ~WinHttpHandle() noexcept
            {
                reset();
            }

            WinHttpHandle(WinHttpHandle const&) = delete;
            WinHttpHandle& operator=(WinHttpHandle const&) = delete;

            WinHttpHandle(WinHttpHandle&& other) noexcept :
                m_handle(other.m_handle)
            {
                other.m_handle = nullptr;
            }

            WinHttpHandle& operator=(WinHttpHandle&& other) noexcept
            {
                if (this != &other)
                {
                    reset();
                    m_handle = other.m_handle;
                    other.m_handle = nullptr;
                }
                return *this;
            }

            HINTERNET get() const noexcept
            {
                return m_handle;
            }

            void reset(HINTERNET handle = nullptr) noexcept
            {
                if (m_handle)
                {
                    WinHttpCloseHandle(m_handle);
                }
                m_handle = handle;
            }

        private:
            HINTERNET m_handle{ nullptr };
        };

        std::wstring Base64StdEncode(uint8_t const* bytes, size_t len)
        {
            if (!bytes || len == 0)
            {
                return L"";
            }

            DWORD outChars = 0;
            if (!CryptBinaryToStringW(bytes, static_cast<DWORD>(len), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &outChars))
            {
                return L"";
            }

            std::wstring out;
            out.resize(outChars);
            if (!CryptBinaryToStringW(bytes, static_cast<DWORD>(len), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out.data(), &outChars))
            {
                return L"";
            }

            while (!out.empty() && out.back() == L'\0')
            {
                out.pop_back();
            }
            return out;
        }

        bool Base64StdDecode(std::wstring const& b64, std::vector<uint8_t>& out)
        {
            out.clear();
            if (b64.empty())
            {
                return false;
            }

            DWORD outBytes = 0;
            if (!CryptStringToBinaryW(b64.c_str(), static_cast<DWORD>(b64.size()), CRYPT_STRING_BASE64, nullptr, &outBytes, nullptr, nullptr))
            {
                return false;
            }

            out.resize(outBytes);
            if (!CryptStringToBinaryW(b64.c_str(), static_cast<DWORD>(b64.size()), CRYPT_STRING_BASE64, out.data(), &outBytes, nullptr, nullptr))
            {
                out.clear();
                return false;
            }
            out.resize(outBytes);
            return true;
        }

        std::wstring GetNamedStringOrEmpty(winrt::Windows::Data::Json::JsonObject const& obj, wchar_t const* name)
        {
            if (!obj.HasKey(name))
            {
                return L"";
            }
            auto value = obj.GetNamedValue(name, nullptr);
            if (!value || value.ValueType() != winrt::Windows::Data::Json::JsonValueType::String)
            {
                return L"";
            }
            return std::wstring(value.GetString().c_str());
        }

        struct ParsedBaseUrl
        {
            std::wstring Host{};
            std::wstring BasePath{ L"/" };
            INTERNET_PORT Port{ INTERNET_DEFAULT_HTTPS_PORT };
            bool Secure{ true };
        };

        std::wstring Utf8ToWide(std::string const& utf8)
        {
            if (utf8.empty())
            {
                return L"";
            }
            int cch = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
            if (cch <= 0)
            {
                return L"";
            }

            std::wstring wide;
            wide.resize(static_cast<size_t>(cch));
            MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), wide.data(), cch);
            return wide;
        }

        std::string WideToUtf8(std::wstring const& wide)
        {
            if (wide.empty())
            {
                return {};
            }

            int cb = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
            if (cb <= 0)
            {
                return {};
            }

            std::string utf8;
            utf8.resize(static_cast<size_t>(cb));
            WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), utf8.data(), cb, nullptr, nullptr);
            return utf8;
        }

        ParsedBaseUrl ParseBaseUrl(std::wstring const& baseUrl)
        {
            URL_COMPONENTS uc{};
            uc.dwStructSize = sizeof(uc);

            wchar_t host[256]{};
            wchar_t path[1024]{};
            uc.lpszHostName = host;
            uc.dwHostNameLength = ARRAYSIZE(host);
            uc.lpszUrlPath = path;
            uc.dwUrlPathLength = ARRAYSIZE(path);

            THROW_IF_WIN32_BOOL_FALSE(WinHttpCrackUrl(baseUrl.c_str(), 0, 0, &uc));

            ParsedBaseUrl out{};
            out.Host.assign(uc.lpszHostName, uc.dwHostNameLength);
            out.Port = uc.nPort;
            out.Secure = uc.nScheme == INTERNET_SCHEME_HTTPS;

            if (uc.dwUrlPathLength > 0)
            {
                out.BasePath.assign(uc.lpszUrlPath, uc.dwUrlPathLength);
            }
            if (out.BasePath.empty())
            {
                out.BasePath = L"/";
            }
            while (out.BasePath.size() > 1 && out.BasePath.back() == L'/')
            {
                out.BasePath.pop_back();
            }

            return out;
        }

        std::wstring BuildRequestPath(std::wstring const& basePath, std::wstring const& suffix)
        {
            std::wstring path = basePath;
            if (path.empty())
            {
                path = L"/";
            }
            if (path.back() != L'/')
            {
                path.push_back(L'/');
            }

            if (!suffix.empty() && suffix.front() == L'/')
            {
                path += suffix.substr(1);
            }
            else
            {
                path += suffix;
            }
            return path;
        }

        std::string ReadResponseBody(HINTERNET hRequest)
        {
            std::string body;
            DWORD size = 0;
            while (WinHttpQueryDataAvailable(hRequest, &size) && size > 0)
            {
                std::string chunk;
                chunk.resize(size);
                DWORD read = 0;
                THROW_IF_WIN32_BOOL_FALSE(WinHttpReadData(hRequest, chunk.data(), size, &read));
                chunk.resize(read);
                body += chunk;
                size = 0;
            }
            return body;
        }

        int32_t QueryStatusCode(HINTERNET hRequest)
        {
            DWORD statusCode = 0;
            DWORD size = sizeof(statusCode);
            THROW_IF_WIN32_BOOL_FALSE(WinHttpQueryHeaders(
                hRequest,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX,
                &statusCode,
                &size,
                WINHTTP_NO_HEADER_INDEX));
            return static_cast<int32_t>(statusCode);
        }

        std::wstring QueryHeaderString(HINTERNET hRequest, wchar_t const* headerName)
        {
            DWORD size = 0;
            if (!WinHttpQueryHeaders(
                hRequest,
                WINHTTP_QUERY_CUSTOM,
                headerName,
                WINHTTP_NO_OUTPUT_BUFFER,
                &size,
                WINHTTP_NO_HEADER_INDEX))
            {
                if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
                {
                    return L"";
                }
            }

            if (size == 0)
            {
                return L"";
            }

            std::wstring value;
            value.resize(size / sizeof(wchar_t));
            if (!WinHttpQueryHeaders(
                hRequest,
                WINHTTP_QUERY_CUSTOM,
                headerName,
                value.data(),
                &size,
                WINHTTP_NO_HEADER_INDEX))
            {
                return L"";
            }

            while (!value.empty() && value.back() == L'\0')
            {
                value.pop_back();
            }
            return value;
        }

        std::wstring QueryRequestId(HINTERNET hRequest)
        {
            std::wstring requestId = QueryHeaderString(hRequest, L"x-request-id");
            if (!requestId.empty())
            {
                return requestId;
            }
            requestId = QueryHeaderString(hRequest, L"request-id");
            if (!requestId.empty())
            {
                return requestId;
            }
            return QueryHeaderString(hRequest, L"x-ms-request-id");
        }

        std::wstring TryGetJsonString(winrt::Windows::Data::Json::JsonObject const& obj, wchar_t const* name)
        {
            if (!obj.HasKey(name))
            {
                return L"";
            }

            auto value = obj.GetNamedValue(name, nullptr);
            if (!value || value.ValueType() != winrt::Windows::Data::Json::JsonValueType::String)
            {
                return L"";
            }

            return std::wstring(value.GetString().c_str());
        }

        int64_t TryGetJsonInt64(winrt::Windows::Data::Json::JsonObject const& obj, wchar_t const* name, int64_t fallback = 0)
        {
            if (!obj.HasKey(name))
            {
                return fallback;
            }

            auto value = obj.GetNamedValue(name, nullptr);
            if (!value || value.ValueType() != winrt::Windows::Data::Json::JsonValueType::Number)
            {
                return fallback;
            }

            return static_cast<int64_t>(value.GetNumber());
        }

        void ParseErrorBody(std::string const& bodyUtf8, SyncHttpStatus* outStatus)
        {
            if (!outStatus || bodyUtf8.empty())
            {
                return;
            }

            try
            {
                auto root = winrt::Windows::Data::Json::JsonObject::Parse(Utf8ToWide(bodyUtf8));
                outStatus->ErrorCode = TryGetJsonString(root, L"code");
                outStatus->ErrorMessage = TryGetJsonString(root, L"message");
                outStatus->ServerVersion = TryGetJsonInt64(root, L"server_version", -1);
                if (outStatus->RequestId.empty())
                {
                    outStatus->RequestId = TryGetJsonString(root, L"request_id");
                }
            }
            catch (...)
            {
                outStatus->ErrorMessage = Utf8ToWide(bodyUtf8);
            }
        }

        void FillVaultRecordFromJsonAxum(
            winrt::Windows::Data::Json::JsonObject const& root,
            std::wstring const& userId,
            VaultRecord& outRecord)
        {
            outRecord = {};
            outRecord.UserId = userId;
            outRecord.VaultVersion = TryGetJsonInt64(root, L"server_version", 0);
            outRecord.DeviceClock = L"";

            outRecord.Blob.CiphertextBase64 = TryGetJsonString(root, L"cipher_blob_base64");
            outRecord.Blob.NonceBase64 = L"";
            outRecord.Blob.AadBase64 = L"";

            outRecord.Meta.CreatedAt = L"";
            outRecord.Meta.UpdatedAt = TryGetJsonString(root, L"updated_at");
            outRecord.Meta.LastWriterDeviceId = L"";
            outRecord.Meta.BlobSha256Base64 = L"";
        }

        HRESULT MapHttpStatusToHr(int32_t statusCode)
        {
            if (statusCode >= 200 && statusCode < 300)
            {
                return S_OK;
            }
            if (statusCode == 404)
            {
                return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
            }
            if (statusCode == 409)
            {
                return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
            }
            if (statusCode == 401 || statusCode == 403)
            {
                return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
            }
            return E_FAIL;
        }

        HRESULT EnsureTransportPolicy(
            ParsedBaseUrl const& parsed,
            bool allowInsecureHttp,
            SyncHttpStatus* outStatus,
            wchar_t const* operation)
        {
            if (parsed.Secure || allowInsecureHttp)
            {
                return S_OK;
            }

            if (outStatus)
            {
                outStatus->ErrorCode = L"INSECURE_HTTP_BLOCKED";
                outStatus->ErrorMessage = std::wstring(L"SyncClient::") + operation + L" blocked insecure HTTP URL. Set TSUPASSWD_SYNC_ALLOW_INSECURE_HTTP=1 only for development.";
            }
            return HRESULT_FROM_WIN32(ERROR_ACCESS_DISABLED_BY_POLICY);
        }

        void FillVaultRecordFromJson(winrt::Windows::Data::Json::JsonObject const& root, VaultRecord& outRecord)
        {
            outRecord = {};
            outRecord.UserId = TryGetJsonString(root, L"user_id");
            outRecord.VaultVersion = TryGetJsonInt64(root, L"vault_version", 0);
            outRecord.DeviceClock = TryGetJsonString(root, L"device_clock");

            auto vaultBlob = root.GetNamedObject(L"vault_blob", nullptr);
            if (vaultBlob)
            {
                outRecord.Blob.CiphertextBase64 = TryGetJsonString(vaultBlob, L"ciphertext_b64");
                outRecord.Blob.NonceBase64 = TryGetJsonString(vaultBlob, L"nonce_b64");
                outRecord.Blob.AadBase64 = TryGetJsonString(vaultBlob, L"aad_b64");
                auto alg = TryGetJsonString(vaultBlob, L"alg");
                if (!alg.empty())
                {
                    outRecord.Blob.Algorithm = alg;
                }
            }

            auto keyEnvelope = root.GetNamedObject(L"key_envelope", nullptr);
            if (keyEnvelope)
            {
                auto kekScheme = TryGetJsonString(keyEnvelope, L"kek_scheme");
                if (!kekScheme.empty())
                {
                    outRecord.Envelope.KekScheme = kekScheme;
                }
                outRecord.Envelope.WrappedDekBase64 = TryGetJsonString(keyEnvelope, L"wrapped_dek_b64");
                outRecord.Envelope.WrapNonceBase64 = TryGetJsonString(keyEnvelope, L"wrap_nonce_b64");
                outRecord.Envelope.KdfSaltBase64 = TryGetJsonString(keyEnvelope, L"kdf_salt_b64");
                auto kdfInfo = TryGetJsonString(keyEnvelope, L"kdf_info");
                if (!kdfInfo.empty())
                {
                    outRecord.Envelope.KdfInfo = kdfInfo;
                }
            }

            auto meta = root.GetNamedObject(L"meta", nullptr);
            if (meta)
            {
                outRecord.Meta.CreatedAt = TryGetJsonString(meta, L"created_at");
                outRecord.Meta.UpdatedAt = TryGetJsonString(meta, L"updated_at");
                outRecord.Meta.LastWriterDeviceId = TryGetJsonString(meta, L"last_writer_device_id");
                outRecord.Meta.BlobSha256Base64 = TryGetJsonString(meta, L"blob_sha256_b64");
            }
        }

        std::wstring BuildPutVaultJson(PutVaultRequest const& request)
        {
            using namespace winrt::Windows::Data::Json;

            JsonObject root;
            root.SetNamedValue(L"expected_version", JsonValue::CreateNumberValue(static_cast<double>(request.ExpectedVersion)));
            root.SetNamedValue(L"new_version", JsonValue::CreateNumberValue(static_cast<double>(request.NewVersion)));
            root.SetNamedValue(L"device_id", JsonValue::CreateStringValue(request.DeviceId));

            JsonObject blob;
            blob.SetNamedValue(L"ciphertext_b64", JsonValue::CreateStringValue(request.Blob.CiphertextBase64));
            blob.SetNamedValue(L"nonce_b64", JsonValue::CreateStringValue(request.Blob.NonceBase64));
            blob.SetNamedValue(L"aad_b64", JsonValue::CreateStringValue(request.Blob.AadBase64));
            blob.SetNamedValue(L"alg", JsonValue::CreateStringValue(request.Blob.Algorithm));
            root.SetNamedValue(L"vault_blob", blob);

            JsonObject envelope;
            envelope.SetNamedValue(L"kek_scheme", JsonValue::CreateStringValue(request.Envelope.KekScheme));
            envelope.SetNamedValue(L"wrapped_dek_b64", JsonValue::CreateStringValue(request.Envelope.WrappedDekBase64));
            envelope.SetNamedValue(L"wrap_nonce_b64", JsonValue::CreateStringValue(request.Envelope.WrapNonceBase64));
            envelope.SetNamedValue(L"kdf_salt_b64", JsonValue::CreateStringValue(request.Envelope.KdfSaltBase64));
            envelope.SetNamedValue(L"kdf_info", JsonValue::CreateStringValue(request.Envelope.KdfInfo));
            root.SetNamedValue(L"key_envelope", envelope);

            JsonObject meta;
            meta.SetNamedValue(L"created_at", JsonValue::CreateStringValue(request.Meta.CreatedAt));
            meta.SetNamedValue(L"updated_at", JsonValue::CreateStringValue(request.Meta.UpdatedAt));
            meta.SetNamedValue(L"last_writer_device_id", JsonValue::CreateStringValue(request.Meta.LastWriterDeviceId));
            meta.SetNamedValue(L"blob_sha256_b64", JsonValue::CreateStringValue(request.Meta.BlobSha256Base64));
            root.SetNamedValue(L"meta", meta);

            return std::wstring(root.Stringify().c_str());
        }

        std::wstring BuildPutVaultJsonAxum(PutVaultRequest const& request)
        {
            using namespace winrt::Windows::Data::Json;

            JsonObject root;
            root.SetNamedValue(L"expected_server_version", JsonValue::CreateNumberValue(static_cast<double>(request.ExpectedVersion)));
            root.SetNamedValue(L"cipher_blob_base64", JsonValue::CreateStringValue(request.Blob.CiphertextBase64));
            return std::wstring(root.Stringify().c_str());
        }
    }

    SyncClient::SyncClient(std::wstring baseUrl) :
        m_baseUrl(std::move(baseUrl))
    {
    }

    void SyncClient::SetApiKind(SyncApiKind kind)
    {
        m_apiKind = kind;
    }

    void SyncClient::SetBearerToken(std::wstring bearerToken)
    {
        m_bearerToken = std::move(bearerToken);
    }

    void SyncClient::SetTimeoutMs(int32_t timeoutMs)
    {
        if (timeoutMs > 0)
        {
            m_timeoutMs = timeoutMs;
        }
    }

    void SyncClient::SetAllowInsecureHttp(bool allowInsecureHttp)
    {
        m_allowInsecureHttp = allowInsecureHttp;
    }

    HRESULT SyncClient::DevLogin(
        std::wstring const& userId,
        std::wstring& outBearerToken,
        SyncHttpStatus* outStatus) const noexcept
    {
        outBearerToken.clear();
        if (outStatus)
        {
            *outStatus = {};
        }

        try
        {
            auto parsed = ParseBaseUrl(m_baseUrl);
            RETURN_IF_FAILED(EnsureTransportPolicy(parsed, m_allowInsecureHttp, outStatus, L"DevLogin"));

            std::wstring path = BuildRequestPath(parsed.BasePath, L"v1/auth/dev/login");

            winrt::Windows::Data::Json::JsonObject root;
            root.SetNamedValue(L"email", winrt::Windows::Data::Json::JsonValue::CreateStringValue(userId));
            std::wstring requestJson = std::wstring(root.Stringify().c_str());
            std::string requestUtf8 = WideToUtf8(requestJson);

            WinHttpHandle hSession(WinHttpOpen(L"tsupasswd_core/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
            THROW_LAST_ERROR_IF_NULL(hSession.get());

            WinHttpSetTimeouts(hSession.get(), m_timeoutMs, m_timeoutMs, m_timeoutMs, m_timeoutMs);

            WinHttpHandle hConnect(WinHttpConnect(hSession.get(), parsed.Host.c_str(), parsed.Port, 0));
            THROW_LAST_ERROR_IF_NULL(hConnect.get());

            DWORD openFlags = parsed.Secure ? WINHTTP_FLAG_SECURE : 0;
            WinHttpHandle requestHandle(WinHttpOpenRequest(hConnect.get(), L"POST", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, openFlags));
            THROW_LAST_ERROR_IF_NULL(requestHandle.get());

            std::wstring headers = L"Content-Type: application/json; charset=utf-8";
            THROW_IF_WIN32_BOOL_FALSE(WinHttpAddRequestHeaders(requestHandle.get(), headers.c_str(), static_cast<DWORD>(headers.size()), WINHTTP_ADDREQ_FLAG_ADD));

            THROW_IF_WIN32_BOOL_FALSE(WinHttpSendRequest(
                requestHandle.get(),
                WINHTTP_NO_ADDITIONAL_HEADERS,
                0,
                requestUtf8.empty() ? WINHTTP_NO_REQUEST_DATA : reinterpret_cast<LPVOID>(requestUtf8.data()),
                static_cast<DWORD>(requestUtf8.size()),
                static_cast<DWORD>(requestUtf8.size()),
                0));

            THROW_IF_WIN32_BOOL_FALSE(WinHttpReceiveResponse(requestHandle.get(), nullptr));

            int32_t statusCode = QueryStatusCode(requestHandle.get());
            std::string body = ReadResponseBody(requestHandle.get());
            if (outStatus)
            {
                outStatus->StatusCode = statusCode;
                outStatus->RequestId = QueryRequestId(requestHandle.get());
            }

            HRESULT hrStatus = MapHttpStatusToHr(statusCode);
            if (FAILED(hrStatus))
            {
                ParseErrorBody(body, outStatus);
                return hrStatus;
            }

            auto tokenRoot = winrt::Windows::Data::Json::JsonObject::Parse(Utf8ToWide(body));
            std::wstring accessToken = TryGetJsonString(tokenRoot, L"access_token");
            if (accessToken.empty())
            {
                if (outStatus)
                {
                    outStatus->ErrorCode = L"CLIENT_ERROR";
                    outStatus->ErrorMessage = L"DevLogin succeeded but response did not include access_token.";
                }
                return E_FAIL;
            }

            outBearerToken = accessToken;
            return S_OK;
        }
        catch (...)
        {
            if (outStatus)
            {
                outStatus->ErrorCode = L"CLIENT_ERROR";
                outStatus->ErrorMessage = L"SyncClient::DevLogin failed before receiving valid response.";
            }
            return wil::ResultFromCaughtException();
        }
    }

    HRESULT SyncClient::OpaqueRegister(
        std::wstring const& userId,
        std::wstring const& password,
        std::vector<uint8_t>* outExportKeyBytes,
        SyncHttpStatus* outStatus) const noexcept
    {
        if (outExportKeyBytes)
        {
            outExportKeyBytes->clear();
        }
        if (outStatus)
        {
            *outStatus = {};
        }

        try
        {
            auto parsed = ParseBaseUrl(m_baseUrl);
            RETURN_IF_FAILED(EnsureTransportPolicy(parsed, m_allowInsecureHttp, outStatus, L"OpaqueRegister"));

            std::string passwordUtf8 = WideToUtf8(password);
            if (passwordUtf8.empty())
            {
                if (outStatus)
                {
                    outStatus->ErrorCode = L"CLIENT_ERROR";
                    outStatus->ErrorMessage = L"OpaqueRegister requires non-empty password.";
                }
                return E_INVALIDARG;
            }

            using tsupasswd::opaque::ByteBufferOwner;
            ByteBufferOwner regClientState;
            ByteBufferOwner regRequest;
            if (!tsupasswd_opaque_client_register_start(
                    reinterpret_cast<const uint8_t*>(passwordUtf8.data()),
                    passwordUtf8.size(),
                    regClientState.out_ptr(),
                    regRequest.out_ptr()))
            {
                if (outStatus)
                {
                    outStatus->ErrorCode = L"OPAQUE_CLIENT_ERROR";
                    outStatus->ErrorMessage = Utf8ToWide(tsupasswd::opaque::TakeLastErrorString());
                }
                return E_FAIL;
            }

            DWORD openFlags = parsed.Secure ? WINHTTP_FLAG_SECURE : 0;
            std::wstring headers = L"Content-Type: application/json; charset=utf-8";

            WinHttpHandle hSession(WinHttpOpen(L"tsupasswd_core/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
            THROW_LAST_ERROR_IF_NULL(hSession.get());
            WinHttpSetTimeouts(hSession.get(), m_timeoutMs, m_timeoutMs, m_timeoutMs, m_timeoutMs);
            WinHttpHandle hConnect(WinHttpConnect(hSession.get(), parsed.Host.c_str(), parsed.Port, 0));
            THROW_LAST_ERROR_IF_NULL(hConnect.get());

            // POST /v1/auth/register/start
            winrt::Windows::Data::Json::JsonObject startBody;
            startBody.SetNamedValue(L"email", winrt::Windows::Data::Json::JsonValue::CreateStringValue(userId));
            startBody.SetNamedValue(
                L"registration_request_base64",
                winrt::Windows::Data::Json::JsonValue::CreateStringValue(Base64StdEncode(regRequest.data(), regRequest.size())));
            std::string startUtf8 = WideToUtf8(std::wstring(startBody.Stringify().c_str()));

            std::wstring startPath = BuildRequestPath(parsed.BasePath, L"v1/auth/register/start");
            WinHttpHandle hReq1(WinHttpOpenRequest(hConnect.get(), L"POST", startPath.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, openFlags));
            THROW_LAST_ERROR_IF_NULL(hReq1.get());
            THROW_IF_WIN32_BOOL_FALSE(WinHttpAddRequestHeaders(hReq1.get(), headers.c_str(), static_cast<DWORD>(headers.size()), WINHTTP_ADDREQ_FLAG_ADD));
            THROW_IF_WIN32_BOOL_FALSE(WinHttpSendRequest(
                hReq1.get(),
                WINHTTP_NO_ADDITIONAL_HEADERS,
                0,
                startUtf8.empty() ? WINHTTP_NO_REQUEST_DATA : reinterpret_cast<LPVOID>(startUtf8.data()),
                static_cast<DWORD>(startUtf8.size()),
                static_cast<DWORD>(startUtf8.size()),
                0));
            THROW_IF_WIN32_BOOL_FALSE(WinHttpReceiveResponse(hReq1.get(), nullptr));

            int32_t statusCode1 = QueryStatusCode(hReq1.get());
            std::string body1 = ReadResponseBody(hReq1.get());
            if (outStatus)
            {
                outStatus->StatusCode = statusCode1;
                outStatus->RequestId = QueryRequestId(hReq1.get());
            }

            HRESULT hrStatus1 = MapHttpStatusToHr(statusCode1);
            if (FAILED(hrStatus1))
            {
                ParseErrorBody(body1, outStatus);
                return hrStatus1;
            }

            auto startRespJson = winrt::Windows::Data::Json::JsonObject::Parse(Utf8ToWide(body1));
            std::wstring regRespB64 = GetNamedStringOrEmpty(startRespJson, L"registration_response_base64");
            if (regRespB64.empty())
            {
                if (outStatus)
                {
                    outStatus->ErrorCode = L"CLIENT_ERROR";
                    outStatus->ErrorMessage = L"OpaqueRegister: missing registration_response_base64.";
                }
                return E_FAIL;
            }

            std::vector<uint8_t> regRespBytes;
            if (!Base64StdDecode(regRespB64, regRespBytes))
            {
                if (outStatus)
                {
                    outStatus->ErrorCode = L"CLIENT_ERROR";
                    outStatus->ErrorMessage = L"OpaqueRegister: invalid registration_response_base64.";
                }
                return E_FAIL;
            }

            ByteBuffer regResp{ regRespBytes.data(), regRespBytes.size() };
            ByteBufferOwner regUpload;
            ByteBufferOwner regSessionKey;
            if (!tsupasswd_opaque_client_register_finish(
                    reinterpret_cast<const uint8_t*>(passwordUtf8.data()),
                    passwordUtf8.size(),
                    &regClientState.get(),
                    &regResp,
                    regUpload.out_ptr(),
                    regSessionKey.out_ptr()))
            {
                if (outStatus)
                {
                    outStatus->ErrorCode = L"OPAQUE_CLIENT_ERROR";
                    outStatus->ErrorMessage = Utf8ToWide(tsupasswd::opaque::TakeLastErrorString());
                }
                return E_FAIL;
            }

            std::vector<uint8_t> exportKeyBytes;
            if (regSessionKey.size() > 0)
            {
                exportKeyBytes.assign(regSessionKey.data(), regSessionKey.data() + regSessionKey.size());
            }

            // POST /v1/auth/register/finish
            winrt::Windows::Data::Json::JsonObject finishBody;
            finishBody.SetNamedValue(L"email", winrt::Windows::Data::Json::JsonValue::CreateStringValue(userId));
            finishBody.SetNamedValue(
                L"registration_upload_base64",
                winrt::Windows::Data::Json::JsonValue::CreateStringValue(Base64StdEncode(regUpload.data(), regUpload.size())));
            std::string finishUtf8 = WideToUtf8(std::wstring(finishBody.Stringify().c_str()));

            std::wstring finishPath = BuildRequestPath(parsed.BasePath, L"v1/auth/register/finish");
            WinHttpHandle hReq2(WinHttpOpenRequest(hConnect.get(), L"POST", finishPath.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, openFlags));
            THROW_LAST_ERROR_IF_NULL(hReq2.get());
            THROW_IF_WIN32_BOOL_FALSE(WinHttpAddRequestHeaders(hReq2.get(), headers.c_str(), static_cast<DWORD>(headers.size()), WINHTTP_ADDREQ_FLAG_ADD));
            THROW_IF_WIN32_BOOL_FALSE(WinHttpSendRequest(
                hReq2.get(),
                WINHTTP_NO_ADDITIONAL_HEADERS,
                0,
                finishUtf8.empty() ? WINHTTP_NO_REQUEST_DATA : reinterpret_cast<LPVOID>(finishUtf8.data()),
                static_cast<DWORD>(finishUtf8.size()),
                static_cast<DWORD>(finishUtf8.size()),
                0));
            THROW_IF_WIN32_BOOL_FALSE(WinHttpReceiveResponse(hReq2.get(), nullptr));

            int32_t statusCode2 = QueryStatusCode(hReq2.get());
            std::string body2 = ReadResponseBody(hReq2.get());
            if (outStatus)
            {
                outStatus->StatusCode = statusCode2;
                outStatus->RequestId = QueryRequestId(hReq2.get());
            }

            HRESULT hrStatus2 = MapHttpStatusToHr(statusCode2);
            if (FAILED(hrStatus2))
            {
                ParseErrorBody(body2, outStatus);
                return hrStatus2;
            }

            auto finishRespJson = winrt::Windows::Data::Json::JsonObject::Parse(Utf8ToWide(body2));
            bool ok = finishRespJson.GetNamedBoolean(L"ok", false);
            if (!ok)
            {
                return E_FAIL;
            }

            if (outExportKeyBytes)
            {
                *outExportKeyBytes = std::move(exportKeyBytes);
            }
            return S_OK;
        }
        catch (...)
        {
            if (outStatus)
            {
                outStatus->ErrorCode = L"CLIENT_ERROR";
                outStatus->ErrorMessage = L"SyncClient::OpaqueRegister failed before receiving valid response.";
            }
            return wil::ResultFromCaughtException();
        }
    }

    HRESULT SyncClient::OpaqueLogin(
        std::wstring const& userId,
        std::wstring const& password,
        std::wstring& outBearerToken,
        std::vector<uint8_t>* outSessionKeyBytes,
        SyncHttpStatus* outStatus) const noexcept
    {
        outBearerToken.clear();
        if (outSessionKeyBytes)
        {
            outSessionKeyBytes->clear();
        }
        if (outStatus)
        {
            *outStatus = {};
        }

        try
        {
            auto parsed = ParseBaseUrl(m_baseUrl);
            RETURN_IF_FAILED(EnsureTransportPolicy(parsed, m_allowInsecureHttp, outStatus, L"OpaqueLogin"));

            std::string passwordUtf8 = WideToUtf8(password);
            if (passwordUtf8.empty())
            {
                if (outStatus)
                {
                    outStatus->ErrorCode = L"CLIENT_ERROR";
                    outStatus->ErrorMessage = L"OpaqueLogin requires non-empty password.";
                }
                return E_INVALIDARG;
            }

            using tsupasswd::opaque::ByteBufferOwner;
            ByteBufferOwner loginClientState;
            ByteBufferOwner credRequest;
            if (!tsupasswd_opaque_client_login_start(
                    reinterpret_cast<const uint8_t*>(passwordUtf8.data()),
                    passwordUtf8.size(),
                    loginClientState.out_ptr(),
                    credRequest.out_ptr()))
            {
                if (outStatus)
                {
                    outStatus->ErrorCode = L"OPAQUE_CLIENT_ERROR";
                    outStatus->ErrorMessage = Utf8ToWide(tsupasswd::opaque::TakeLastErrorString());
                }
                return E_FAIL;
            }

            DWORD openFlags = parsed.Secure ? WINHTTP_FLAG_SECURE : 0;
            std::wstring headers = L"Content-Type: application/json; charset=utf-8";

            WinHttpHandle hSession(WinHttpOpen(L"tsupasswd_core/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
            THROW_LAST_ERROR_IF_NULL(hSession.get());
            WinHttpSetTimeouts(hSession.get(), m_timeoutMs, m_timeoutMs, m_timeoutMs, m_timeoutMs);
            WinHttpHandle hConnect(WinHttpConnect(hSession.get(), parsed.Host.c_str(), parsed.Port, 0));
            THROW_LAST_ERROR_IF_NULL(hConnect.get());

            // POST /v1/auth/login/start
            winrt::Windows::Data::Json::JsonObject startBody;
            startBody.SetNamedValue(L"email", winrt::Windows::Data::Json::JsonValue::CreateStringValue(userId));
            startBody.SetNamedValue(
                L"credential_request_base64",
                winrt::Windows::Data::Json::JsonValue::CreateStringValue(Base64StdEncode(credRequest.data(), credRequest.size())));
            std::string startUtf8 = WideToUtf8(std::wstring(startBody.Stringify().c_str()));

            std::wstring startPath = BuildRequestPath(parsed.BasePath, L"v1/auth/login/start");
            WinHttpHandle hReq1(WinHttpOpenRequest(hConnect.get(), L"POST", startPath.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, openFlags));
            THROW_LAST_ERROR_IF_NULL(hReq1.get());
            THROW_IF_WIN32_BOOL_FALSE(WinHttpAddRequestHeaders(hReq1.get(), headers.c_str(), static_cast<DWORD>(headers.size()), WINHTTP_ADDREQ_FLAG_ADD));
            THROW_IF_WIN32_BOOL_FALSE(WinHttpSendRequest(
                hReq1.get(),
                WINHTTP_NO_ADDITIONAL_HEADERS,
                0,
                startUtf8.empty() ? WINHTTP_NO_REQUEST_DATA : reinterpret_cast<LPVOID>(startUtf8.data()),
                static_cast<DWORD>(startUtf8.size()),
                static_cast<DWORD>(startUtf8.size()),
                0));
            THROW_IF_WIN32_BOOL_FALSE(WinHttpReceiveResponse(hReq1.get(), nullptr));

            int32_t statusCode1 = QueryStatusCode(hReq1.get());
            std::string body1 = ReadResponseBody(hReq1.get());
            if (outStatus)
            {
                outStatus->StatusCode = statusCode1;
                outStatus->RequestId = QueryRequestId(hReq1.get());
            }

            HRESULT hrStatus1 = MapHttpStatusToHr(statusCode1);
            if (FAILED(hrStatus1))
            {
                ParseErrorBody(body1, outStatus);
                return hrStatus1;
            }

            auto startRespJson = winrt::Windows::Data::Json::JsonObject::Parse(Utf8ToWide(body1));
            std::wstring serverStateB64 = GetNamedStringOrEmpty(startRespJson, L"server_state_base64");
            std::wstring credRespB64 = GetNamedStringOrEmpty(startRespJson, L"credential_response_base64");
            if (serverStateB64.empty() || credRespB64.empty())
            {
                if (outStatus)
                {
                    outStatus->ErrorCode = L"CLIENT_ERROR";
                    outStatus->ErrorMessage = L"OpaqueLogin: missing server_state_base64 or credential_response_base64.";
                }
                return E_FAIL;
            }

            std::vector<uint8_t> serverStateBytes;
            std::vector<uint8_t> credRespBytes;
            if (!Base64StdDecode(serverStateB64, serverStateBytes) || !Base64StdDecode(credRespB64, credRespBytes))
            {
                if (outStatus)
                {
                    outStatus->ErrorCode = L"CLIENT_ERROR";
                    outStatus->ErrorMessage = L"OpaqueLogin: invalid base64 in login/start response.";
                }
                return E_FAIL;
            }

            ByteBuffer serverState{ serverStateBytes.data(), serverStateBytes.size() };
            ByteBuffer credResp{ credRespBytes.data(), credRespBytes.size() };

            ByteBufferOwner credFinalization;
            ByteBufferOwner sessionKey;
            if (!tsupasswd_opaque_client_login_finish(
                    reinterpret_cast<const uint8_t*>(passwordUtf8.data()),
                    passwordUtf8.size(),
                    &loginClientState.get(),
                    &credResp,
                    credFinalization.out_ptr(),
                    sessionKey.out_ptr()))
            {
                if (outStatus)
                {
                    outStatus->ErrorCode = L"OPAQUE_CLIENT_ERROR";
                    outStatus->ErrorMessage = Utf8ToWide(tsupasswd::opaque::TakeLastErrorString());
                }
                return E_FAIL;
            }

            // POST /v1/auth/login/finish
            winrt::Windows::Data::Json::JsonObject finishBody;
            finishBody.SetNamedValue(
                L"email",
                winrt::Windows::Data::Json::JsonValue::CreateStringValue(winrt::hstring{ userId }));
            finishBody.SetNamedValue(
                L"server_state_base64",
                winrt::Windows::Data::Json::JsonValue::CreateStringValue(winrt::hstring{ Base64StdEncode(serverState.ptr, serverState.len) }));
            finishBody.SetNamedValue(
                L"credential_finalization_base64",
                winrt::Windows::Data::Json::JsonValue::CreateStringValue(winrt::hstring{ Base64StdEncode(credFinalization.data(), credFinalization.size()) }));
            std::string finishUtf8 = WideToUtf8(std::wstring(finishBody.Stringify().c_str()));

            std::wstring finishPath = BuildRequestPath(parsed.BasePath, L"v1/auth/login/finish");
            WinHttpHandle hReq2(WinHttpOpenRequest(hConnect.get(), L"POST", finishPath.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, openFlags));
            THROW_LAST_ERROR_IF_NULL(hReq2.get());
            THROW_IF_WIN32_BOOL_FALSE(WinHttpAddRequestHeaders(hReq2.get(), headers.c_str(), static_cast<DWORD>(headers.size()), WINHTTP_ADDREQ_FLAG_ADD));
            THROW_IF_WIN32_BOOL_FALSE(WinHttpSendRequest(
                hReq2.get(),
                WINHTTP_NO_ADDITIONAL_HEADERS,
                0,
                finishUtf8.empty() ? WINHTTP_NO_REQUEST_DATA : reinterpret_cast<LPVOID>(finishUtf8.data()),
                static_cast<DWORD>(finishUtf8.size()),
                static_cast<DWORD>(finishUtf8.size()),
                0));
            THROW_IF_WIN32_BOOL_FALSE(WinHttpReceiveResponse(hReq2.get(), nullptr));

            int32_t statusCode2 = QueryStatusCode(hReq2.get());
            std::string body2 = ReadResponseBody(hReq2.get());
            if (outStatus)
            {
                outStatus->StatusCode = statusCode2;
                outStatus->RequestId = QueryRequestId(hReq2.get());
            }

            HRESULT hrStatus2 = MapHttpStatusToHr(statusCode2);
            if (FAILED(hrStatus2))
            {
                ParseErrorBody(body2, outStatus);
                return hrStatus2;
            }

            auto tokenJson = winrt::Windows::Data::Json::JsonObject::Parse(Utf8ToWide(body2));
            std::wstring accessToken = GetNamedStringOrEmpty(tokenJson, L"access_token");
            if (accessToken.empty())
            {
                if (outStatus)
                {
                    outStatus->ErrorCode = L"CLIENT_ERROR";
                    outStatus->ErrorMessage = L"OpaqueLogin succeeded but response did not include access_token.";
                }
                return E_FAIL;
            }

            outBearerToken = accessToken;

            if (outSessionKeyBytes)
            {
                outSessionKeyBytes->assign(sessionKey.data(), sessionKey.data() + sessionKey.size());
            }
            return S_OK;
        }
        catch (...)
        {
            if (outStatus)
            {
                outStatus->ErrorCode = L"CLIENT_ERROR";
                outStatus->ErrorMessage = L"SyncClient::OpaqueLogin failed before receiving valid response.";
            }
            return wil::ResultFromCaughtException();
        }
    }

    HRESULT SyncClient::GetVault(
        std::wstring const& userId,
        VaultRecord& outRecord,
        SyncHttpStatus* outStatus) const noexcept
    {
        outRecord = {};
        if (outStatus)
        {
            *outStatus = {};
        }

        try
        {
            auto parsed = ParseBaseUrl(m_baseUrl);
            RETURN_IF_FAILED(EnsureTransportPolicy(parsed, m_allowInsecureHttp, outStatus, L"GetVault"));
            std::wstring path = BuildRequestPath(parsed.BasePath, L"v1/vaults/" + userId);

            WinHttpHandle hSession(WinHttpOpen(L"tsupasswd_core/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
            THROW_LAST_ERROR_IF_NULL(hSession.get());

            WinHttpSetTimeouts(hSession.get(), m_timeoutMs, m_timeoutMs, m_timeoutMs, m_timeoutMs);

            WinHttpHandle hConnect(WinHttpConnect(hSession.get(), parsed.Host.c_str(), parsed.Port, 0));
            THROW_LAST_ERROR_IF_NULL(hConnect.get());

            DWORD openFlags = parsed.Secure ? WINHTTP_FLAG_SECURE : 0;
            WinHttpHandle requestHandle(WinHttpOpenRequest(hConnect.get(), L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, openFlags));
            THROW_LAST_ERROR_IF_NULL(requestHandle.get());

            if (!m_bearerToken.empty())
            {
                std::wstring authHeader = L"Authorization: Bearer " + m_bearerToken;
                THROW_IF_WIN32_BOOL_FALSE(WinHttpAddRequestHeaders(requestHandle.get(), authHeader.c_str(), static_cast<DWORD>(authHeader.size()), WINHTTP_ADDREQ_FLAG_ADD));
            }

            THROW_IF_WIN32_BOOL_FALSE(WinHttpSendRequest(requestHandle.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0));
            THROW_IF_WIN32_BOOL_FALSE(WinHttpReceiveResponse(requestHandle.get(), nullptr));

            int32_t statusCode = QueryStatusCode(requestHandle.get());
            std::string body = ReadResponseBody(requestHandle.get());
            if (outStatus)
            {
                outStatus->StatusCode = statusCode;
                outStatus->RequestId = QueryRequestId(requestHandle.get());
            }

            HRESULT hrStatus = MapHttpStatusToHr(statusCode);
            if (FAILED(hrStatus))
            {
                ParseErrorBody(body, outStatus);
                return hrStatus;
            }

            auto root = winrt::Windows::Data::Json::JsonObject::Parse(Utf8ToWide(body));
            if (m_apiKind == SyncApiKind::Axum)
            {
                FillVaultRecordFromJsonAxum(root, userId, outRecord);
            }
            else
            {
                FillVaultRecordFromJson(root, outRecord);
            }
            return S_OK;
        }
        catch (...)
        {
            if (outStatus)
            {
                outStatus->ErrorCode = L"CLIENT_ERROR";
                outStatus->ErrorMessage = L"SyncClient::GetVault failed before receiving valid response.";
            }
            return wil::ResultFromCaughtException();
        }
    }

    HRESULT SyncClient::PutVault(
        std::wstring const& userId,
        PutVaultRequest const& request,
        PutVaultResponse& outResponse,
        SyncHttpStatus* outStatus) const noexcept
    {
        outResponse = {};
        if (outStatus)
        {
            *outStatus = {};
        }

        try
        {
            auto parsed = ParseBaseUrl(m_baseUrl);
            RETURN_IF_FAILED(EnsureTransportPolicy(parsed, m_allowInsecureHttp, outStatus, L"PutVault"));
            std::wstring path = BuildRequestPath(parsed.BasePath, L"v1/vaults/" + userId);
            std::wstring requestJson = (m_apiKind == SyncApiKind::Axum)
                ? BuildPutVaultJsonAxum(request)
                : BuildPutVaultJson(request);
            std::string requestUtf8 = WideToUtf8(requestJson);

            WinHttpHandle hSession(WinHttpOpen(L"tsupasswd_core/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
            THROW_LAST_ERROR_IF_NULL(hSession.get());

            WinHttpSetTimeouts(hSession.get(), m_timeoutMs, m_timeoutMs, m_timeoutMs, m_timeoutMs);

            WinHttpHandle hConnect(WinHttpConnect(hSession.get(), parsed.Host.c_str(), parsed.Port, 0));
            THROW_LAST_ERROR_IF_NULL(hConnect.get());

            DWORD openFlags = parsed.Secure ? WINHTTP_FLAG_SECURE : 0;
            WinHttpHandle requestHandle(WinHttpOpenRequest(hConnect.get(), L"PUT", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, openFlags));
            THROW_LAST_ERROR_IF_NULL(requestHandle.get());

            std::wstring headers = L"Content-Type: application/json; charset=utf-8";
            THROW_IF_WIN32_BOOL_FALSE(WinHttpAddRequestHeaders(requestHandle.get(), headers.c_str(), static_cast<DWORD>(headers.size()), WINHTTP_ADDREQ_FLAG_ADD));

            if (!m_bearerToken.empty())
            {
                std::wstring authHeader = L"Authorization: Bearer " + m_bearerToken;
                THROW_IF_WIN32_BOOL_FALSE(WinHttpAddRequestHeaders(requestHandle.get(), authHeader.c_str(), static_cast<DWORD>(authHeader.size()), WINHTTP_ADDREQ_FLAG_ADD));
            }

            THROW_IF_WIN32_BOOL_FALSE(WinHttpSendRequest(
                requestHandle.get(),
                WINHTTP_NO_ADDITIONAL_HEADERS,
                0,
                requestUtf8.empty() ? WINHTTP_NO_REQUEST_DATA : reinterpret_cast<LPVOID>(requestUtf8.data()),
                static_cast<DWORD>(requestUtf8.size()),
                static_cast<DWORD>(requestUtf8.size()),
                0));

            THROW_IF_WIN32_BOOL_FALSE(WinHttpReceiveResponse(requestHandle.get(), nullptr));

            int32_t statusCode = QueryStatusCode(requestHandle.get());
            std::string body = ReadResponseBody(requestHandle.get());
            if (outStatus)
            {
                outStatus->StatusCode = statusCode;
                outStatus->RequestId = QueryRequestId(requestHandle.get());
            }

            HRESULT hrStatus = MapHttpStatusToHr(statusCode);
            if (FAILED(hrStatus))
            {
                ParseErrorBody(body, outStatus);
                return hrStatus;
            }

            auto root = winrt::Windows::Data::Json::JsonObject::Parse(Utf8ToWide(body));
            outResponse.Ok = root.GetNamedBoolean(L"ok", false);
            if (m_apiKind == SyncApiKind::Axum)
            {
                outResponse.VaultVersion = TryGetJsonInt64(root, L"server_version", request.NewVersion);
            }
            else
            {
                outResponse.VaultVersion = TryGetJsonInt64(root, L"vault_version", request.NewVersion);
            }
            outResponse.UpdatedAt = TryGetJsonString(root, L"updated_at");
            return S_OK;
        }
        catch (...)
        {
            if (outStatus)
            {
                outStatus->ErrorCode = L"CLIENT_ERROR";
                outStatus->ErrorMessage = L"SyncClient::PutVault failed before receiving valid response.";
            }
            return wil::ResultFromCaughtException();
        }
    }
}
