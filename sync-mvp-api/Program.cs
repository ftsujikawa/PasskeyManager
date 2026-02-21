using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);

var rateLimitPerMinute = ReadPositiveIntFromEnv("TSUPASSWD_SYNC_RATE_LIMIT_PER_MINUTE", 60);
var rateLimitQueueLimit = ReadNonNegativeIntFromEnv("TSUPASSWD_SYNC_RATE_LIMIT_QUEUE_LIMIT", 0);

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
});

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = async (context, cancellationToken) =>
    {
        context.HttpContext.Response.ContentType = "application/json";
        var body = JsonSerializer.Serialize(new ErrorResponse("RATE_LIMITED", "too many requests"));
        await context.HttpContext.Response.WriteAsync(body, cancellationToken);
    };

    options.AddPolicy("vaults-per-ip", httpContext =>
    {
        var clientKey = GetRateLimitClientKey(httpContext);
        return RateLimitPartition.GetFixedWindowLimiter(clientKey, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = rateLimitPerMinute,
            Window = TimeSpan.FromMinutes(1),
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = rateLimitQueueLimit,
            AutoReplenishment = true
        });
    });
});

var app = builder.Build();
var logger = app.Logger;

app.UseRateLimiter();

var requiredToken = Environment.GetEnvironmentVariable("TSUPASSWD_SYNC_BEARER_TOKEN")
    ?? Environment.GetEnvironmentVariable("TSUPASSWD_SYNC_DEV_BEARER_TOKEN")
    ?? "dev-token";
var dbPath = Environment.GetEnvironmentVariable("TSUPASSWD_SYNC_DB_PATH")
    ?? Path.Combine(AppContext.BaseDirectory, "vault-store.db");
var legacyJsonStorePath = Environment.GetEnvironmentVariable("TSUPASSWD_SYNC_STORE_PATH")
    ?? Path.Combine(AppContext.BaseDirectory, "vault-store.json");

EnsureDbSchema(dbPath);
TryMigrateJsonStoreToDb(legacyJsonStorePath, dbPath);

app.MapGet("/healthz", () => Results.Ok(new
{
    ok = true,
    service = "sync-mvp-api",
    db_path = dbPath,
    legacy_json_store_path = legacyJsonStorePath
}));

app.MapGet("/v1/vaults/{userId}", (HttpContext http, string userId) =>
{
    var auth = Authorize(http, requiredToken, logger, userId);
    if (auth is not null)
    {
        return auth;
    }

    if (!TryGetVaultFromDb(dbPath, userId, out var doc) || doc is null)
    {
        AuditVaultOperation(logger, http, userId, StatusCodes.Status404NotFound, "vault_not_found", null);
        return Results.NotFound(new ErrorResponse("VAULT_NOT_FOUND", "vault not found"));
    }

    AuditVaultOperation(logger, http, userId, StatusCodes.Status200OK, "vault_get_ok", doc.VaultVersion);
    return Results.Ok(doc.ToResponse(userId));
}).RequireRateLimiting("vaults-per-ip");

app.MapPut("/v1/vaults/{userId}", async (HttpContext http, string userId) =>
{
    var auth = Authorize(http, requiredToken, logger, userId);
    if (auth is not null)
    {
        return auth;
    }

    var request = await http.Request.ReadFromJsonAsync<PutVaultRequest>();
    if (request is null)
    {
        AuditVaultOperation(logger, http, userId, StatusCodes.Status400BadRequest, "invalid_body", null);
        return Results.BadRequest(new ErrorResponse("INVALID_BODY", "request body is required"));
    }

    if (request.NewVersion <= 0)
    {
        AuditVaultOperation(logger, http, userId, StatusCodes.Status400BadRequest, "invalid_version", null);
        return Results.BadRequest(new ErrorResponse("INVALID_VERSION", "new_version must be > 0"));
    }

    var existing = TryGetVaultFromDb(dbPath, userId, out var current) ? current : null;
    var currentVersion = existing?.VaultVersion ?? 0;

    if (request.ExpectedVersion != currentVersion)
    {
        AuditVaultOperation(logger, http, userId, StatusCodes.Status409Conflict, "version_conflict", currentVersion);
        return Results.Conflict(new
        {
            code = "VERSION_CONFLICT",
            server_version = currentVersion
        });
    }

    var now = DateTimeOffset.UtcNow;
    var createdAt = existing?.Meta.CreatedAt ?? now;

    var next = new VaultDocument
    {
        VaultVersion = request.NewVersion,
        DeviceClock = now,
        VaultBlob = request.VaultBlob,
        KeyEnvelope = request.KeyEnvelope,
        Meta = new VaultMeta
        {
            CreatedAt = createdAt,
            UpdatedAt = now,
            LastWriterDeviceId = request.DeviceId,
            BlobSha256Base64 = request.Meta?.BlobSha256Base64 ?? string.Empty
        }
    };

    if (!TryWriteVaultWithVersionCheck(dbPath, userId, request.ExpectedVersion, next, out var serverVersion))
    {
        return Results.Conflict(new
        {
            code = "VERSION_CONFLICT",
            server_version = serverVersion
        });
    }

    AuditVaultOperation(logger, http, userId, StatusCodes.Status200OK, "vault_put_ok", next.VaultVersion);

    return Results.Ok(new
    {
        ok = true,
        vault_version = next.VaultVersion,
        updated_at = next.Meta.UpdatedAt.ToString("O")
    });
}).RequireRateLimiting("vaults-per-ip");

app.Run("http://127.0.0.1:8088");

static void EnsureDbSchema(string dbPath)
{
    var parentDir = Path.GetDirectoryName(dbPath);
    if (!string.IsNullOrWhiteSpace(parentDir))
    {
        Directory.CreateDirectory(parentDir);
    }

    using var connection = CreateConnection(dbPath);
    connection.Open();

    using var command = connection.CreateCommand();
    command.CommandText = @"
CREATE TABLE IF NOT EXISTS vaults (
    user_id TEXT PRIMARY KEY,
    vault_version INTEGER NOT NULL,
    document_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);";
    command.ExecuteNonQuery();
}

static void TryMigrateJsonStoreToDb(string legacyJsonStorePath, string dbPath)
{
    if (!File.Exists(legacyJsonStorePath) || GetVaultCount(dbPath) > 0)
    {
        return;
    }

    try
    {
        var json = File.ReadAllText(legacyJsonStorePath);
        var persisted = JsonSerializer.Deserialize<PersistedStore>(json);
        if (persisted?.Vaults is null || persisted.Vaults.Count == 0)
        {
            return;
        }

        foreach (var kv in persisted.Vaults)
        {
            if (!string.IsNullOrWhiteSpace(kv.Key) && kv.Value is not null)
            {
                UpsertVaultToDb(dbPath, kv.Key, kv.Value);
            }
        }
    }
    catch
    {
        // MVP: 壊れた JSON は無視して空 DB で起動する。
    }
}

static bool TryGetVaultFromDb(string dbPath, string userId, out VaultDocument? document)
{
    document = null;

    using var connection = CreateConnection(dbPath);
    connection.Open();

    using var command = connection.CreateCommand();
    command.CommandText = "SELECT document_json FROM vaults WHERE user_id = $userId;";
    command.Parameters.AddWithValue("$userId", userId);

    var json = command.ExecuteScalar() as string;
    if (string.IsNullOrWhiteSpace(json))
    {
        return false;
    }

    document = JsonSerializer.Deserialize<VaultDocument>(json);
    return document is not null;
}

static bool TryWriteVaultWithVersionCheck(string dbPath, string userId, long expectedVersion, VaultDocument next, out long serverVersion)
{
    serverVersion = 0;

    using var connection = CreateConnection(dbPath);
    connection.Open();

    using var transaction = connection.BeginTransaction();

    using (var select = connection.CreateCommand())
    {
        select.Transaction = transaction;
        select.CommandText = "SELECT vault_version FROM vaults WHERE user_id = $userId;";
        select.Parameters.AddWithValue("$userId", userId);
        var rawVersion = select.ExecuteScalar();
        serverVersion = rawVersion is null || rawVersion is DBNull ? 0 : Convert.ToInt64(rawVersion);
    }

    if (expectedVersion != serverVersion)
    {
        transaction.Rollback();
        return false;
    }

    UpsertVaultToDbWithConnection(connection, transaction, userId, next);
    transaction.Commit();
    return true;
}

static void UpsertVaultToDb(string dbPath, string userId, VaultDocument document)
{
    using var connection = CreateConnection(dbPath);
    connection.Open();
    UpsertVaultToDbWithConnection(connection, null, userId, document);
}

static void UpsertVaultToDbWithConnection(SqliteConnection connection, SqliteTransaction? transaction, string userId, VaultDocument document)
{
    using var command = connection.CreateCommand();
    command.Transaction = transaction;
    command.CommandText = @"
INSERT INTO vaults (user_id, vault_version, document_json, updated_at)
VALUES ($userId, $vaultVersion, $documentJson, $updatedAt)
ON CONFLICT(user_id) DO UPDATE SET
    vault_version = excluded.vault_version,
    document_json = excluded.document_json,
    updated_at = excluded.updated_at;";

    command.Parameters.AddWithValue("$userId", userId);
    command.Parameters.AddWithValue("$vaultVersion", document.VaultVersion);
    command.Parameters.AddWithValue("$documentJson", JsonSerializer.Serialize(document));
    command.Parameters.AddWithValue("$updatedAt", document.Meta.UpdatedAt.ToString("O"));
    command.ExecuteNonQuery();
}

static long GetVaultCount(string dbPath)
{
    using var connection = CreateConnection(dbPath);
    connection.Open();

    using var command = connection.CreateCommand();
    command.CommandText = "SELECT COUNT(*) FROM vaults;";
    return Convert.ToInt64(command.ExecuteScalar());
}

static SqliteConnection CreateConnection(string dbPath)
{
    var builder = new SqliteConnectionStringBuilder
    {
        DataSource = dbPath,
        Mode = SqliteOpenMode.ReadWriteCreate,
        Cache = SqliteCacheMode.Default
    };

    return new SqliteConnection(builder.ConnectionString);
}

static IResult? Authorize(HttpContext http, string requiredToken, ILogger logger, string userId)
{
    if (!http.Request.Headers.TryGetValue("Authorization", out var authHeader))
    {
        AuditVaultOperation(logger, http, userId, StatusCodes.Status401Unauthorized, "auth_missing_header", null);
        return Results.Unauthorized();
    }

    var value = authHeader.ToString();
    const string prefix = "Bearer ";
    if (!value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
    {
        AuditVaultOperation(logger, http, userId, StatusCodes.Status401Unauthorized, "auth_invalid_scheme", null);
        return Results.Unauthorized();
    }

    var token = value[prefix.Length..].Trim();
    if (!string.Equals(token, requiredToken, StringComparison.Ordinal))
    {
        AuditVaultOperation(logger, http, userId, StatusCodes.Status403Forbidden, "auth_token_mismatch", null);
        return Results.StatusCode(StatusCodes.Status403Forbidden);
    }

    return null;
}

static void AuditVaultOperation(ILogger logger, HttpContext http, string userId, int resultCode, string outcome, long? serverVersion)
{
    logger.LogInformation(
        "audit.vault_op ts={Timestamp} user_id={UserId} method={Method} result_code={ResultCode} remote_addr={RemoteAddr} outcome={Outcome} server_version={ServerVersion}",
        DateTimeOffset.UtcNow.ToString("O"),
        userId,
        http.Request.Method,
        resultCode,
        GetRemoteAddress(http),
        outcome,
        serverVersion);
}

static string GetRemoteAddress(HttpContext http)
{
    var forwardedFor = http.Request.Headers["X-Forwarded-For"].ToString();
    if (!string.IsNullOrWhiteSpace(forwardedFor))
    {
        var first = forwardedFor.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(first))
        {
            return first;
        }
    }

    return http.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}

static int ReadPositiveIntFromEnv(string name, int defaultValue)
{
    var raw = Environment.GetEnvironmentVariable(name);
    if (int.TryParse(raw, out var parsed) && parsed > 0)
    {
        return parsed;
    }

    return defaultValue;
}

static int ReadNonNegativeIntFromEnv(string name, int defaultValue)
{
    var raw = Environment.GetEnvironmentVariable(name);
    if (int.TryParse(raw, out var parsed) && parsed >= 0)
    {
        return parsed;
    }

    return defaultValue;
}

static string GetRateLimitClientKey(HttpContext http)
{
    return GetRemoteAddress(http);
}

record ErrorResponse(string code, string message);

sealed class VaultDocument
{
    public long VaultVersion { get; set; }
    public DateTimeOffset DeviceClock { get; set; }
    public VaultBlob VaultBlob { get; set; } = new();
    public KeyEnvelope KeyEnvelope { get; set; } = new();
    public VaultMeta Meta { get; set; } = new();

    public object ToResponse(string userId) => new
    {
        user_id = userId,
        vault_version = VaultVersion,
        device_clock = DeviceClock.ToString("O"),
        vault_blob = new
        {
            ciphertext_b64 = VaultBlob.CiphertextB64,
            nonce_b64 = VaultBlob.NonceB64,
            aad_b64 = VaultBlob.AadB64,
            alg = string.IsNullOrWhiteSpace(VaultBlob.Alg) ? "AES-256-GCM" : VaultBlob.Alg
        },
        key_envelope = new
        {
            kek_scheme = string.IsNullOrWhiteSpace(KeyEnvelope.KekScheme) ? "passkey+recovery_code_v1" : KeyEnvelope.KekScheme,
            wrapped_dek_b64 = KeyEnvelope.WrappedDekB64,
            wrap_nonce_b64 = KeyEnvelope.WrapNonceB64,
            kdf_salt_b64 = KeyEnvelope.KdfSaltB64,
            kdf_info = string.IsNullOrWhiteSpace(KeyEnvelope.KdfInfo) ? "vault-dek-wrap" : KeyEnvelope.KdfInfo
        },
        meta = new
        {
            created_at = Meta.CreatedAt.ToString("O"),
            updated_at = Meta.UpdatedAt.ToString("O"),
            last_writer_device_id = Meta.LastWriterDeviceId,
            blob_sha256_b64 = Meta.BlobSha256Base64
        }
    };
}

sealed class PutVaultRequest
{
    [JsonPropertyName("expected_version")]
    public long ExpectedVersion { get; set; }

    [JsonPropertyName("new_version")]
    public long NewVersion { get; set; }

    [JsonPropertyName("device_id")]
    public string DeviceId { get; set; } = string.Empty;

    [JsonPropertyName("vault_blob")]
    public VaultBlob VaultBlob { get; set; } = new();

    [JsonPropertyName("key_envelope")]
    public KeyEnvelope KeyEnvelope { get; set; } = new();

    [JsonPropertyName("meta")]
    public PutMeta? Meta { get; set; }
}

sealed class VaultBlob
{
    [JsonPropertyName("ciphertext_b64")]
    public string CiphertextB64 { get; set; } = string.Empty;

    [JsonPropertyName("nonce_b64")]
    public string NonceB64 { get; set; } = string.Empty;

    [JsonPropertyName("aad_b64")]
    public string AadB64 { get; set; } = string.Empty;

    [JsonPropertyName("alg")]
    public string Alg { get; set; } = "AES-256-GCM";
}

sealed class KeyEnvelope
{
    [JsonPropertyName("kek_scheme")]
    public string KekScheme { get; set; } = "passkey+recovery_code_v1";

    [JsonPropertyName("wrapped_dek_b64")]
    public string WrappedDekB64 { get; set; } = string.Empty;

    [JsonPropertyName("wrap_nonce_b64")]
    public string WrapNonceB64 { get; set; } = string.Empty;

    [JsonPropertyName("kdf_salt_b64")]
    public string KdfSaltB64 { get; set; } = string.Empty;

    [JsonPropertyName("kdf_info")]
    public string KdfInfo { get; set; } = "vault-dek-wrap";
}

sealed class PutMeta
{
    [JsonPropertyName("blob_sha256_b64")]
    public string BlobSha256Base64 { get; set; } = string.Empty;
}

sealed class VaultMeta
{
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public string LastWriterDeviceId { get; set; } = string.Empty;
    public string BlobSha256Base64 { get; set; } = string.Empty;
}

sealed class PersistedStore
{
    public Dictionary<string, VaultDocument> Vaults { get; set; } = new(StringComparer.Ordinal);
}
