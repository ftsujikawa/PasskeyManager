using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
});

var app = builder.Build();

var requiredToken = Environment.GetEnvironmentVariable("TSUPASSWD_SYNC_BEARER_TOKEN")
    ?? Environment.GetEnvironmentVariable("TSUPASSWD_SYNC_DEV_BEARER_TOKEN")
    ?? "dev-token";
var storePath = Environment.GetEnvironmentVariable("TSUPASSWD_SYNC_STORE_PATH")
    ?? Path.Combine(AppContext.BaseDirectory, "vault-store.json");

var store = new ConcurrentDictionary<string, VaultDocument>(StringComparer.Ordinal);
var persistLock = new object();

LoadStoreFromDisk(store, storePath);

app.MapGet("/healthz", () => Results.Ok(new { ok = true, service = "sync-mvp-api", store_path = storePath }));

app.MapGet("/v1/vaults/{userId}", (HttpContext http, string userId) =>
{
    var auth = Authorize(http, requiredToken);
    if (auth is not null)
    {
        return auth;
    }

    if (!store.TryGetValue(userId, out var doc))
    {
        return Results.NotFound(new ErrorResponse("VAULT_NOT_FOUND", "vault not found"));
    }

    return Results.Ok(doc.ToResponse(userId));
});

app.MapPut("/v1/vaults/{userId}", async (HttpContext http, string userId) =>
{
    var auth = Authorize(http, requiredToken);
    if (auth is not null)
    {
        return auth;
    }

    var request = await http.Request.ReadFromJsonAsync<PutVaultRequest>();
    if (request is null)
    {
        return Results.BadRequest(new ErrorResponse("INVALID_BODY", "request body is required"));
    }

    if (request.NewVersion <= 0)
    {
        return Results.BadRequest(new ErrorResponse("INVALID_VERSION", "new_version must be > 0"));
    }

    var existing = store.TryGetValue(userId, out var current) ? current : null;
    var currentVersion = existing?.VaultVersion ?? 0;

    if (request.ExpectedVersion != currentVersion)
    {
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

    store[userId] = next;
    SaveStoreToDisk(store, storePath, persistLock);

    return Results.Ok(new
    {
        ok = true,
        vault_version = next.VaultVersion,
        updated_at = next.Meta.UpdatedAt.ToString("O")
    });
});

app.Run("http://127.0.0.1:8088");

static void LoadStoreFromDisk(ConcurrentDictionary<string, VaultDocument> store, string storePath)
{
    if (!File.Exists(storePath))
    {
        return;
    }

    try
    {
        var json = File.ReadAllText(storePath);
        var persisted = JsonSerializer.Deserialize<PersistedStore>(json);
        if (persisted?.Vaults is null)
        {
            return;
        }

        foreach (var kv in persisted.Vaults)
        {
            if (!string.IsNullOrWhiteSpace(kv.Key) && kv.Value is not null)
            {
                store[kv.Key] = kv.Value;
            }
        }
    }
    catch
    {
        // MVP: 壊れたファイルは無視して空ストアで起動する。
    }
}

static void SaveStoreToDisk(ConcurrentDictionary<string, VaultDocument> store, string storePath, object persistLock)
{
    lock (persistLock)
    {
        var parentDir = Path.GetDirectoryName(storePath);
        if (!string.IsNullOrWhiteSpace(parentDir))
        {
            Directory.CreateDirectory(parentDir);
        }

        var snapshot = new PersistedStore
        {
            Vaults = store.ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal)
        };

        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        var json = JsonSerializer.Serialize(snapshot, options);
        var tempPath = storePath + ".tmp";
        File.WriteAllText(tempPath, json);
        File.Move(tempPath, storePath, true);
    }
}

static IResult? Authorize(HttpContext http, string requiredToken)
{
    if (!http.Request.Headers.TryGetValue("Authorization", out var authHeader))
    {
        return Results.Unauthorized();
    }

    var value = authHeader.ToString();
    const string prefix = "Bearer ";
    if (!value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
    {
        return Results.Unauthorized();
    }

    var token = value[prefix.Length..].Trim();
    if (!string.Equals(token, requiredToken, StringComparison.Ordinal))
    {
        return Results.StatusCode(StatusCodes.Status403Forbidden);
    }

    return null;
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
