using System.Net;
using System.Text.Json;
using HkdfGuard.Abstractions;
using HkdfGuard.DataProtectionKey.KeyTracking;

namespace HkdfGuard.Cache.Vault;

/// <summary>
/// A ProtectedCacheBase pulled through from a HashiCorp Vault secret store, talking to Vault's
/// HTTP REST API directly (no Vault client library). Secrets are fetched as plaintext (Vault is
/// trusted for confidentiality/access control on its own) on a cache miss, then immediately
/// encrypted into Cache via dataProtectionKey, so nothing here ever holds Vault plaintext beyond
/// the duration of a single TryPopulate call. dataProtectionKey is expected to be an ephemeral
/// key already registered on a KeyRing (e.g. via KeyRingBuilder.AddEphemeralKey/
/// HkdfGuardOptions.EphemeralKeys) rather than one this class builds itself - its lifetime,
/// rotation, and sharing across caches stay a property of that KeyRing. Because that key is
/// ephemeral (freshly random per KeyRing instance), this is still a read-through cache for the
/// KeyRing's lifetime only - only Vault itself is a durable source of truth.
///
/// name is the request path appended after "v1/" (e.g. "secret/data/my-app" for a KV v2 mount
/// named "secret") - Vault's response envelope's top-level "data" field is taken verbatim
/// (JSON-serialized) as the cached value, since a Vault secret is itself a multi-field document
/// rather than a single string; callers parse whatever fields they need from the returned JSON.
///
/// Authentication is obtained via the supplied IVaultAuthenticator and reused for every
/// subsequent request until tokenLifetime elapses (default one day), at which point the next
/// request re-authenticates automatically. The Vault token itself is never held in plaintext:
/// IVaultAuthenticator returns it as a formatted string from an IDataProtector bound to
/// ProtectorPurpose (via keyRing.CreateProtector), so it stays decryptable regardless of
/// whatever else gets added to keyRing in the meantime - and it's revealed only transiently,
/// into a stackalloc'd buffer immediately before being attached to each request, cleared right
/// after.
/// </summary>
public sealed class VaultProtectedCache(
    HttpClient httpClient,
    IVaultAuthenticator authenticator,
    KeyRing keyRing,
    IDataProtectionKey dataProtectionKey,
    TimeSpan? tokenLifetime = null)
    : ProtectedCacheBase(dataProtectionKey)
{
    /// <summary>
    /// The name every IDataProtector this library creates from keyRing (for protecting Vault
    /// credentials/tokens) is bound to - must be the same everywhere so values protected by one
    /// class here can be revealed by another.
    /// </summary>
    public const string ProtectorPurpose = "HkdfGuard.Cache.Vault";

    private static readonly TimeSpan DefaultTokenLifetime = TimeSpan.FromDays(1);

    private readonly TimeSpan _tokenLifetime = tokenLifetime ?? DefaultTokenLifetime;
    private readonly Lock _tokenLock = new();
    private string? _encryptedToken;
    private DateTimeOffset _tokenExpiresAt;

    /// <summary>
    /// Checks whether Vault is initialized, unsealed, and active by calling the unauthenticated
    /// sys/health endpoint - Vault's own "is this instance up and ready to serve requests" check
    /// (Vault's API has no route literally named "ping"; sys/health is the purpose-built
    /// equivalent). Returns false rather than throwing for both an unhealthy response (any status
    /// other than 200) and a failure to even reach Vault (connection failure, timeout) - a
    /// health check that itself needs a try/catch to answer "is it up" defeats its own purpose.
    /// </summary>
    public bool Ping()
    {
        using var activity = VaultDiagnostics.ActivitySource.StartActivity("VaultProtectedCache.Ping");

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "v1/sys/health");
            using var response = httpClient.Send(request);
            return response.StatusCode == HttpStatusCode.OK;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            VaultDiagnostics.RecordException(activity, ex);
            return false;
        }
        catch (Exception ex)
        {
            VaultDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    protected override bool TryPopulate(string name)
    {
        using var activity = VaultDiagnostics.ActivitySource.StartActivity("VaultProtectedCache.TryPopulate");
        if (VaultDiagnostics.EnableSensitiveLogging)
            VaultDiagnostics.LogSensitiveOperation(activity, "VaultProtectedCache.TryPopulate", ("name", name));

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"v1/{name}");
            request.Headers.Add("X-Vault-Token", RevealToken());

            using var response = httpClient.Send(request);
            if (response.StatusCode == HttpStatusCode.NotFound)
                return false;

            response.EnsureSuccessStatusCode();

            using var stream = response.Content.ReadAsStream();
            using var document = JsonDocument.Parse(stream);
            var data = document.RootElement.GetProperty("data");

            // GetRawText() returns a fresh immutable string that can't be zeroed itself - copy it
            // into a caller-owned Span<char> that EncryptChars can zero once it's done encrypting.
            var rawText = data.GetRawText();
            Span<char> secretChars = stackalloc char[rawText.Length];
            rawText.AsSpan().CopyTo(secretChars);
            Cache[name] = EncryptChars(secretChars);
            return true;
        }
        catch (Exception ex)
        {
            VaultDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    // Authenticates on first use and again whenever tokenLifetime has elapsed since the last
    // authentication - everything in between reuses the same encrypted token.
    private string GetEncryptedToken()
    {
        lock (_tokenLock)
        {
            if (_encryptedToken is null || DateTimeOffset.UtcNow >= _tokenExpiresAt)
            {
                _encryptedToken = authenticator.GetToken(httpClient, keyRing);
                _tokenExpiresAt = DateTimeOffset.UtcNow + _tokenLifetime;
            }

            return _encryptedToken;
        }
    }

    // Reveals the Vault token fresh on every call into a stackalloc'd buffer rather than caching
    // the plaintext or touching the heap for it, and clears the buffer immediately after use -
    // the token only ever exists as plaintext for the duration of building this one header value.
    private string RevealToken()
    {
        var encrypted = GetEncryptedToken();
        var protector = keyRing.CreateProtector(ProtectorPurpose);

        Span<char> tokenChars = stackalloc char[protector.GetMaxDecryptedLength(encrypted)];
        try
        {
            var written = protector.Decrypt(encrypted, tokenChars);
            return new string(tokenChars[..written]);
        }
        finally
        {
            tokenChars.Clear();
        }
    }
}
