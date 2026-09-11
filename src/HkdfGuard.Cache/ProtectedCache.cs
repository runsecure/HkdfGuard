using HkdfGuard.Abstractions;

namespace HkdfGuard.Cache;

/// <summary>
/// Default IProtectedCache. Backed by a single, already-built IDataProtectionKey - every
/// Add/AddOrUpdate encrypts through it (see ProtectedCacheBase), every TryDecrypt reveals
/// through it. Add uses TryAdd as its atomicity gate so a duplicate name is rejected even under
/// concurrent callers; AddOrUpdate's upsert and TryDecrypt's reads are otherwise lock-free, so
/// this holds up under highly concurrent access in every direction. Nothing here ever holds
/// plaintext beyond the duration of a single Add/AddOrUpdate/TryDecrypt call.
/// </summary>
public sealed class ProtectedCache(IDataProtectionKey dataProtectionKey) : ProtectedCacheBase(dataProtectionKey), IProtectedCache
{
    /// <inheritdoc/>
    public void Add(string name, Span<byte> plaintext)
    {
        using var activity = CacheDiagnostics.ActivitySource.StartActivity("ProtectedCache.Add");
        if (CacheDiagnostics.EnableSensitiveLogging)
            CacheDiagnostics.LogSensitiveOperation(activity, "ProtectedCache.Add",
                ("name", name), ("plaintextLength", plaintext.Length));

        try
        {
            if (!Cache.TryAdd(name, Encrypt(plaintext)))
                throw new ArgumentException($"An item with the name '{name}' has already been added.", nameof(name));
        }
        catch (Exception ex)
        {
            CacheDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public void Add(string name, ReadOnlySpan<char> plaintext)
    {
        using var activity = CacheDiagnostics.ActivitySource.StartActivity("ProtectedCache.Add");
        if (CacheDiagnostics.EnableSensitiveLogging)
            CacheDiagnostics.LogSensitiveOperation(activity, "ProtectedCache.Add",
                ("name", name), ("plaintextLength", plaintext.Length));

        try
        {
            if (!Cache.TryAdd(name, EncryptChars(plaintext)))
                throw new ArgumentException($"An item with the name '{name}' has already been added.", nameof(name));
        }
        catch (Exception ex)
        {
            CacheDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public void AddOrUpdate(string name, Span<byte> plaintext)
    {
        using var activity = CacheDiagnostics.ActivitySource.StartActivity("ProtectedCache.AddOrUpdate");
        if (CacheDiagnostics.EnableSensitiveLogging)
            CacheDiagnostics.LogSensitiveOperation(activity, "ProtectedCache.AddOrUpdate",
                ("name", name), ("plaintextLength", plaintext.Length));

        try
        {
            Cache[name] = Encrypt(plaintext);
        }
        catch (Exception ex)
        {
            CacheDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public void AddOrUpdate(string name, ReadOnlySpan<char> plaintext)
    {
        using var activity = CacheDiagnostics.ActivitySource.StartActivity("ProtectedCache.AddOrUpdate");
        if (CacheDiagnostics.EnableSensitiveLogging)
            CacheDiagnostics.LogSensitiveOperation(activity, "ProtectedCache.AddOrUpdate",
                ("name", name), ("plaintextLength", plaintext.Length));

        try
        {
            Cache[name] = EncryptChars(plaintext);
        }
        catch (Exception ex)
        {
            CacheDiagnostics.RecordException(activity, ex);
            throw;
        }
    }
}
