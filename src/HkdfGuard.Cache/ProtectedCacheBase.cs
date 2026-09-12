using System.Collections.Concurrent;
using System.Text;
using HkdfGuard.Abstractions;
using HkdfGuard.Core.Utilities;

namespace HkdfGuard.Cache;

/// <summary>
/// Shared IProtectedReadOnlyCache plumbing for every cache in this library: a single
/// IDataProtectionKey, a ConcurrentDictionary&lt;string, byte[]&gt; of encrypted bytes keyed
/// case-insensitively (OrdinalIgnoreCase), and the encrypt/decrypt/telemetry logic every
/// concrete cache needs. Decrypt/TryGetMaxDecryptedLength fall back to TryPopulate on a miss
/// before giving up - the default implementation here just returns false (nothing to pull from),
/// but a subclass backed by an external source (e.g. a remote secret store) overrides it to fetch
/// the plaintext value and encrypt it into Cache on demand, so nothing here ever holds plaintext
/// beyond the duration of a single call.
/// </summary>
public abstract class ProtectedCacheBase(IDataProtectionKey dataProtectionKey) : IProtectedReadOnlyCache
{
    /// <summary>
    /// The encrypted values this cache holds, keyed case-insensitively. Protected so concrete
    /// caches (e.g. ProtectedCache's Add/AddOrUpdate) can populate it directly.
    /// </summary>
    protected readonly ConcurrentDictionary<string, byte[]> Cache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Called when name isn't already in Cache, before Decrypt/TryGetMaxDecryptedLength give
    /// up and return false. The default implementation does nothing - override to pull a value in
    /// from an external source and populate Cache (e.g. via Encrypt/EncryptChars) before
    /// returning true.
    /// </summary>
    /// <param name="name">The name that was missing from Cache</param>
    /// <returns>True if name was successfully populated into Cache as a result of this call</returns>
    protected virtual bool TryPopulate(string name) => false;

    /// <inheritdoc/>
    public int Decrypt(string name, Span<byte> result)
    {
        using var activity = CacheDiagnostics.ActivitySource.StartActivity($"{GetType().Name}.Decrypt");
        if (CacheDiagnostics.EnableSensitiveLogging)
            CacheDiagnostics.LogSensitiveOperation(activity, $"{GetType().Name}.Decrypt", ("name", name));

        try
        {
            if (!TryGetEncrypted(name, out var encrypted))
                return 0;

            return dataProtectionKey.Decrypt(encrypted, result);
        }
        catch (Exception ex)
        {
            CacheDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public int Decrypt(string name, Span<char> result)
    {
        using var activity = CacheDiagnostics.ActivitySource.StartActivity($"{GetType().Name}.Decrypt");
        if (CacheDiagnostics.EnableSensitiveLogging)
            CacheDiagnostics.LogSensitiveOperation(activity, $"{GetType().Name}.Decrypt", ("name", name));

        try
        {
            if (!TryGetEncrypted(name, out var encrypted))
                return 0;

            // AEAD ciphertext is always at least as long as the plaintext it encloses, so
            // encrypted.Length is a safe upper bound for the decrypted UTF8 byte count.
            Span<byte> plaintextBytes = stackalloc byte[encrypted.Length];
            try
            {
                var decryptedLength = dataProtectionKey.Decrypt(encrypted, plaintextBytes);
                return Encoding.UTF8.GetChars(plaintextBytes[..decryptedLength], result);
            }
            finally
            {
                ArrayUtility.ZeroMemory(plaintextBytes);
            }
        }
        catch (Exception ex)
        {
            CacheDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public bool TryGetMaxDecryptedLength(string name, out int maxLength)
    {
        if (TryGetEncrypted(name, out var encrypted))
        {
            maxLength = encrypted.Length;
            return true;
        }

        maxLength = 0;
        return false;
    }

    private bool TryGetEncrypted(string name, out byte[] encrypted)
    {
        if (Cache.TryGetValue(name, out encrypted!))
            return true;

        if (TryPopulate(name) && Cache.TryGetValue(name, out encrypted!))
            return true;

        encrypted = null!;
        return false;
    }

    /// <summary>
    /// Encrypts plaintext through this cache's IDataProtectionKey.
    /// </summary>
    protected byte[] Encrypt(Span<byte> plaintext) => dataProtectionKey.Encrypt(plaintext);

    /// <summary>
    /// Encrypts plaintext (as UTF8 bytes) through this cache's IDataProtectionKey. plaintext is
    /// zeroed as a side effect - callers that only hold a string must copy it into a caller-owned
    /// Span&lt;char&gt; (e.g. via stackalloc) first, since a string's own backing buffer can't be
    /// safely cleared.
    /// </summary>
    protected byte[] EncryptChars(Span<char> plaintext)
    {
        var plaintextBytes = new byte[Encoding.UTF8.GetByteCount(plaintext)];
        try
        {
            Encoding.UTF8.GetBytes(plaintext, plaintextBytes);
            return dataProtectionKey.Encrypt(plaintextBytes);
        }
        finally
        {
            ArrayUtility.ZeroMemory(plaintext);
        }
    }
}
