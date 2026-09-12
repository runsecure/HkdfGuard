using Azure;
using Azure.Security.KeyVault.Secrets;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache;

namespace HkdfGuard.Cache.AzureKeyVault;

/// <summary>
/// A ProtectedCacheBase pulled through from Azure Key Vault: Key Vault secrets are fetched as
/// plaintext (Key Vault is trusted for confidentiality/access control on its own) on a cache
/// miss, then immediately encrypted into Cache via dataProtectionKey, so nothing here ever holds
/// Key Vault plaintext beyond the duration of a single TryPopulate call. dataProtectionKey is
/// expected to be an ephemeral key already registered on a KeyRing (e.g. via
/// KeyRingBuilder.AddEphemeralKey/HkdfGuardOptions.EphemeralKeys) rather than one this class
/// builds itself - its lifetime, rotation, and sharing across caches stay a property of that
/// KeyRing. Because that key is ephemeral (freshly random per KeyRing instance), this is still a
/// read-through cache for the KeyRing's lifetime only - it never writes anything back to Key
/// Vault, and its encrypted values can't be decrypted after that KeyRing is gone; only Key Vault
/// itself is a durable source of truth.
/// </summary>
public sealed class AzureKeyVaultProtectedCache(SecretClient secretClient, IDataProtectionKey dataProtectionKey)
    : ProtectedCacheBase(dataProtectionKey)
{
    /// <inheritdoc/>
    protected override bool TryPopulate(string name)
    {
        using var activity = AzureKeyVaultDiagnostics.ActivitySource.StartActivity("AzureKeyVaultProtectedCache.TryPopulate");
        if (AzureKeyVaultDiagnostics.EnableSensitiveLogging)
            AzureKeyVaultDiagnostics.LogSensitiveOperation(activity, "AzureKeyVaultProtectedCache.TryPopulate", ("name", name));

        try
        {
            var secret = secretClient.GetSecret(name);

            // secret.Value.Value is an immutable string owned by the Key Vault SDK, so it can't be
            // zeroed itself - copy it into a caller-owned Span<char> that EncryptChars can zero
            // once it's done encrypting.
            Span<char> secretChars = stackalloc char[secret.Value.Value.Length];
            secret.Value.Value.AsSpan().CopyTo(secretChars);
            Cache[name] = EncryptChars(secretChars);
            return true;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return false;
        }
        catch (Exception ex)
        {
            AzureKeyVaultDiagnostics.RecordException(activity, ex);
            throw;
        }
    }
}
