using HkdfGuard.DataProtectionKey.KeyTracking;

namespace HkdfGuard.Cache.Vault;

/// <summary>
/// IVaultAuthenticator backed by an already-obtained Vault token - performs no login call.
/// encryptedToken is assumed to already be a formatted, encrypted value (produced by an
/// IDataProtector bound to VaultProtectedCache.ProtectorPurpose, e.g. via the same KeyRing at
/// setup time) rather than held as plaintext; GetToken reveals it only transiently, into a
/// stackalloc'd buffer, right before re-protecting it for return - re-keying it to whatever's
/// current now if rotation happened since encryptedToken was produced.
/// </summary>
public sealed class VaultTokenAuthenticator(string encryptedToken) : IVaultAuthenticator
{
    /// <inheritdoc/>
    public string GetToken(HttpClient httpClient, KeyRing keyRing)
    {
        var protector = keyRing.CreateProtector(VaultProtectedCache.ProtectorPurpose);

        Span<char> tokenChars = stackalloc char[protector.GetMaxDecryptedLength(encryptedToken)];
        try
        {
            var written = protector.Decrypt(encryptedToken, tokenChars);
            return protector.Encrypt(tokenChars[..written]);
        }
        finally
        {
            tokenChars.Clear();
        }
    }
}
