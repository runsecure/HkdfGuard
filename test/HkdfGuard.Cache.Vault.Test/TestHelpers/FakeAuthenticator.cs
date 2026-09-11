using HkdfGuard.DataProtectionKey.KeyTracking;

namespace HkdfGuard.Cache.Vault.Test.TestHelpers;

/// <summary>
/// An IVaultAuthenticator that protects a fixed token via an IDataProtector bound to keyRing and
/// counts calls - lets tests assert VaultProtectedCache authenticates only when it needs to
/// (once, then again only after expiry) rather than on every request, and that the token it
/// reveals downstream round-trips correctly.
/// </summary>
internal sealed class FakeAuthenticator(string token) : IVaultAuthenticator
{
    public int GetTokenCallCount { get; private set; }

    public string GetToken(HttpClient httpClient, KeyRing keyRing)
    {
        GetTokenCallCount++;
        return keyRing.CreateProtector(VaultProtectedCache.ProtectorPurpose).Encrypt(token.AsSpan());
    }
}
