using HkdfGuard.DataProtectionKey.KeyTracking;

namespace HkdfGuard.Cache.Vault;

/// <summary>
/// Obtains an encrypted Vault token for a VaultProtectedCache to reveal and send as the
/// X-Vault-Token header on its requests. The extension point for adding new Vault auth methods
/// later (AppRole, AWS IAM, Kubernetes, LDAP, ...) without changing VaultProtectedCache itself -
/// implement this interface and pass an instance to VaultProtectedCache's constructor. Any
/// credential an implementation holds (a token, a username/password, ...) should likewise be
/// accepted and stored already encrypted (as a VaultCredentialProtector-formatted string),
/// revealed only transiently inside GetToken right before it's actually needed.
/// </summary>
public interface IVaultAuthenticator
{
    /// <summary>
    /// Returns a Vault token as a version-tagged formatted string (see
    /// VaultCredentialProtector), performing whatever login call (if any) this auth method
    /// needs. Called lazily, once, the first time VaultProtectedCache needs a token - the
    /// plaintext token itself is never returned, so it never has to be held by anything beyond
    /// this call. Formatting the result with the key version that encrypted it (rather than
    /// returning raw encrypted bytes) means the token stays decryptable later regardless of
    /// whatever else gets added to keyRing in the meantime.
    /// </summary>
    /// <param name="httpClient">
    /// The same HttpClient VaultProtectedCache uses for its own requests - BaseAddress is
    /// already Vault's address. An auth method that needs mutual TLS (e.g.
    /// VaultTlsCertificateAuthenticator) relies on this client's handler already carrying the
    /// client certificate; this interface has no way to configure that itself.
    /// </param>
    /// <param name="keyRing">Supplies the current key used to encrypt the token before it's returned</param>
    /// <returns>The Vault token, encrypted and formatted</returns>
    string GetToken(HttpClient httpClient, KeyRing keyRing);
}
