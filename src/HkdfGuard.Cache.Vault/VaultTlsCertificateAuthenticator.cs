using HkdfGuard.DataProtectionKey.KeyTracking;

namespace HkdfGuard.Cache.Vault;

/// <summary>
/// IVaultAuthenticator using Vault's TLS certificate auth method (POST auth/cert/login).
/// Authentication actually happens during the TLS handshake itself - this relies entirely on the
/// HttpClient passed to GetToken already being configured (via its handler, e.g.
/// HttpClientHandler.ClientCertificates) with the client certificate Vault's cert auth backend
/// is configured to trust. This class has no way to attach a certificate to an HttpClient after
/// the fact, so that configuration must happen wherever the HttpClient itself is constructed.
/// </summary>
public sealed class VaultTlsCertificateAuthenticator : IVaultAuthenticator
{
    /// <inheritdoc/>
    public string GetToken(HttpClient httpClient, KeyRing keyRing)
        => VaultLoginClient.Login(httpClient, "v1/auth/cert/login", content: null, "VaultTlsCertificateAuthenticator.GetToken", keyRing);
}
