using System.Net;
using System.Text;
using HkdfGuard.Cache.Vault.Test.TestHelpers;

namespace HkdfGuard.Cache.Vault.Test;

public class VaultTlsCertificateAuthenticatorTests
{
    private static HttpClient CreateClient(FakeVaultHandler handler)
        => new(handler) { BaseAddress = new Uri("https://vault.example.com/") };

    [Fact]
    public void GetToken_PostsToCorrectPath_WithNoBody_AndReturnsEncryptedClientToken()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = request => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"auth":{"client_token":"cert-token"}}""", Encoding.UTF8, "application/json")
            }
        };
        using var httpClient = CreateClient(handler);
        var keyRing = TestKeyRingFactory.Create();
        var authenticator = new VaultTlsCertificateAuthenticator();

        var encrypted = authenticator.GetToken(httpClient, keyRing);

        Assert.Equal("cert-token", TestKeyRingFactory.Decrypt(keyRing, encrypted));
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("/v1/auth/cert/login", request.RequestUri!.PathAndQuery);
        Assert.Null(request.Content);
    }

    [Fact]
    public void GetToken_WhenLoginFails_Throws()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => new HttpResponseMessage(HttpStatusCode.Forbidden)
        };
        using var httpClient = CreateClient(handler);
        var keyRing = TestKeyRingFactory.Create();
        var authenticator = new VaultTlsCertificateAuthenticator();

        Assert.Throws<HttpRequestException>(() => authenticator.GetToken(httpClient, keyRing));
    }
}
