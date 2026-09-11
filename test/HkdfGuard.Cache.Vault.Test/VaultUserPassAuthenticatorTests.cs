using System.Net;
using System.Text;
using HkdfGuard.Cache.Vault.Test.TestHelpers;

namespace HkdfGuard.Cache.Vault.Test;

public class VaultUserPassAuthenticatorTests
{
    private static HttpClient CreateClient(FakeVaultHandler handler)
        => new(handler) { BaseAddress = new Uri("https://vault.example.com/") };

    [Fact]
    public void GetToken_PostsToCorrectPath_WithPasswordBody_AndReturnsEncryptedClientToken()
    {
        string? capturedBody = null;
        var handler = new FakeVaultHandler
        {
            OnSend = request =>
            {
                capturedBody = request.Content?.ReadAsStream() is { } stream
                    ? new StreamReader(stream).ReadToEnd()
                    : null;

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("""{"auth":{"client_token":"userpass-token"}}""", Encoding.UTF8, "application/json")
                };
            }
        };
        using var httpClient = CreateClient(handler);
        var keyRing = TestKeyRingFactory.Create();
        var authenticator = new VaultUserPassAuthenticator(TestKeyRingFactory.Encrypt(keyRing, "alice"), TestKeyRingFactory.Encrypt(keyRing, "hunter2"));

        var encrypted = authenticator.GetToken(httpClient, keyRing);

        Assert.Equal("userpass-token", TestKeyRingFactory.Decrypt(keyRing, encrypted));
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("v1/auth/userpass/login/alice", request.RequestUri!.PathAndQuery.TrimStart('/'));
        Assert.Contains("\"password\":\"hunter2\"", capturedBody);
    }

    [Fact]
    public void GetToken_WithEscapedTokenValue_StillDecryptsCorrectly()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                // e is a JSON-escaped 'e' - exercises the Utf8JsonReader
                // ValueIsEscaped/GetString fallback path rather than the raw ValueSpan fast path.
                Content = new StringContent("""{"auth":{"client_token":"token\u002Descaped"}}""", Encoding.UTF8, "application/json")
            }
        };
        using var httpClient = CreateClient(handler);
        var keyRing = TestKeyRingFactory.Create();
        var authenticator = new VaultUserPassAuthenticator(TestKeyRingFactory.Encrypt(keyRing, "alice"), TestKeyRingFactory.Encrypt(keyRing, "pw"));

        var encrypted = authenticator.GetToken(httpClient, keyRing);

        Assert.Equal("token-escaped", TestKeyRingFactory.Decrypt(keyRing, encrypted));
    }

    [Fact]
    public void GetToken_WithOtherFieldsPrecedingClientTokenInAuthObject_StillFindsIt()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                // A real Vault login response has several sibling fields alongside client_token
                // (renewable, lease_duration, ...) - this exercises skipping past those.
                Content = new StringContent(
                    """{"auth":{"renewable":true,"lease_duration":3600,"client_token":"tok-with-siblings"}}""",
                    Encoding.UTF8, "application/json")
            }
        };
        using var httpClient = CreateClient(handler);
        var keyRing = TestKeyRingFactory.Create();
        var authenticator = new VaultUserPassAuthenticator(TestKeyRingFactory.Encrypt(keyRing, "alice"), TestKeyRingFactory.Encrypt(keyRing, "pw"));

        var encrypted = authenticator.GetToken(httpClient, keyRing);

        Assert.Equal("tok-with-siblings", TestKeyRingFactory.Decrypt(keyRing, encrypted));
    }

    [Fact]
    public void GetToken_WithUsernameNeedingEscaping_EscapesUsernameInPath()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"auth":{"client_token":"t"}}""", Encoding.UTF8, "application/json")
            }
        };
        using var httpClient = CreateClient(handler);
        var keyRing = TestKeyRingFactory.Create();
        var authenticator = new VaultUserPassAuthenticator(TestKeyRingFactory.Encrypt(keyRing, "alice smith"), TestKeyRingFactory.Encrypt(keyRing, "pw"));

        authenticator.GetToken(httpClient, keyRing);

        var request = Assert.Single(handler.Requests);
        Assert.DoesNotContain(" ", request.RequestUri!.PathAndQuery);
    }

    [Fact]
    public void GetToken_WhenLoginFails_Throws()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => new HttpResponseMessage(HttpStatusCode.Unauthorized)
        };
        using var httpClient = CreateClient(handler);
        var keyRing = TestKeyRingFactory.Create();
        var authenticator = new VaultUserPassAuthenticator(TestKeyRingFactory.Encrypt(keyRing, "alice"), TestKeyRingFactory.Encrypt(keyRing, "wrong-password"));

        Assert.Throws<HttpRequestException>(() => authenticator.GetToken(httpClient, keyRing));
    }

    [Fact]
    public void GetToken_WhenAuthObjectMissingClientToken_ThrowsInvalidOperationException()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"auth":{}}""", Encoding.UTF8, "application/json")
            }
        };
        using var httpClient = CreateClient(handler);
        var keyRing = TestKeyRingFactory.Create();
        var authenticator = new VaultUserPassAuthenticator(TestKeyRingFactory.Encrypt(keyRing, "alice"), TestKeyRingFactory.Encrypt(keyRing, "pw"));

        Assert.Throws<InvalidOperationException>(() => authenticator.GetToken(httpClient, keyRing));
    }

    [Fact]
    public void GetToken_WhenAuthObjectMissingEntirely_ThrowsInvalidOperationException()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"lease_duration":0}""", Encoding.UTF8, "application/json")
            }
        };
        using var httpClient = CreateClient(handler);
        var keyRing = TestKeyRingFactory.Create();
        var authenticator = new VaultUserPassAuthenticator(TestKeyRingFactory.Encrypt(keyRing, "alice"), TestKeyRingFactory.Encrypt(keyRing, "pw"));

        Assert.Throws<InvalidOperationException>(() => authenticator.GetToken(httpClient, keyRing));
    }

    [Fact]
    public void GetToken_WhenClientTokenIsNotAString_ThrowsInvalidOperationException()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"auth":{"client_token":123}}""", Encoding.UTF8, "application/json")
            }
        };
        using var httpClient = CreateClient(handler);
        var keyRing = TestKeyRingFactory.Create();
        var authenticator = new VaultUserPassAuthenticator(TestKeyRingFactory.Encrypt(keyRing, "alice"), TestKeyRingFactory.Encrypt(keyRing, "pw"));

        Assert.Throws<InvalidOperationException>(() => authenticator.GetToken(httpClient, keyRing));
    }
}
