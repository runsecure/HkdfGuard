using System.Net;
using System.Text;
using System.Text.Json;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache.Vault.Test.TestHelpers;
using HkdfGuard.DataProtectionKey.KeyTracking;

namespace HkdfGuard.Cache.Vault.Test;

public class VaultProtectedCacheTests
{
    // The cache's own dataProtectionKey (for cache values) and the authenticator's/cache's
    // keyRing (for the Vault token) both come from the SAME KeyRing here, matching the intended
    // real usage - a single ephemeral key already registered on a KeyRing (via
    // KeyRingBuilder.AddEphemeralKey), reused across both purposes.
    private static VaultProtectedCache CreateCache(
        FakeVaultHandler handler, IVaultAuthenticator? authenticator = null, IKeyInputStorage? storage = null,
        TimeSpan? tokenLifetime = null)
    {
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://vault.example.com/") };
        var keyRing = TestKeyRingFactory.Create(storage);
        return new VaultProtectedCache(
            httpClient,
            authenticator ?? new FakeAuthenticator("test-token"),
            keyRing,
            keyRing.Get(1),
            tokenLifetime);
    }

    private static HttpResponseMessage JsonResponse(HttpStatusCode status, string json)
        => new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    [Fact]
    public void TryDecrypt_Bytes_WithExistingSecret_FetchesEncryptsAndReturnsPlaintext()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => JsonResponse(HttpStatusCode.OK, """{"data":{"username":"admin","password":"hunter2"}}""")
        };
        var cache = CreateCache(handler);

        var result = new byte[256];
        var found = cache.TryDecrypt("secret/data/my-app", result, out var written);

        Assert.True(found);
        var json = Encoding.UTF8.GetString(result, 0, written);
        using var document = JsonDocument.Parse(json);
        Assert.Equal("admin", document.RootElement.GetProperty("username").GetString());
        Assert.Equal("hunter2", document.RootElement.GetProperty("password").GetString());
    }

    [Fact]
    public void TryDecrypt_Chars_WithExistingSecret_FetchesEncryptsAndReturnsPlaintext()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => JsonResponse(HttpStatusCode.OK, """{"data":{"apiKey":"sk-live-abc123"}}""")
        };
        var cache = CreateCache(handler);

        var result = new char[256];
        var found = cache.TryDecrypt("secret/data/api", result, out var written);

        Assert.True(found);
        using var document = JsonDocument.Parse(new string(result, 0, written));
        Assert.Equal("sk-live-abc123", document.RootElement.GetProperty("apiKey").GetString());
    }

    [Fact]
    public void TryDecrypt_RequestsExpectedPath_AndAttachesVaultTokenHeader()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => JsonResponse(HttpStatusCode.OK, """{"data":{"k":"v"}}""")
        };
        var authenticator = new FakeAuthenticator("my-vault-token");
        var cache = CreateCache(handler, authenticator);

        cache.TryDecrypt("secret/data/my-app", new byte[256], out _);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal("/v1/secret/data/my-app", request.RequestUri!.PathAndQuery);
        Assert.Equal("my-vault-token", Assert.Single(request.Headers.GetValues("X-Vault-Token")));
    }

    [Fact]
    public void TryDecrypt_SecondCallForSameName_DoesNotFetchFromVaultAgain()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => JsonResponse(HttpStatusCode.OK, """{"data":{"k":"v"}}""")
        };
        var cache = CreateCache(handler);

        cache.TryDecrypt("secret/data/my-app", new byte[256], out _);
        cache.TryDecrypt("secret/data/my-app", new byte[256], out _);

        Assert.Single(handler.Requests);
    }

    [Fact]
    public void TryDecrypt_AuthenticatesOnlyOnce_AcrossMultipleDifferentSecrets()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => JsonResponse(HttpStatusCode.OK, """{"data":{"k":"v"}}""")
        };
        var authenticator = new FakeAuthenticator("token");
        var cache = CreateCache(handler, authenticator);

        cache.TryDecrypt("secret/data/one", new byte[256], out _);
        cache.TryDecrypt("secret/data/two", new byte[256], out _);

        Assert.Equal(1, authenticator.GetTokenCallCount);
    }

    [Fact]
    public void TryDecrypt_WithCustomTokenLifetime_ReusesTokenWithinThatWindow()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => JsonResponse(HttpStatusCode.OK, """{"data":{"k":"v"}}""")
        };
        var authenticator = new FakeAuthenticator("token");
        var cache = CreateCache(handler, authenticator, tokenLifetime: TimeSpan.FromMinutes(10));

        cache.TryDecrypt("secret/data/one", new byte[256], out _);
        cache.TryDecrypt("secret/data/two", new byte[256], out _);

        Assert.Equal(1, authenticator.GetTokenCallCount);
    }

    [Fact]
    public void TryDecrypt_AfterTokenLifetimeElapses_ReAuthenticates()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => JsonResponse(HttpStatusCode.OK, """{"data":{"k":"v"}}""")
        };
        var authenticator = new FakeAuthenticator("token");
        // Zero lifetime means the very next check (even nanoseconds later) is already expired.
        var cache = CreateCache(handler, authenticator, tokenLifetime: TimeSpan.Zero);

        cache.TryDecrypt("secret/data/one", new byte[256], out _);
        cache.TryDecrypt("secret/data/two", new byte[256], out _);

        Assert.Equal(2, authenticator.GetTokenCallCount);
    }

    [Fact]
    public void TryDecrypt_WithUnknownSecretPath_ReturnsFalse()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => new HttpResponseMessage(HttpStatusCode.NotFound)
        };
        var cache = CreateCache(handler);

        var found = cache.TryDecrypt("secret/data/missing", new byte[256], out var written);

        Assert.False(found);
        Assert.Equal(0, written);
    }

    [Fact]
    public void TryGetMaxDecryptedLength_WithExistingSecret_FetchesAndReturnsUpperBound()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => JsonResponse(HttpStatusCode.OK, """{"data":{"k":"a value"}}""")
        };
        var cache = CreateCache(handler);

        var found = cache.TryGetMaxDecryptedLength("secret/data/my-app", out var maxLength);

        Assert.True(found);
        Assert.True(maxLength > 0);
    }

    [Fact]
    public void TryGetMaxDecryptedLength_WithUnknownSecretPath_ReturnsFalse()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => new HttpResponseMessage(HttpStatusCode.NotFound)
        };
        var cache = CreateCache(handler);

        var found = cache.TryGetMaxDecryptedLength("secret/data/missing", out var maxLength);

        Assert.False(found);
        Assert.Equal(0, maxLength);
    }

    [Fact]
    public void TryDecrypt_WhenVaultReturnsServerError_ThrowsHttpRequestException()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => new HttpResponseMessage(HttpStatusCode.InternalServerError)
        };
        var cache = CreateCache(handler);

        Assert.Throws<HttpRequestException>(() => cache.TryDecrypt("secret/data/my-app", new byte[256], out _));
    }

    [Fact]
    public void TryDecrypt_WithSensitiveLoggingEnabled_StillPopulatesFromVault()
    {
        var original = VaultDiagnostics.EnableSensitiveLogging;
        try
        {
            VaultDiagnostics.EnableSensitiveLogging = true;

            var handler = new FakeVaultHandler
            {
                OnSend = _ => JsonResponse(HttpStatusCode.OK, """{"data":{"k":"v"}}""")
            };
            var cache = CreateCache(handler);

            var found = cache.TryDecrypt("secret/data/my-app", new byte[256], out _);

            Assert.True(found);
        }
        finally
        {
            VaultDiagnostics.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public void TwoInstances_UseIndependentEphemeralKeys()
    {
        var handler1 = new FakeVaultHandler { OnSend = _ => JsonResponse(HttpStatusCode.OK, """{"data":{"k":"v"}}""") };
        var handler2 = new FakeVaultHandler { OnSend = _ => JsonResponse(HttpStatusCode.OK, """{"data":{"k":"v"}}""") };
        var storage = new InMemoryKeyInputStorage();
        var cache1 = CreateCache(handler1, storage: storage);
        var cache2 = CreateCache(handler2, storage: storage);

        var found1 = cache1.TryDecrypt("secret/data/my-app", new byte[256], out var written1);
        var found2 = cache2.TryDecrypt("secret/data/my-app", new byte[256], out var written2);

        Assert.True(found1);
        Assert.True(found2);
    }

    [Fact]
    public void Ping_WhenVaultReturns200_ReturnsTrue()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => JsonResponse(HttpStatusCode.OK, """{"initialized":true,"sealed":false,"standby":false}""")
        };
        var cache = CreateCache(handler);

        Assert.True(cache.Ping());
    }

    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.NotImplemented)]
    public void Ping_WhenVaultReturnsNon200_ReturnsFalse(HttpStatusCode status)
    {
        var handler = new FakeVaultHandler { OnSend = _ => new HttpResponseMessage(status) };
        var cache = CreateCache(handler);

        Assert.False(cache.Ping());
    }

    [Fact]
    public void Ping_WhenConnectionFails_ReturnsFalseRatherThanThrowing()
    {
        var handler = new FakeVaultHandler { OnSend = _ => throw new HttpRequestException("connection refused") };
        var cache = CreateCache(handler);

        Assert.False(cache.Ping());
    }

    [Fact]
    public void Ping_WhenAnUnexpectedExceptionOccurs_RecordsExceptionAndRethrows()
    {
        var handler = new FakeVaultHandler { OnSend = _ => throw new InvalidOperationException("unexpected") };
        var cache = CreateCache(handler);

        Assert.Throws<InvalidOperationException>(() => cache.Ping());
    }

    [Fact]
    public void Ping_RequestsExpectedPath_AndDoesNotAttachVaultTokenHeader()
    {
        var handler = new FakeVaultHandler
        {
            OnSend = _ => JsonResponse(HttpStatusCode.OK, """{"initialized":true}""")
        };
        var authenticator = new FakeAuthenticator("token");
        var cache = CreateCache(handler, authenticator);

        cache.Ping();

        var request = Assert.Single(handler.Requests);
        Assert.Equal("/v1/sys/health", request.RequestUri!.PathAndQuery);
        Assert.False(request.Headers.Contains("X-Vault-Token"));
        Assert.Equal(0, authenticator.GetTokenCallCount);
    }
}
