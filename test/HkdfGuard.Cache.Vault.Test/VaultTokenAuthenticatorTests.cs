using HkdfGuard.Cache.Vault.Test.TestHelpers;

namespace HkdfGuard.Cache.Vault.Test;

public class VaultTokenAuthenticatorTests
{
    [Fact]
    public void GetToken_ReturnsTokenReEncryptedWithKeyRingsCurrentKey_WithoutAnyHttpCall()
    {
        var handler = new FakeVaultHandler();
        using var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://vault.example.com/") };
        var keyRing = TestKeyRingFactory.Create();
        var encryptedToken = TestKeyRingFactory.Encrypt(keyRing, "my-token");
        var authenticator = new VaultTokenAuthenticator(encryptedToken);

        var result = authenticator.GetToken(httpClient, keyRing);

        Assert.Empty(handler.Requests);
        Assert.Equal("my-token", TestKeyRingFactory.Decrypt(keyRing, result));
    }
}
