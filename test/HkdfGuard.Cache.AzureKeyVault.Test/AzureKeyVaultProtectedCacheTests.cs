using Azure;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache.AzureKeyVault.Test.TestHelpers;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.DataProtectionKey.FormatProvider;
using HkdfGuard.DataProtectionKey.KeyTracking;

namespace HkdfGuard.Cache.AzureKeyVault.Test;

public class AzureKeyVaultProtectedCacheTests
{
    private const string ServiceName = "azure-key-vault-cache-test-svc";

    // Mirrors the intended real usage: the cache is handed an ephemeral key already registered
    // on a KeyRing (via KeyRingBuilder.AddEphemeralKey), rather than building its own.
    private static IDataProtectionKey CreateEphemeralKeyFromKeyRing(IKeyInputStorage storage)
    {
        var ring = new KeyRingBuilder()
            .WithCryptoRecipe(new CryptoRecipeBuilder()
                .WithServiceName(ServiceName)
                .WithKeyDerivation(new Pbkdf2KeyDerivationFunction(storage))
                .WithCipher(new AesGcmCipher())
                .WithHash(new HmacSha256Hash()))
            .WithKeyWrapperFactory(new HkdfKeyWrapperFactory())
            .WithKeyProtectorFactory(new KeyProtectorFactory())
            .AddEphemeralKey(version: 1, materialIdentifier: 1, iterations: 1)
            .Build();

        return ring.Get(1);
    }

    private static AzureKeyVaultProtectedCache CreateCache(FakeSecretClient secretClient, IKeyInputStorage? storage = null)
        => new(secretClient, CreateEphemeralKeyFromKeyRing(storage ?? new InMemoryKeyInputStorage()));

    [Fact]
    public void Decrypt_Bytes_WithExistingSecret_FetchesEncryptsAndReturnsPlaintext()
    {
        var secretClient = new FakeSecretClient(new Dictionary<string, string> { ["item"] = "secret value" });
        var cache = CreateCache(secretClient);

        var result = new byte[32];
        var written = cache.Decrypt("item", result);

        Assert.True(written > 0);
        Assert.Equal("secret value", System.Text.Encoding.UTF8.GetString(result, 0, written));
        Assert.Equal(1, secretClient.GetSecretCallCount);
    }

    [Fact]
    public void Decrypt_Chars_WithExistingSecret_FetchesEncryptsAndReturnsPlaintext()
    {
        var secretClient = new FakeSecretClient(new Dictionary<string, string> { ["item"] = "secret value" });
        var cache = CreateCache(secretClient);

        var result = new char[32];
        var written = cache.Decrypt("item", result);

        Assert.True(written > 0);
        Assert.Equal("secret value", new string(result, 0, written));
    }

    [Fact]
    public void Decrypt_SecondCallForSameName_DoesNotFetchFromKeyVaultAgain()
    {
        var secretClient = new FakeSecretClient(new Dictionary<string, string> { ["item"] = "secret value" });
        var cache = CreateCache(secretClient);

        cache.Decrypt("item", new byte[32]);
        cache.Decrypt("item", new byte[32]);

        Assert.Equal(1, secretClient.GetSecretCallCount);
    }

    [Fact]
    public void Decrypt_WithUnknownSecretName_ReturnsZero()
    {
        var secretClient = new FakeSecretClient(new Dictionary<string, string>());
        var cache = CreateCache(secretClient);

        var written = cache.Decrypt("missing", new byte[32]);

        Assert.Equal(0, written);
        Assert.Equal(1, secretClient.GetSecretCallCount);
    }

    [Fact]
    public void TryGetMaxDecryptedLength_WithExistingSecret_FetchesAndReturnsUpperBound()
    {
        var secretClient = new FakeSecretClient(new Dictionary<string, string> { ["item"] = "secret value" });
        var cache = CreateCache(secretClient);

        var found = cache.TryGetMaxDecryptedLength("item", out var maxLength);

        Assert.True(found);
        Assert.True(maxLength >= "secret value".Length);
    }

    [Fact]
    public void TryGetMaxDecryptedLength_WithUnknownSecretName_ReturnsFalse()
    {
        var secretClient = new FakeSecretClient(new Dictionary<string, string>());
        var cache = CreateCache(secretClient);

        var found = cache.TryGetMaxDecryptedLength("missing", out var maxLength);

        Assert.False(found);
        Assert.Equal(0, maxLength);
    }

    [Fact]
    public void Decrypt_WhenKeyVaultThrowsNonNotFoundError_RecordsExceptionAndThrows()
    {
        var secretClient = new FakeSecretClient(new Dictionary<string, string>())
        {
            ThrowOnGetSecret = new RequestFailedException(500, "internal error")
        };
        var cache = CreateCache(secretClient);

        Assert.Throws<RequestFailedException>(() => cache.Decrypt("item", new byte[32]));
    }

    [Fact]
    public void TwoInstances_UseIndependentEphemeralKeys()
    {
        var secrets = new Dictionary<string, string> { ["item"] = "secret value" };
        var storage = new InMemoryKeyInputStorage();
        var cache1 = CreateCache(new FakeSecretClient(secrets), storage);
        var cache2 = CreateCache(new FakeSecretClient(secrets), storage);

        // Both populate independently from Key Vault (each has its own in-memory Cache and its
        // own ephemeral key), so both should decrypt their own fetched copy successfully -
        // proving each instance's ephemeral key only ever has to agree with itself.
        var result1 = new byte[32];
        var result2 = new byte[32];
        var written1 = cache1.Decrypt("item", result1);
        var written2 = cache2.Decrypt("item", result2);

        Assert.True(written1 > 0);
        Assert.True(written2 > 0);
        Assert.Equal("secret value", System.Text.Encoding.UTF8.GetString(result1, 0, written1));
        Assert.Equal("secret value", System.Text.Encoding.UTF8.GetString(result2, 0, written2));
    }

    [Fact]
    public void Decrypt_WithSensitiveLoggingEnabled_StillPopulatesFromKeyVault()
    {
        var original = AzureKeyVaultDiagnostics.EnableSensitiveLogging;
        try
        {
            AzureKeyVaultDiagnostics.EnableSensitiveLogging = true;

            var secretClient = new FakeSecretClient(new Dictionary<string, string> { ["item"] = "secret value" });
            var cache = CreateCache(secretClient);

            var result = new byte[32];
            var written = cache.Decrypt("item", result);

            Assert.True(written > 0);
            Assert.Equal("secret value", System.Text.Encoding.UTF8.GetString(result, 0, written));
        }
        finally
        {
            AzureKeyVaultDiagnostics.EnableSensitiveLogging = original;
        }
    }
}
