using Amazon.SecretsManager.Model;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache.AwsSecretsManager.Test.TestHelpers;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.DataProtectionKey.Key;

namespace HkdfGuard.Cache.AwsSecretsManager.Test;

public class AwsSecretsManagerProtectedCacheTests
{
    private const string ServiceName = "aws-secrets-manager-cache-test-svc";

    private static IKeySpec BuildSpec(IKeyInputStorage storage)
        => new CryptoRecipeBuilder()
            .WithServiceName(ServiceName)
            .WithKeyDerivation(new Pbkdf2KeyDerivationFunction(storage))
            .WithCipher(new AesGcmCipher())
            .WithHash(new HmacSha256Hash())
            .WithMaterialIdentifier(1)
            .WithIterations(1)
            .Build();

    private static AwsSecretsManagerProtectedCache CreateCache(FakeSecretsManagerClient client, IKeyInputStorage? storage = null)
    {
        var dataProtectionKey = new KeyWrappedDataProtectionKey(
            new FakeKeyWrapper(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)), new AesGcmCipher());
        return new AwsSecretsManagerProtectedCache(client, dataProtectionKey);
    }

    [Fact]
    public void TryDecrypt_Bytes_WithExistingSecret_FetchesEncryptsAndReturnsPlaintext()
    {
        var client = new FakeSecretsManagerClient(new Dictionary<string, string> { ["item"] = "secret value" });
        var cache = CreateCache(client);

        var result = new byte[32];
        var found = cache.TryDecrypt("item", result, out var written);

        Assert.True(found);
        Assert.Equal("secret value", System.Text.Encoding.UTF8.GetString(result, 0, written));
        Assert.Equal(1, client.GetSecretValueCallCount);
    }

    [Fact]
    public void TryDecrypt_Chars_WithExistingSecret_FetchesEncryptsAndReturnsPlaintext()
    {
        var client = new FakeSecretsManagerClient(new Dictionary<string, string> { ["item"] = "secret value" });
        var cache = CreateCache(client);

        var result = new char[32];
        var found = cache.TryDecrypt("item", result, out var written);

        Assert.True(found);
        Assert.Equal("secret value", new string(result, 0, written));
    }

    [Fact]
    public void TryDecrypt_SecondCallForSameName_DoesNotFetchFromAwsAgain()
    {
        var client = new FakeSecretsManagerClient(new Dictionary<string, string> { ["item"] = "secret value" });
        var cache = CreateCache(client);

        cache.TryDecrypt("item", new byte[32], out _);
        cache.TryDecrypt("item", new byte[32], out _);

        Assert.Equal(1, client.GetSecretValueCallCount);
    }

    [Fact]
    public void TryDecrypt_WithUnknownSecretId_ReturnsFalse()
    {
        var client = new FakeSecretsManagerClient(new Dictionary<string, string>());
        var cache = CreateCache(client);

        var found = cache.TryDecrypt("missing", new byte[32], out var written);

        Assert.False(found);
        Assert.Equal(0, written);
        Assert.Equal(1, client.GetSecretValueCallCount);
    }

    [Fact]
    public void TryGetMaxDecryptedLength_WithExistingSecret_FetchesAndReturnsUpperBound()
    {
        var client = new FakeSecretsManagerClient(new Dictionary<string, string> { ["item"] = "secret value" });
        var cache = CreateCache(client);

        var found = cache.TryGetMaxDecryptedLength("item", out var maxLength);

        Assert.True(found);
        Assert.True(maxLength >= "secret value".Length);
    }

    [Fact]
    public void TryGetMaxDecryptedLength_WithUnknownSecretId_ReturnsFalse()
    {
        var client = new FakeSecretsManagerClient(new Dictionary<string, string>());
        var cache = CreateCache(client);

        var found = cache.TryGetMaxDecryptedLength("missing", out var maxLength);

        Assert.False(found);
        Assert.Equal(0, maxLength);
    }

    [Fact]
    public void TryDecrypt_WhenSecretHasNoSecretString_ThrowsNotSupportedException()
    {
        var client = new FakeSecretsManagerClient(new Dictionary<string, string>())
        {
            OnGetSecretValue = request => new GetSecretValueResponse { Name = request.SecretId, SecretString = null }
        };
        var cache = CreateCache(client);

        Assert.Throws<NotSupportedException>(() => cache.TryDecrypt("item", new byte[32], out _));
    }

    [Fact]
    public void TryDecrypt_WhenAwsThrowsUnexpectedError_RecordsExceptionAndThrows()
    {
        var client = new FakeSecretsManagerClient(new Dictionary<string, string>())
        {
            ThrowOnGetSecretValue = new InternalServiceErrorException("internal error")
        };
        var cache = CreateCache(client);

        Assert.Throws<InternalServiceErrorException>(() => cache.TryDecrypt("item", new byte[32], out _));
    }

    [Fact]
    public void TwoInstances_UseIndependentDataProtectionKeys()
    {
        var secrets = new Dictionary<string, string> { ["item"] = "secret value" };
        var cache1 = CreateCache(new FakeSecretsManagerClient(secrets));
        var cache2 = CreateCache(new FakeSecretsManagerClient(secrets));

        var result1 = new byte[32];
        var result2 = new byte[32];
        var found1 = cache1.TryDecrypt("item", result1, out var written1);
        var found2 = cache2.TryDecrypt("item", result2, out var written2);

        Assert.True(found1);
        Assert.True(found2);
        Assert.Equal("secret value", System.Text.Encoding.UTF8.GetString(result1, 0, written1));
        Assert.Equal("secret value", System.Text.Encoding.UTF8.GetString(result2, 0, written2));
    }

    [Fact]
    public void TryDecrypt_WithSensitiveLoggingEnabled_StillPopulatesFromAws()
    {
        var original = AwsSecretsManagerDiagnostics.EnableSensitiveLogging;
        try
        {
            AwsSecretsManagerDiagnostics.EnableSensitiveLogging = true;

            var client = new FakeSecretsManagerClient(new Dictionary<string, string> { ["item"] = "secret value" });
            var cache = CreateCache(client);

            var result = new byte[32];
            var found = cache.TryDecrypt("item", result, out var written);

            Assert.True(found);
            Assert.Equal("secret value", System.Text.Encoding.UTF8.GetString(result, 0, written));
        }
        finally
        {
            AwsSecretsManagerDiagnostics.EnableSensitiveLogging = original;
        }
    }
}
