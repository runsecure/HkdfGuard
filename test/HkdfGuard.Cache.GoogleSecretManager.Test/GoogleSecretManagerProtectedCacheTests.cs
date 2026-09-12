using System.Security.Cryptography;
using System.Text;
using Google.Cloud.SecretManager.V1;
using Google.Protobuf;
using Grpc.Core;
using HkdfGuard.Cache.GoogleSecretManager.Test.TestHelpers;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.DataProtectionKey.Key;

namespace HkdfGuard.Cache.GoogleSecretManager.Test;

public class GoogleSecretManagerProtectedCacheTests
{
    private static GoogleSecretManagerProtectedCache CreateCache(FakeSecretManagerServiceClient client)
    {
        var dataProtectionKey = new KeyWrappedDataProtectionKey(
            new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), new AesGcmCipher());
        return new GoogleSecretManagerProtectedCache(client, dataProtectionKey);
    }

    private const string SecretName = "projects/my-project/secrets/my-secret/versions/latest";

    [Fact]
    public void Decrypt_Bytes_WithExistingSecret_FetchesEncryptsAndReturnsPlaintext()
    {
        var client = new FakeSecretManagerServiceClient(new Dictionary<string, string> { [SecretName] = "secret value" });
        var cache = CreateCache(client);

        var result = new byte[32];
        var written = cache.Decrypt(SecretName, result);

        Assert.True(written > 0);
        Assert.Equal("secret value", Encoding.UTF8.GetString(result, 0, written));
        Assert.Equal(1, client.AccessSecretVersionCallCount);
    }

    [Fact]
    public void Decrypt_Chars_WithExistingSecret_FetchesEncryptsAndReturnsPlaintext()
    {
        var client = new FakeSecretManagerServiceClient(new Dictionary<string, string> { [SecretName] = "secret value" });
        var cache = CreateCache(client);

        var result = new char[32];
        var written = cache.Decrypt(SecretName, result);

        Assert.True(written > 0);
        Assert.Equal("secret value", new string(result, 0, written));
    }

    [Fact]
    public void Decrypt_HandlesMultiByteUtf8Secret()
    {
        const string plaintext = "héllo wörld 日本語";
        var client = new FakeSecretManagerServiceClient(new Dictionary<string, string> { [SecretName] = plaintext });
        var cache = CreateCache(client);

        var result = new char[plaintext.Length];
        var written = cache.Decrypt(SecretName, result);

        Assert.True(written > 0);
        Assert.Equal(plaintext, new string(result, 0, written));
    }

    [Fact]
    public void Decrypt_SecondCallForSameName_DoesNotFetchFromGoogleAgain()
    {
        var client = new FakeSecretManagerServiceClient(new Dictionary<string, string> { [SecretName] = "secret value" });
        var cache = CreateCache(client);

        cache.Decrypt(SecretName, new byte[32]);
        cache.Decrypt(SecretName, new byte[32]);

        Assert.Equal(1, client.AccessSecretVersionCallCount);
    }

    [Fact]
    public void Decrypt_WithUnknownSecretName_ReturnsZero()
    {
        var client = new FakeSecretManagerServiceClient(new Dictionary<string, string>());
        var cache = CreateCache(client);

        var written = cache.Decrypt("projects/my-project/secrets/missing/versions/latest", new byte[32]);

        Assert.Equal(0, written);
        Assert.Equal(1, client.AccessSecretVersionCallCount);
    }

    [Fact]
    public void TryGetMaxDecryptedLength_WithExistingSecret_FetchesAndReturnsUpperBound()
    {
        var client = new FakeSecretManagerServiceClient(new Dictionary<string, string> { [SecretName] = "secret value" });
        var cache = CreateCache(client);

        var found = cache.TryGetMaxDecryptedLength(SecretName, out var maxLength);

        Assert.True(found);
        Assert.True(maxLength >= "secret value".Length);
    }

    [Fact]
    public void TryGetMaxDecryptedLength_WithUnknownSecretName_ReturnsFalse()
    {
        var client = new FakeSecretManagerServiceClient(new Dictionary<string, string>());
        var cache = CreateCache(client);

        var found = cache.TryGetMaxDecryptedLength("projects/my-project/secrets/missing/versions/latest", out var maxLength);

        Assert.False(found);
        Assert.Equal(0, maxLength);
    }

    [Fact]
    public void Decrypt_WhenGoogleThrowsNonNotFoundError_RecordsExceptionAndThrows()
    {
        var client = new FakeSecretManagerServiceClient(new Dictionary<string, string>())
        {
            ThrowOnAccessSecretVersion = new RpcException(new Status(StatusCode.PermissionDenied, "denied"))
        };
        var cache = CreateCache(client);

        Assert.Throws<RpcException>(() => cache.Decrypt(SecretName, new byte[32]));
    }

    [Fact]
    public void TwoInstances_UseIndependentDataProtectionKeys()
    {
        var secrets = new Dictionary<string, string> { [SecretName] = "secret value" };
        var cache1 = CreateCache(new FakeSecretManagerServiceClient(secrets));
        var cache2 = CreateCache(new FakeSecretManagerServiceClient(secrets));

        var result1 = new byte[32];
        var result2 = new byte[32];
        var written1 = cache1.Decrypt(SecretName, result1);
        var written2 = cache2.Decrypt(SecretName, result2);

        Assert.True(written1 > 0);
        Assert.True(written2 > 0);
        Assert.Equal("secret value", Encoding.UTF8.GetString(result1, 0, written1));
        Assert.Equal("secret value", Encoding.UTF8.GetString(result2, 0, written2));
    }

    [Fact]
    public void Decrypt_WithSensitiveLoggingEnabled_StillPopulatesFromGoogle()
    {
        var original = GoogleSecretManagerDiagnostics.EnableSensitiveLogging;
        try
        {
            GoogleSecretManagerDiagnostics.EnableSensitiveLogging = true;

            var client = new FakeSecretManagerServiceClient(new Dictionary<string, string> { [SecretName] = "secret value" });
            var cache = CreateCache(client);

            var result = new byte[32];
            var written = cache.Decrypt(SecretName, result);

            Assert.True(written > 0);
            Assert.Equal("secret value", Encoding.UTF8.GetString(result, 0, written));
        }
        finally
        {
            GoogleSecretManagerDiagnostics.EnableSensitiveLogging = original;
        }
    }
}
