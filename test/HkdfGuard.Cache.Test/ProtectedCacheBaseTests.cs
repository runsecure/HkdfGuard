using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache.Test.TestHelpers;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.DataProtectionKey.Key;

namespace HkdfGuard.Cache.Test;

public class ProtectedCacheBaseTests
{
    private static PopulatingCache CreateCache()
    {
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        var dataProtectionKey = new KeyWrappedDataProtectionKey(wrapper, new AesGcmCipher());
        return new PopulatingCache(dataProtectionKey);
    }

    [Fact]
    public void Decrypt_OnMiss_CallsTryPopulate_AndReturnsPopulatedValue()
    {
        var cache = CreateCache();
        cache.OnTryPopulate = name =>
        {
            cache.Seed(name, "populated value".ToCharArray());
            return true;
        };

        var result = new byte[32];
        var written = cache.Decrypt("item", result);

        Assert.True(written > 0);
        Assert.Equal(1, cache.TryPopulateCallCount);
        Assert.Equal("populated value", System.Text.Encoding.UTF8.GetString(result, 0, written));
    }

    [Fact]
    public void Decrypt_WhenAlreadyCached_DoesNotCallTryPopulate()
    {
        var cache = CreateCache();
        cache.Seed("item", "already cached".ToCharArray());
        cache.OnTryPopulate = _ => throw new InvalidOperationException("should not be called");

        var result = new byte[32];
        var written = cache.Decrypt("item", result);

        Assert.True(written > 0);
        Assert.Equal(0, cache.TryPopulateCallCount);
        Assert.Equal("already cached", System.Text.Encoding.UTF8.GetString(result, 0, written));
    }

    [Fact]
    public void Decrypt_WhenTryPopulateReturnsFalse_ReturnsZero()
    {
        var cache = CreateCache();
        cache.OnTryPopulate = _ => false;

        var written = cache.Decrypt("item", new byte[32]);

        Assert.Equal(0, written);
        Assert.Equal(1, cache.TryPopulateCallCount);
    }

    [Fact]
    public void Decrypt_WhenTryPopulateReturnsTrueButDoesNotActuallyPopulate_ReturnsZero()
    {
        var cache = CreateCache();
        cache.OnTryPopulate = _ => true; // lies - never calls Seed

        var written = cache.Decrypt("item", new byte[32]);

        Assert.Equal(0, written);
    }

    [Fact]
    public void TryGetMaxDecryptedLength_OnMiss_CallsTryPopulate()
    {
        var cache = CreateCache();
        cache.OnTryPopulate = name =>
        {
            cache.Seed(name, "populated value".ToCharArray());
            return true;
        };

        var found = cache.TryGetMaxDecryptedLength("item", out var maxLength);

        Assert.True(found);
        Assert.True(maxLength > 0);
        Assert.Equal(1, cache.TryPopulateCallCount);
    }

    [Fact]
    public void DefaultTryPopulate_ReturnsFalse_WithoutOverride()
    {
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        var dataProtectionKey = new KeyWrappedDataProtectionKey(wrapper, new AesGcmCipher());
        var cache = new PopulatingCache(dataProtectionKey) { OnTryPopulate = null };

        var written = cache.Decrypt("item", new byte[16]);

        Assert.Equal(0, written);
    }
}
