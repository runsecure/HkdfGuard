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
    public void TryDecrypt_OnMiss_CallsTryPopulate_AndReturnsPopulatedValue()
    {
        var cache = CreateCache();
        cache.OnTryPopulate = name =>
        {
            cache.Seed(name, "populated value");
            return true;
        };

        var result = new byte[32];
        var found = cache.TryDecrypt("item", result, out var written);

        Assert.True(found);
        Assert.Equal(1, cache.TryPopulateCallCount);
        Assert.Equal("populated value", System.Text.Encoding.UTF8.GetString(result, 0, written));
    }

    [Fact]
    public void TryDecrypt_WhenAlreadyCached_DoesNotCallTryPopulate()
    {
        var cache = CreateCache();
        cache.Seed("item", "already cached");
        cache.OnTryPopulate = _ => throw new InvalidOperationException("should not be called");

        var result = new byte[32];
        var found = cache.TryDecrypt("item", result, out var written);

        Assert.True(found);
        Assert.Equal(0, cache.TryPopulateCallCount);
        Assert.Equal("already cached", System.Text.Encoding.UTF8.GetString(result, 0, written));
    }

    [Fact]
    public void TryDecrypt_WhenTryPopulateReturnsFalse_ReturnsFalse()
    {
        var cache = CreateCache();
        cache.OnTryPopulate = _ => false;

        var found = cache.TryDecrypt("item", new byte[32], out var written);

        Assert.False(found);
        Assert.Equal(0, written);
        Assert.Equal(1, cache.TryPopulateCallCount);
    }

    [Fact]
    public void TryDecrypt_WhenTryPopulateReturnsTrueButDoesNotActuallyPopulate_ReturnsFalse()
    {
        var cache = CreateCache();
        cache.OnTryPopulate = _ => true; // lies - never calls Seed

        var found = cache.TryDecrypt("item", new byte[32], out var written);

        Assert.False(found);
        Assert.Equal(0, written);
    }

    [Fact]
    public void TryGetMaxDecryptedLength_OnMiss_CallsTryPopulate()
    {
        var cache = CreateCache();
        cache.OnTryPopulate = name =>
        {
            cache.Seed(name, "populated value");
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

        var found = cache.TryDecrypt("item", new byte[16], out _);

        Assert.False(found);
    }
}
