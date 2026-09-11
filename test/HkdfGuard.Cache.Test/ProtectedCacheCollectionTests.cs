using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache.Test.TestHelpers;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.DataProtectionKey.Key;

namespace HkdfGuard.Cache.Test;

public class ProtectedCacheCollectionTests
{
    private static ProtectedCache CreateCache()
    {
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        var dataProtectionKey = new KeyWrappedDataProtectionKey(wrapper, new AesGcmCipher());
        return new ProtectedCache(dataProtectionKey);
    }

    [Fact]
    public void Add_ReturnsSameInstance_ForFluentChaining()
    {
        var collection = new ProtectedCacheCollection();

        var returned = collection.Add(CreateCache());

        Assert.Same(collection, returned);
    }

    [Fact]
    public void TryDecrypt_Bytes_WithNoSources_ReturnsFalse()
    {
        var collection = new ProtectedCacheCollection();

        var found = collection.TryDecrypt("item", new byte[16], out var written);

        Assert.False(found);
        Assert.Equal(0, written);
    }

    [Fact]
    public void TryDecrypt_Bytes_ReturnsFromFirstSourceThatHasIt()
    {
        var first = CreateCache();
        var second = CreateCache();
        first.Add("item", "from-first"u8.ToArray());
        second.Add("item", "from-second"u8.ToArray());

        var collection = new ProtectedCacheCollection().Add(first).Add(second);

        var result = new byte[32];
        var found = collection.TryDecrypt("item", result, out var written);

        Assert.True(found);
        Assert.Equal("from-first", System.Text.Encoding.UTF8.GetString(result, 0, written));
    }

    [Fact]
    public void TryDecrypt_Bytes_FallsThroughToLaterSourceWhenEarlierOnesLackTheName()
    {
        var first = CreateCache();
        var second = CreateCache();
        second.Add("item", "from-second"u8.ToArray());

        var collection = new ProtectedCacheCollection().Add(first).Add(second);

        var result = new byte[32];
        var found = collection.TryDecrypt("item", result, out var written);

        Assert.True(found);
        Assert.Equal("from-second", System.Text.Encoding.UTF8.GetString(result, 0, written));
    }

    [Fact]
    public void TryDecrypt_Bytes_WithNoSourceHavingTheName_ReturnsFalse()
    {
        var first = CreateCache();
        var second = CreateCache();

        var collection = new ProtectedCacheCollection().Add(first).Add(second);

        var found = collection.TryDecrypt("missing", new byte[16], out var written);

        Assert.False(found);
        Assert.Equal(0, written);
    }

    [Fact]
    public void TryDecrypt_Chars_ReturnsFromFirstSourceThatHasIt()
    {
        var first = CreateCache();
        var second = CreateCache();
        first.Add("item", "from-first".AsSpan());
        second.Add("item", "from-second".AsSpan());

        var collection = new ProtectedCacheCollection().Add(first).Add(second);

        var result = new char[32];
        var found = collection.TryDecrypt("item", result, out var written);

        Assert.True(found);
        Assert.Equal("from-first", new string(result, 0, written));
    }

    [Fact]
    public void TryDecrypt_Chars_FallsThroughToLaterSourceWhenEarlierOnesLackTheName()
    {
        var first = CreateCache();
        var second = CreateCache();
        second.Add("item", "from-second".AsSpan());

        var collection = new ProtectedCacheCollection().Add(first).Add(second);

        var result = new char[32];
        var found = collection.TryDecrypt("item", result, out var written);

        Assert.True(found);
        Assert.Equal("from-second", new string(result, 0, written));
    }

    [Fact]
    public void TryDecrypt_Chars_WithNoSourceHavingTheName_ReturnsFalse()
    {
        var collection = new ProtectedCacheCollection().Add(CreateCache()).Add(CreateCache());

        var found = collection.TryDecrypt("missing", new char[16], out var written);

        Assert.False(found);
        Assert.Equal(0, written);
    }

    [Fact]
    public void TryGetMaxDecryptedLength_WithNoSources_ReturnsFalse()
    {
        var collection = new ProtectedCacheCollection();

        var found = collection.TryGetMaxDecryptedLength("item", out var maxLength);

        Assert.False(found);
        Assert.Equal(0, maxLength);
    }

    [Fact]
    public void TryGetMaxDecryptedLength_ReturnsFromFirstSourceThatHasIt()
    {
        var first = CreateCache();
        var second = CreateCache();
        first.Add("item", "abc"u8.ToArray());
        second.Add("item", "a much longer value than the first source has"u8.ToArray());

        var collection = new ProtectedCacheCollection().Add(first).Add(second);

        first.TryGetMaxDecryptedLength("item", out var expectedMaxLength);
        var found = collection.TryGetMaxDecryptedLength("item", out var maxLength);

        Assert.True(found);
        Assert.Equal(expectedMaxLength, maxLength);
    }

    [Fact]
    public void TryGetMaxDecryptedLength_FallsThroughToLaterSourceWhenEarlierOnesLackTheName()
    {
        var first = CreateCache();
        var second = CreateCache();
        second.Add("item", "from-second"u8.ToArray());

        var collection = new ProtectedCacheCollection().Add(first).Add(second);

        var found = collection.TryGetMaxDecryptedLength("item", out var maxLength);

        Assert.True(found);
        Assert.True(maxLength > 0);
    }

    [Fact]
    public void TryGetMaxDecryptedLength_WithNoSourceHavingTheName_ReturnsFalse()
    {
        var collection = new ProtectedCacheCollection().Add(CreateCache()).Add(CreateCache());

        var found = collection.TryGetMaxDecryptedLength("missing", out var maxLength);

        Assert.False(found);
        Assert.Equal(0, maxLength);
    }

    [Fact]
    public void TryDecrypt_Bytes_WithSensitiveLoggingEnabled_StillRoundTrips()
    {
        var original = CacheDiagnostics.EnableSensitiveLogging;
        try
        {
            CacheDiagnostics.EnableSensitiveLogging = true;

            var source = CreateCache();
            source.Add("item", "top secret"u8.ToArray());
            var collection = new ProtectedCacheCollection().Add(source);

            var result = new byte[32];
            var found = collection.TryDecrypt("item", result, out var written);

            Assert.True(found);
            Assert.Equal("top secret", System.Text.Encoding.UTF8.GetString(result, 0, written));
        }
        finally
        {
            CacheDiagnostics.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public void TryDecrypt_Chars_WithSensitiveLoggingEnabled_StillRoundTrips()
    {
        var original = CacheDiagnostics.EnableSensitiveLogging;
        try
        {
            CacheDiagnostics.EnableSensitiveLogging = true;

            var source = CreateCache();
            source.Add("item", "top secret".AsSpan());
            var collection = new ProtectedCacheCollection().Add(source);

            var result = new char[32];
            var found = collection.TryDecrypt("item", result, out var written);

            Assert.True(found);
            Assert.Equal("top secret", new string(result, 0, written));
        }
        finally
        {
            CacheDiagnostics.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public void TryDecrypt_Bytes_WhenASourceThrows_RecordsExceptionAndThrows()
    {
        var collection = new ProtectedCacheCollection().Add(new ThrowingReadOnlyCache(new InvalidOperationException("boom")));

        Assert.Throws<InvalidOperationException>(() => collection.TryDecrypt("item", new byte[16], out _));
    }

    [Fact]
    public void TryDecrypt_Chars_WhenASourceThrows_RecordsExceptionAndThrows()
    {
        var collection = new ProtectedCacheCollection().Add(new ThrowingReadOnlyCache(new InvalidOperationException("boom")));

        Assert.Throws<InvalidOperationException>(() => collection.TryDecrypt("item", new char[16], out _));
    }
}
