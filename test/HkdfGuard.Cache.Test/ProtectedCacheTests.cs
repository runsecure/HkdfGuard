using System.Security.Cryptography;
using System.Text;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache.Test.TestHelpers;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.DataProtectionKey.Key;

namespace HkdfGuard.Cache.Test;

public class ProtectedCacheTests
{
    private static ProtectedCache CreateCache()
    {
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        var dataProtectionKey = new KeyWrappedDataProtectionKey(wrapper, new AesGcmCipher());
        return new ProtectedCache(dataProtectionKey);
    }

    [Fact]
    public void AddTryDecrypt_Bytes_RoundTrips()
    {
        var cache = CreateCache();
        var plaintext = "top secret bytes"u8.ToArray();
        var expected = (byte[])plaintext.Clone();

        cache.Add("item", plaintext);

        var result = new byte[expected.Length];
        var found = cache.TryDecrypt("item", result, out var written);

        Assert.True(found);
        Assert.Equal(expected.Length, written);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void AddTryDecrypt_Chars_RoundTrips()
    {
        var cache = CreateCache();
        const string plaintext = "top secret chars";

        cache.Add("item", plaintext.AsSpan());

        var result = new char[plaintext.Length];
        var found = cache.TryDecrypt("item", result, out var written);

        Assert.True(found);
        Assert.Equal(plaintext.Length, written);
        Assert.Equal(plaintext, new string(result, 0, written));
    }

    [Fact]
    public void AddTryDecrypt_Chars_HandlesMultiByteUtf8()
    {
        var cache = CreateCache();
        const string plaintext = "héllo wörld 日本語";

        cache.Add("item", plaintext.AsSpan());

        var result = new char[plaintext.Length];
        var found = cache.TryDecrypt("item", result, out var written);

        Assert.True(found);
        Assert.Equal(plaintext, new string(result, 0, written));
    }

    [Fact]
    public void Add_Bytes_CalledTwiceWithSameName_ThrowsArgumentException()
    {
        var cache = CreateCache();

        cache.Add("item", "first"u8.ToArray());

        Assert.Throws<ArgumentException>(() => cache.Add("item", "second"u8.ToArray()));
    }

    [Fact]
    public void Add_Chars_CalledTwiceWithSameName_ThrowsArgumentException()
    {
        var cache = CreateCache();

        cache.Add("item", "first".AsSpan());

        Assert.Throws<ArgumentException>(() => cache.Add("item", "second".AsSpan()));
    }

    [Fact]
    public void Add_Bytes_CalledTwiceWithDifferentCasedName_ThrowsArgumentException()
    {
        var cache = CreateCache();

        cache.Add("Item", "first"u8.ToArray());

        Assert.Throws<ArgumentException>(() => cache.Add("ITEM", "second"u8.ToArray()));
    }

    [Fact]
    public void Add_Bytes_DoesNotReplacePreviousValueWhenDuplicateNameRejected()
    {
        var cache = CreateCache();
        var original = "original"u8.ToArray();
        var expected = (byte[])original.Clone();

        cache.Add("item", original);
        Assert.Throws<ArgumentException>(() => cache.Add("item", "attempted-overwrite"u8.ToArray()));

        var result = new byte[expected.Length];
        cache.TryDecrypt("item", result, out var written);
        Assert.Equal(expected, result[..written]);
    }

    [Fact]
    public void AddOrUpdate_Bytes_CalledTwiceWithSameName_ReplacesPreviousValue()
    {
        var cache = CreateCache();

        cache.AddOrUpdate("item", "first"u8.ToArray());
        cache.AddOrUpdate("item", "second-value"u8.ToArray());

        cache.TryGetMaxDecryptedLength("item", out var maxLength);
        var result = new byte[maxLength];
        var found = cache.TryDecrypt("item", result, out var written);

        Assert.True(found);
        Assert.Equal("second-value", Encoding.UTF8.GetString(result, 0, written));
    }

    [Fact]
    public void AddOrUpdate_Chars_CalledTwiceWithSameName_ReplacesPreviousValue()
    {
        var cache = CreateCache();

        cache.AddOrUpdate("item", "first".AsSpan());
        cache.AddOrUpdate("item", "second-value".AsSpan());

        var result = new char[32];
        var found = cache.TryDecrypt("item", result, out var written);

        Assert.True(found);
        Assert.Equal("second-value", new string(result, 0, written));
    }

    [Fact]
    public void AddOrUpdate_AfterAdd_ReplacesPreviousValueWithoutThrowing()
    {
        var cache = CreateCache();

        cache.Add("item", "first"u8.ToArray());
        var exception = Record.Exception(() => cache.AddOrUpdate("item", "second"u8.ToArray()));

        Assert.Null(exception);
    }

    [Fact]
    public void NamesAreCaseInsensitive_AcrossAddAndTryDecrypt()
    {
        var cache = CreateCache();
        var plaintext = "value"u8.ToArray();
        var expected = (byte[])plaintext.Clone();

        cache.Add("Item-Name", plaintext);

        var result = new byte[expected.Length];
        var found = cache.TryDecrypt("ITEM-name", result, out var written);

        Assert.True(found);
        Assert.Equal(expected, result[..written]);
    }

    [Fact]
    public void NamesAreCaseInsensitive_AcrossAddOrUpdate()
    {
        var cache = CreateCache();

        cache.AddOrUpdate("Item-Name", "first"u8.ToArray());
        cache.AddOrUpdate("ITEM-name", "second"u8.ToArray());

        cache.TryGetMaxDecryptedLength("item-name", out var maxLength);
        var result = new byte[maxLength];
        cache.TryDecrypt("item-name", result, out var written);

        Assert.Equal("second", Encoding.UTF8.GetString(result, 0, written));
    }

    [Fact]
    public void TryDecrypt_Bytes_WithUnknownName_ReturnsFalse()
    {
        var cache = CreateCache();

        var found = cache.TryDecrypt("missing", new byte[16], out var written);

        Assert.False(found);
        Assert.Equal(0, written);
    }

    [Fact]
    public void TryDecrypt_Chars_WithUnknownName_ReturnsFalse()
    {
        var cache = CreateCache();

        var found = cache.TryDecrypt("missing", new char[16], out var written);

        Assert.False(found);
        Assert.Equal(0, written);
    }

    [Fact]
    public void TryGetMaxDecryptedLength_WithUnknownName_ReturnsFalse()
    {
        var cache = CreateCache();

        var found = cache.TryGetMaxDecryptedLength("missing", out var maxLength);

        Assert.False(found);
        Assert.Equal(0, maxLength);
    }

    [Fact]
    public void TryGetMaxDecryptedLength_IsSafeUpperBoundForTryDecrypt()
    {
        var cache = CreateCache();
        var plaintext = "some plaintext value"u8.ToArray();
        var expected = (byte[])plaintext.Clone();

        cache.Add("item", plaintext);

        var found = cache.TryGetMaxDecryptedLength("item", out var maxLength);
        Assert.True(found);

        var result = new byte[maxLength];
        cache.TryDecrypt("item", result, out var written);

        Assert.True(maxLength >= written);
        Assert.Equal(expected, result[..written]);
    }

    [Fact]
    public void AddTryDecrypt_WithSensitiveLoggingEnabled_StillRoundTrips()
    {
        var original = CacheDiagnostics.EnableSensitiveLogging;
        try
        {
            CacheDiagnostics.EnableSensitiveLogging = true;

            var cache = CreateCache();
            var plaintext = "top secret"u8.ToArray();
            var expected = (byte[])plaintext.Clone();

            cache.Add("item", plaintext);
            var result = new byte[expected.Length];
            var found = cache.TryDecrypt("item", result, out var written);

            Assert.True(found);
            Assert.Equal(expected, result[..written]);
        }
        finally
        {
            CacheDiagnostics.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public void AddOrUpdateTryDecrypt_Chars_WithSensitiveLoggingEnabled_StillRoundTrips()
    {
        var original = CacheDiagnostics.EnableSensitiveLogging;
        try
        {
            CacheDiagnostics.EnableSensitiveLogging = true;

            var cache = CreateCache();
            const string plaintext = "top secret chars";

            cache.AddOrUpdate("item", plaintext.AsSpan());
            var result = new char[plaintext.Length];
            var found = cache.TryDecrypt("item", result, out var written);

            Assert.True(found);
            Assert.Equal(plaintext, new string(result, 0, written));
        }
        finally
        {
            CacheDiagnostics.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public void Add_Chars_WithSensitiveLoggingEnabled_StillRoundTrips()
    {
        var original = CacheDiagnostics.EnableSensitiveLogging;
        try
        {
            CacheDiagnostics.EnableSensitiveLogging = true;

            var cache = CreateCache();
            const string plaintext = "top secret chars";

            cache.Add("item", plaintext.AsSpan());
            var result = new char[plaintext.Length];
            var found = cache.TryDecrypt("item", result, out var written);

            Assert.True(found);
            Assert.Equal(plaintext, new string(result, 0, written));
        }
        finally
        {
            CacheDiagnostics.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public void AddOrUpdate_Bytes_WithSensitiveLoggingEnabled_StillRoundTrips()
    {
        var original = CacheDiagnostics.EnableSensitiveLogging;
        try
        {
            CacheDiagnostics.EnableSensitiveLogging = true;

            var cache = CreateCache();
            var plaintext = "top secret"u8.ToArray();
            var expected = (byte[])plaintext.Clone();

            cache.AddOrUpdate("item", plaintext);
            var result = new byte[expected.Length];
            var found = cache.TryDecrypt("item", result, out var written);

            Assert.True(found);
            Assert.Equal(expected, result[..written]);
        }
        finally
        {
            CacheDiagnostics.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public void TryDecrypt_Bytes_WithTooSmallResultBuffer_RecordsExceptionAndThrows()
    {
        var cache = CreateCache();
        cache.Add("item", "top secret"u8.ToArray());

        var tooSmall = new byte[1];
        Assert.Throws<ArgumentException>(() => cache.TryDecrypt("item", tooSmall, out _));
    }

    [Fact]
    public void TryDecrypt_Chars_WithTooSmallResultBuffer_RecordsExceptionAndThrows()
    {
        var cache = CreateCache();
        cache.Add("item", "top secret chars".AsSpan());

        var tooSmall = new char[1];
        Assert.Throws<ArgumentException>(() => cache.TryDecrypt("item", tooSmall, out _));
    }

    [Fact]
    public void Add_Bytes_WithNullName_RecordsExceptionAndThrows()
    {
        var cache = CreateCache();

        Assert.Throws<ArgumentNullException>(() => cache.Add(null!, "value"u8.ToArray()));
    }

    [Fact]
    public void Add_Chars_WithNullName_RecordsExceptionAndThrows()
    {
        var cache = CreateCache();

        Assert.Throws<ArgumentNullException>(() => cache.Add(null!, "value".AsSpan()));
    }

    [Fact]
    public void AddOrUpdate_Bytes_WithNullName_RecordsExceptionAndThrows()
    {
        var cache = CreateCache();

        Assert.Throws<ArgumentNullException>(() => cache.AddOrUpdate(null!, "value"u8.ToArray()));
    }

    [Fact]
    public void AddOrUpdate_Chars_WithNullName_RecordsExceptionAndThrows()
    {
        var cache = CreateCache();

        Assert.Throws<ArgumentNullException>(() => cache.AddOrUpdate(null!, "value".AsSpan()));
    }

    [Fact]
    public void TryDecrypt_Bytes_WithMissingName_AndSensitiveLoggingEnabled_StillReturnsFalse()
    {
        var original = CacheDiagnostics.EnableSensitiveLogging;
        try
        {
            CacheDiagnostics.EnableSensitiveLogging = true;
            var cache = CreateCache();

            var found = cache.TryDecrypt("missing", new byte[16], out var written);

            Assert.False(found);
            Assert.Equal(0, written);
        }
        finally
        {
            CacheDiagnostics.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public void ConcurrentAddAndTryDecrypt_AcrossManyNames_AllRoundTrip()
    {
        var cache = CreateCache();
        const int itemCount = 200;

        Parallel.For(0, itemCount, i =>
        {
            cache.Add($"item-{i}", Encoding.UTF8.GetBytes($"value-{i}"));
        });

        Parallel.For(0, itemCount, i =>
        {
            cache.TryGetMaxDecryptedLength($"item-{i}", out var maxLength);
            var result = new byte[maxLength];
            var found = cache.TryDecrypt($"item-{i}", result, out var written);
            Assert.True(found);
            Assert.Equal($"value-{i}", Encoding.UTF8.GetString(result, 0, written));
        });
    }

    [Fact]
    public void ConcurrentAdd_WithSameName_ExactlyOneSucceeds()
    {
        var cache = CreateCache();
        const int attemptCount = 50;
        var succeeded = 0;

        Parallel.For(0, attemptCount, i =>
        {
            try
            {
                cache.Add("shared-name", Encoding.UTF8.GetBytes($"value-{i}"));
                Interlocked.Increment(ref succeeded);
            }
            catch (ArgumentException)
            {
                // expected for every attempt but the winner
            }
        });

        Assert.Equal(1, succeeded);
    }
}
