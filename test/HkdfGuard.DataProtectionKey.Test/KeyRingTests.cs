using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.DataProtectionKey.FormatProvider;
using HkdfGuard.DataProtectionKey.Key;
using HkdfGuard.DataProtectionKey.KeyTracking;
using HkdfGuard.DataProtectionKey.Test.TestHelpers;

namespace HkdfGuard.DataProtectionKey.Test;

public class KeyRingTests
{
    private static IDataProtectionKey CreateFakeKey()
        => new KeyWrappedDataProtectionKey(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), new AesGcmCipher());

    [Fact]
    public void CurrentVersion_BeforeAnyAdd_ThrowsInvalidOperationException()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        Assert.Throws<InvalidOperationException>(() => ring.CurrentVersion);
    }

    [Fact]
    public void Add_FirstKey_BecomesCurrentVersion()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, CreateFakeKey());

        Assert.Equal(1, ring.CurrentVersion);
    }

    [Fact]
    public void Add_HigherVersion_BecomesNewCurrent()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, CreateFakeKey());
        ring.Add(5, CreateFakeKey());

        Assert.Equal(5, ring.CurrentVersion);
    }

    [Fact]
    public void Add_LowerVersionAfterHigher_DoesNotChangeCurrent()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(5, CreateFakeKey());
        ring.Add(1, CreateFakeKey());

        Assert.Equal(5, ring.CurrentVersion);
    }

    [Fact]
    public void Add_WithSensitiveLoggingEnabled_StillWorksCorrectly()
    {
        using var _ = new SensitiveLoggingScope(true);

        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, CreateFakeKey());

        Assert.Equal(1, ring.CurrentVersion);
    }

    [Fact]
    public void Add_DuplicateVersion_ThrowsArgumentException()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, CreateFakeKey());

        Assert.Throws<ArgumentException>(() => ring.Add(1, CreateFakeKey()));
    }

    [Fact]
    public void Get_RegisteredVersion_ReturnsSameInstance()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        var key = CreateFakeKey();
        ring.Add(1, key);

        Assert.Same(key, ring.Get(1));
    }

    [Fact]
    public void Get_UnregisteredVersion_ThrowsKeyNotFoundException()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        Assert.Throws<KeyNotFoundException>(() => ring.Get(999));
    }

    [Fact]
    public void TryGet_RegisteredVersion_ReturnsTrueAndKey()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        var key = CreateFakeKey();
        ring.Add(1, key);

        Assert.True(ring.TryGet(1, out var found));
        Assert.Same(key, found);
    }

    [Fact]
    public void TryGet_UnregisteredVersion_ReturnsFalse()
    {
        var ring = new KeyRing(new DefaultFormatProvider());

        Assert.False(ring.TryGet(999, out var found));
        Assert.Null(found);
    }

    [Fact]
    public void GetCurrent_ReturnsCurrentVersionAndKey()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        var key = CreateFakeKey();
        ring.Add(3, key);

        var (version, resolvedKey) = ring.GetCurrent();

        Assert.Equal(3, version);
        Assert.Same(key, resolvedKey);
    }

    [Fact]
    public void GetCurrent_WithNoKeysAdded_ThrowsInvalidOperationException()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        Assert.Throws<InvalidOperationException>(() => ring.GetCurrent());
    }

    [Fact]
    public void CreateProtector_ProducesWorkingProtectorBoundToThisRing()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, CreateFakeKey());

        var protector = ring.CreateProtector("purpose");
        var formatted = protector.Encrypt("hello".AsSpan());

        Span<char> result = new char[protector.GetMaxDecryptedLength(formatted.AsSpan())];
        var written = protector.Decrypt(formatted.AsSpan(), result);

        Assert.Equal("hello", new string(result[..written]));
    }

    [Fact]
    public void CreateProtector_UsesRingsConfiguredFormatProvider()
    {
        var recordingFormatProvider = new RecordingFormatProvider();
        var ring = new KeyRing(recordingFormatProvider);
        ring.Add(1, CreateFakeKey());

        var formatted = ring.CreateProtector("purpose").Encrypt("hello".AsSpan());
        Assert.True(recordingFormatProvider.FormatCalled);

        ring.CreateProtector("purpose").Decrypt(formatted.AsSpan(), new char[16]);
        Assert.True(recordingFormatProvider.ParseCalled);
    }
}
