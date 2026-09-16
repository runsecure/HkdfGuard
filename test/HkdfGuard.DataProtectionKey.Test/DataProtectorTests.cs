using System.Security.Cryptography;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.DataProtectionKey.FormatProvider;
using HkdfGuard.DataProtectionKey.Key;
using HkdfGuard.DataProtectionKey.KeyTracking;
using HkdfGuard.DataProtectionKey.Test.TestHelpers;

namespace HkdfGuard.DataProtectionKey.Test;

/// <summary>
/// Exercises IDataProtector's failure paths (Protector.DataProtector is internal - reachable only
/// through KeyRing.CreateProtector, matching how it's actually used in practice).
/// </summary>
public class DataProtectorTests
{
    private static KeyRing CreateRingWithOneKey()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, new KeyWrappedDataProtectionKey(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), new AesGcmCipher()));
        return ring;
    }

    [Fact]
    public void Encrypt_OnEmptyRing_ThrowsInvalidOperationException()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        var protector = ring.CreateProtector("purpose");

        Assert.Throws<InvalidOperationException>(() => protector.Encrypt("hello".AsSpan()));
    }

    [Fact]
    public void Decrypt_WithMalformedInput_ThrowsFormatException()
    {
        var protector = CreateRingWithOneKey().CreateProtector("purpose");

        Assert.Throws<FormatException>(() => protector.Decrypt("not-a-valid-format".AsSpan(), new char[16]));
    }

    [Fact]
    public void Decrypt_ForUnregisteredVersion_ThrowsKeyNotFoundException()
    {
        var protector = CreateRingWithOneKey().CreateProtector("purpose");
        var formatted = protector.Encrypt("hello".AsSpan());

        // Claim a version that was never registered in this ring.
        var tampered = formatted.Replace("::v1::", "::v99::");

        Assert.Throws<KeyNotFoundException>(() => protector.Decrypt(tampered.AsSpan(), new char[16]));
    }

    [Fact]
    public void EncryptDecrypt_WithSensitiveLoggingEnabled_StillRoundTrips()
    {
        using var _ = new SensitiveLoggingScope(true);

        var protector = CreateRingWithOneKey().CreateProtector("purpose");
        var formatted = protector.Encrypt("hello".AsSpan());

        Span<char> result = new char[16];
        var written = protector.Decrypt(formatted.AsSpan(), result);

        Assert.Equal("hello", new string(result[..written]));
    }

    [Fact]
    public void Decrypt_WithDifferentProtectorName_ThrowsDueToAadMismatch()
    {
        var ring = CreateRingWithOneKey();
        var formatted = ring.CreateProtector("purpose-a").Encrypt("hello".AsSpan());

        Assert.Throws<AuthenticationTagMismatchException>(() =>
            ring.CreateProtector("purpose-b").Decrypt(formatted.AsSpan(), new char[16]));
    }
}
