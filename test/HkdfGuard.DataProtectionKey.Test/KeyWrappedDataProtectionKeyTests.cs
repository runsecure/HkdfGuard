using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.Core.Primitives;
using HkdfGuard.DataProtectionKey.Key;
using HkdfGuard.DataProtectionKey.Test.TestHelpers;

namespace HkdfGuard.DataProtectionKey.Test;

public class KeyWrappedDataProtectionKeyTests
{
    private static KeyWrappedDataProtectionKey CreateKey(out FakeKeyWrapper wrapper)
    {
        wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        return new KeyWrappedDataProtectionKey(wrapper, new AesGcmCipher());
    }

    [Fact]
    public void EncryptDecrypt_RoundTrips()
    {
        var dataProtectionKey = CreateKey(out _);
        var plaintext = "top secret"u8.ToArray();
        // AesGcmCipher.Encrypt zeroes the plaintext span it's given as a side effect.
        var expected = (byte[])plaintext.Clone();
        var encrypted = new byte[plaintext.Length + 12 + 16];

        var written = dataProtectionKey.Encrypt(plaintext, encrypted);
        Assert.Equal(encrypted.Length, written);

        var decrypted = new byte[expected.Length];
        var decryptedLength = dataProtectionKey.Decrypt(encrypted, decrypted);

        Assert.Equal(expected.Length, decryptedLength);
        Assert.Equal(expected, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_WithAad_RoundTrips()
    {
        var dataProtectionKey = CreateKey(out _);
        var plaintext = "top secret"u8.ToArray();
        var expected = (byte[])plaintext.Clone();
        var aad = new AdditionalAuthData("context".AsSpan());
        var encrypted = new byte[plaintext.Length + 12 + 16];

        dataProtectionKey.Encrypt(plaintext, aad, encrypted);

        var decrypted = new byte[expected.Length];
        var decryptedLength = dataProtectionKey.Decrypt(encrypted, aad, decrypted);

        Assert.Equal(expected, decrypted[..decryptedLength]);
    }

    [Fact]
    public void Decrypt_WithMismatchedAad_Throws()
    {
        var dataProtectionKey = CreateKey(out _);
        var plaintext = "top secret"u8.ToArray();
        var encrypted = new byte[plaintext.Length + 12 + 16];
        dataProtectionKey.Encrypt(plaintext, new AdditionalAuthData("context-a".AsSpan()), encrypted);

        var result = new byte[plaintext.Length];
        Assert.Throws<AuthenticationTagMismatchException>(() =>
            dataProtectionKey.Decrypt(encrypted, new AdditionalAuthData("context-b".AsSpan()), result));
    }

    [Fact]
    public void EncryptDecrypt_WithSensitiveLoggingEnabled_StillRoundTrips()
    {
        using var loggingScope = new SensitiveLoggingScope(true);

        var dataProtectionKey = CreateKey(out _);
        var plaintext = "top secret"u8.ToArray();
        var expected = (byte[])plaintext.Clone();
        var encrypted = new byte[plaintext.Length + 12 + 16];

        dataProtectionKey.Encrypt(plaintext, encrypted);
        var decrypted = new byte[expected.Length];
        var decryptedLength = dataProtectionKey.Decrypt(encrypted, decrypted);

        Assert.Equal(expected, decrypted[..decryptedLength]);
    }

    [Fact]
    public void Encrypt_WithTooSmallResultBuffer_ThrowsArgumentException()
    {
        var dataProtectionKey = CreateKey(out _);
        var plaintext = "top secret"u8.ToArray();
        var tooSmall = new byte[plaintext.Length]; // missing AES-GCM's 12-byte nonce + 16-byte tag overhead

        Assert.Throws<ArgumentException>(() => dataProtectionKey.Encrypt(plaintext, tooSmall));
    }

    [Fact]
    public void EncryptAndDecrypt_EachRevealKeyFreshOnEveryCall()
    {
        var dataProtectionKey = CreateKey(out var wrapper);
        var plaintext1 = "one"u8.ToArray();
        var encrypted1 = new byte[plaintext1.Length + 12 + 16];
        dataProtectionKey.Encrypt(plaintext1, encrypted1);

        var plaintext2 = "two"u8.ToArray();
        var encrypted2 = new byte[plaintext2.Length + 12 + 16];
        dataProtectionKey.Encrypt(plaintext2, encrypted2);

        dataProtectionKey.Decrypt(encrypted1, new byte[3]);

        Assert.Equal(3, wrapper.DecryptCallCount);
    }
}
