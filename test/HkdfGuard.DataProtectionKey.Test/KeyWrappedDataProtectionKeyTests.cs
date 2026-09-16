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

        var encrypted = dataProtectionKey.Encrypt(plaintext);
        Assert.Equal(expected.Length + 12 + 16, encrypted.Length);

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

        var encrypted = dataProtectionKey.Encrypt(plaintext, aad);

        var decrypted = new byte[expected.Length];
        var decryptedLength = dataProtectionKey.Decrypt(encrypted, aad, decrypted);

        Assert.Equal(expected, decrypted[..decryptedLength]);
    }

    [Fact]
    public void Decrypt_WithMismatchedAad_Throws()
    {
        var dataProtectionKey = CreateKey(out _);
        var plaintext = "top secret"u8.ToArray();
        var encrypted = dataProtectionKey.Encrypt(plaintext, new AdditionalAuthData("context-a".AsSpan()));

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

        var encrypted = dataProtectionKey.Encrypt(plaintext);
        var decrypted = new byte[expected.Length];
        var decryptedLength = dataProtectionKey.Decrypt(encrypted, decrypted);

        Assert.Equal(expected, decrypted[..decryptedLength]);
    }

    [Fact]
    public void Encrypt_ReturnsExactlySizedArray()
    {
        var dataProtectionKey = CreateKey(out _);
        var plaintext = "a longer plaintext value to encrypt"u8.ToArray();
        var expectedLength = plaintext.Length + 12 + 16; // AES-GCM nonce + tag overhead

        var encrypted = dataProtectionKey.Encrypt(plaintext);

        Assert.Equal(expectedLength, encrypted.Length);
    }

    [Fact]
    public void Encrypt_WhenKeyWrapperFails_RecordsExceptionAndThrows()
    {
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32))
        {
            ThrowOnDecrypt = new InvalidOperationException("key reveal failed")
        };
        var dataProtectionKey = new KeyWrappedDataProtectionKey(wrapper, new AesGcmCipher());

        Assert.Throws<InvalidOperationException>(() => dataProtectionKey.Encrypt("top secret"u8.ToArray()));
    }

    [Fact]
    public void Decrypt_WhenKeyWrapperFails_RecordsExceptionAndThrows()
    {
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        var dataProtectionKey = new KeyWrappedDataProtectionKey(wrapper, new AesGcmCipher());
        var encrypted = dataProtectionKey.Encrypt("top secret"u8.ToArray());

        wrapper.ThrowOnDecrypt = new InvalidOperationException("key reveal failed");

        Assert.Throws<InvalidOperationException>(() => dataProtectionKey.Decrypt(encrypted, new byte[16]));
    }

    [Fact]
    public void EncryptAndDecrypt_EachRevealKeyFreshOnEveryCall()
    {
        var dataProtectionKey = CreateKey(out var wrapper);
        var encrypted1 = dataProtectionKey.Encrypt("one"u8.ToArray());
        var encrypted2 = dataProtectionKey.Encrypt("two"u8.ToArray());

        dataProtectionKey.Decrypt(encrypted1, new byte[3]);

        Assert.Equal(3, wrapper.DecryptCallCount);
    }
}
