using System.Security.Cryptography;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.Core.Primitives;

namespace HkdfGuard.Core.Test;

public class AesGcmCipherTests
{
    [Fact]
    public void EncryptDecrypt_RoundTrips()
    {
        var cipher = new AesGcmCipher();
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = "hello world"u8.ToArray();
        var expectedPlaintext = (byte[])plaintext.Clone();
        var encrypted = new byte[plaintext.Length + 28];

        // Encrypt zeroes the key and plaintext spans it's given, so each call needs its own copy of the key.
        var written = cipher.Encrypt((byte[])key.Clone(), plaintext, encrypted);
        Assert.Equal(encrypted.Length, written);

        var decrypted = new byte[expectedPlaintext.Length];
        var decryptedLength = cipher.Decrypt((byte[])key.Clone(), encrypted, decrypted);

        Assert.Equal(expectedPlaintext.Length, decryptedLength);
        Assert.Equal(expectedPlaintext, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_RoundTrips_WithAad()
    {
        var cipher = new AesGcmCipher();
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = "hello world"u8.ToArray();
        var expectedPlaintext = (byte[])plaintext.Clone();
        var aad = new AdditionalAuthData("context");
        var encrypted = new byte[plaintext.Length + 28];

        cipher.Encrypt((byte[])key.Clone(), plaintext, aad, encrypted);

        var decrypted = new byte[expectedPlaintext.Length];
        cipher.Decrypt((byte[])key.Clone(), encrypted, aad, decrypted);

        Assert.Equal(expectedPlaintext, decrypted);
    }

    [Fact]
    public void Decrypt_WithWrongAad_Throws()
    {
        var cipher = new AesGcmCipher();
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = "hello world"u8.ToArray();
        var encrypted = new byte[plaintext.Length + 28];
        cipher.Encrypt((byte[])key.Clone(), plaintext, new AdditionalAuthData("correct-aad"), encrypted);

        var decrypted = new byte[11];
        Assert.Throws<AuthenticationTagMismatchException>(() =>
            cipher.Decrypt((byte[])key.Clone(), encrypted, new AdditionalAuthData("wrong-aad"), decrypted));
    }

    [Fact]
    public void Decrypt_WithTamperedCiphertext_Throws()
    {
        var cipher = new AesGcmCipher();
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = "hello world"u8.ToArray();
        var encrypted = new byte[plaintext.Length + 28];
        cipher.Encrypt((byte[])key.Clone(), plaintext, encrypted);
        encrypted[15] ^= 0xFF;

        var decrypted = new byte[11];
        Assert.Throws<AuthenticationTagMismatchException>(() => cipher.Decrypt((byte[])key.Clone(), encrypted, decrypted));
    }

    [Fact]
    public void Encrypt_WithTooSmallResultBuffer_Throws()
    {
        var cipher = new AesGcmCipher();
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = "hello world"u8.ToArray();
        var tooSmall = new byte[plaintext.Length];

        Assert.Throws<ArgumentException>(() => cipher.Encrypt(key, plaintext, tooSmall));
    }

    [Fact]
    public void Decrypt_WithTooShortCiphertext_Throws()
    {
        var cipher = new AesGcmCipher();
        var key = RandomNumberGenerator.GetBytes(32);
        var tooShort = new byte[10];
        var result = new byte[4];

        Assert.Throws<ArgumentException>(() => cipher.Decrypt(key, tooShort, result));
    }

    [Fact]
    public void Encrypt_WithInvalidKeySize_Throws()
    {
        var cipher = new AesGcmCipher();
        var invalidKey = RandomNumberGenerator.GetBytes(10);
        var plaintext = "hello world"u8.ToArray();
        var encrypted = new byte[plaintext.Length + 28];

        Assert.Throws<CryptographicException>(() => cipher.Encrypt(invalidKey, plaintext, encrypted));
    }

    [Fact]
    public void Encrypt_WithAllZeroKey_Throws()
    {
        var cipher = new AesGcmCipher();
        var zeroKey = new byte[32];
        var plaintext = "hello world"u8.ToArray();
        var encrypted = new byte[plaintext.Length + 28];

        Assert.Throws<ArgumentException>(() => cipher.Encrypt(zeroKey, plaintext, encrypted));
    }

    [Fact]
    public void Decrypt_WithAllZeroKey_Throws()
    {
        var cipher = new AesGcmCipher();
        var zeroKey = new byte[32];
        var ciphertext = new byte[38];
        var result = new byte[10];

        Assert.Throws<ArgumentException>(() => cipher.Decrypt(zeroKey, ciphertext, result));
    }
}
