using System.Security.Cryptography;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.Core.Primitives;
using HkdfGuard.Core.Test.TestHelpers;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Core.Test;

public class KeyProtectorTests
{
    private const string ServiceName = "svc";
    private const int MaterialIdentifier = 1;
    private const int Iterations = 1;

    private static (KeyProtector protector, IKeyDerivationFunction keyDerivation, ISymmetricCipher cipher, byte[] salt) CreateProtector()
    {
        var keyDerivation = new Pbkdf2KeyDerivationFunction(new InMemoryKeyInputStorage());
        var cipher = new AesGcmCipher();
        var salt = RandomNumberGenerator.GetBytes(64);
        var protector = new KeyProtector(keyDerivation, cipher, salt, MaterialIdentifier, Iterations, ServiceName);
        return (protector, keyDerivation, cipher, salt);
    }

    // KeyProtector only protects (see IKeyProtector) - there is no matching Decrypt on this type,
    // so round-trip verification here re-derives the wrapping key the same way KeyProtector itself
    // does (from the leading 32 byte nonce it wrote) and decrypts with the same cipher, mirroring
    // what HkdfKeyWrapper does for real when reading a saved blob back.
    private static byte[] Reveal(
        byte[] wrapped, IKeyDerivationFunction keyDerivation, ISymmetricCipher cipher, byte[] salt, IAdditionalAuthData? aad = null)
    {
        var nonce = wrapped.AsSpan(0, 32);
        Span<byte> key = stackalloc byte[32];
        keyDerivation.Derive(nonce, salt, MaterialIdentifier, Iterations, ServiceName, key);

        var result = new byte[wrapped.Length - 32 - 12 - 16];
        if (aad is null)
            cipher.Decrypt(key, wrapped.AsSpan(32), result);
        else
            cipher.Decrypt(key, wrapped.AsSpan(32), aad, result);
        return result;
    }

    [Fact]
    public void Encrypt_ProducesDataRevealableByTheSameRecipe()
    {
        var (protector, keyDerivation, cipher, salt) = CreateProtector();
        var plaintextKey = RandomNumberGenerator.GetBytes(32);
        var expected = (byte[])plaintextKey.Clone();
        var wrapped = new byte[32 + 12 + 32 + 16];

        var written = protector.Encrypt(plaintextKey, wrapped);

        Assert.Equal(wrapped.Length, written);
        Assert.Equal(expected, Reveal(wrapped, keyDerivation, cipher, salt));
    }

    [Fact]
    public void Encrypt_WithAad_ProducesDataRevealableWithTheSameAad()
    {
        var (protector, keyDerivation, cipher, salt) = CreateProtector();
        var plaintextKey = RandomNumberGenerator.GetBytes(32);
        var expected = (byte[])plaintextKey.Clone();
        var aad = new AdditionalAuthData("context");
        var wrapped = new byte[32 + 12 + 32 + 16];

        protector.Encrypt(plaintextKey, aad, wrapped);

        Assert.Equal(expected, Reveal(wrapped, keyDerivation, cipher, salt, aad));
    }

    [Fact]
    public void Encrypt_ProducesDifferentNoncesAcrossCalls()
    {
        var (protector, _, _, _) = CreateProtector();
        var first = new byte[32 + 12 + 32 + 16];
        var second = new byte[32 + 12 + 32 + 16];

        protector.Encrypt(RandomNumberGenerator.GetBytes(32), first);
        protector.Encrypt(RandomNumberGenerator.GetBytes(32), second);

        Assert.NotEqual(first.AsSpan(0, 32).ToArray(), second.AsSpan(0, 32).ToArray());
    }

    [Fact]
    public void Encrypt_WithAllZeroPlaintext_Throws()
    {
        var (protector, _, _, _) = CreateProtector();
        var wrapped = new byte[32 + 12 + 32 + 16];

        Assert.Throws<ArgumentException>(() => protector.Encrypt(new byte[32], wrapped));
    }

    [Fact]
    public void Encrypt_WithTooSmallResultBuffer_RecordsExceptionAndThrows()
    {
        var (protector, _, _, _) = CreateProtector();
        var plaintextKey = RandomNumberGenerator.GetBytes(32);
        var tooSmall = new byte[10];

        // result.Slice(0, 32) is what actually throws here, inside the try block - so this both
        // covers the catch/RecordException/rethrow path and confirms it doesn't swallow the error.
        Assert.Throws<ArgumentOutOfRangeException>(() => protector.Encrypt(plaintextKey, tooSmall));
    }
}
