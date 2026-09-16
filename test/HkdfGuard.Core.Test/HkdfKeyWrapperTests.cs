using System.Security.Cryptography;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.Core.Primitives;
using HkdfGuard.Core.Test.TestHelpers;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Core.Test;

public class HkdfKeyWrapperTests
{
    private const string ServiceName = "svc";
    private static readonly KeyBlobSpec BlobSpec = new(
        saltLength: 64, encryptedKeySaltLength: 32, encryptedKeyValueLength: 60, signatureLength: 64);
    private static readonly IKeyWrapperFactory KeyWrapperFactory = new HkdfKeyWrapperFactory();

    private static IKeySpec CreateKeySpec()
        => new CryptoRecipeBuilder()
            .WithServiceName(ServiceName)
            .WithKeyDerivation(new Pbkdf2KeyDerivationFunction(new InMemoryKeyInputStorage()))
            .WithCipher(new AesGcmCipher())
            .WithHash(new HmacSha512Hash())
            .WithMaterialIdentifier(1)
            .WithIterations(1)
            .Build();

    // Mirrors the real Initializer flow: bootstrap-wrap plaintextKey to produce a validly signed
    // blob, exercising the same Create -> Save -> TryLoad path production code uses.
    private static IKeyBlob CreateValidatedBlob(IKeySpec keySpec, byte[] plaintextKey)
    {
        var salt = RandomNumberGenerator.GetBytes(BlobSpec.SaltLength);
        var protector = new KeyProtector(keySpec, salt);

        var blob = KeyBlobFactory.Create(plaintextKey, protector, keySpec, BlobSpec, salt);
        var blobBytes = new byte[BlobSpec.TotalLength];
        blob.Save(blobBytes);

        Assert.True(KeyBlobFactory.TryLoad(blobBytes, keySpec, BlobSpec, out var loadedBlob));
        return loadedBlob!;
    }

    [Fact]
    public void Decrypt_RevealsOriginallyProtectedKey()
    {
        var keySpec = CreateKeySpec();
        var plaintextKey = RandomNumberGenerator.GetBytes(32);
        // KeyBlobFactory.Create's Encrypt call zeroes the plaintext span it's given as a side
        // effect, so snapshot it first.
        var expectedPlaintextKey = (byte[])plaintextKey.Clone();
        var blob = CreateValidatedBlob(keySpec, plaintextKey);

        var wrapper = KeyWrapperFactory.Create(keySpec, blob);

        var revealed = new byte[32];
        var written = wrapper.Decrypt(revealed);

        Assert.Equal(32, written);
        Assert.Equal(expectedPlaintextKey, revealed);
    }

    [Fact]
    public void Decrypt_WithMismatchedAad_Throws()
    {
        var keySpec = CreateKeySpec();
        var salt = RandomNumberGenerator.GetBytes(BlobSpec.SaltLength);
        var protector = new KeyProtector(keySpec, salt);

        // Wraps with a specific AAD, exactly as KeyBlobFactory.Create does when protecting a
        // key - the only IKeyProtector.Encrypt call anything in this codebase actually makes.
        var plaintextKey = RandomNumberGenerator.GetBytes(32);
        var wrapped = new byte[BlobSpec.EncryptedKeySaltLength + BlobSpec.EncryptedKeyValueLength];
        var aad = new AdditionalAuthData("context-a".AsSpan());
        protector.Encrypt(plaintextKey, aad, wrapped);

        var blob = new FlexibleKeyBlob(BlobSpec, salt,
            wrapped.AsSpan(0, BlobSpec.EncryptedKeySaltLength),
            wrapped.AsSpan(BlobSpec.EncryptedKeySaltLength, BlobSpec.EncryptedKeyValueLength),
            new byte[BlobSpec.SignatureLength]);
        var wrapper = KeyWrapperFactory.Create(keySpec, blob);

        var wrongAad = new AdditionalAuthData("context-b".AsSpan());
        var result = new byte[32];
        Assert.Throws<AuthenticationTagMismatchException>(() => wrapper.Decrypt(wrongAad, result));
    }
}
