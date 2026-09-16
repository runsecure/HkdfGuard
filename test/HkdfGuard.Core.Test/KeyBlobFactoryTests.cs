using System.Security.Cryptography;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.Core.Primitives;
using HkdfGuard.Core.Test.TestHelpers;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Core.Test;

public class KeyBlobFactoryTests
{
    private const string ServiceName = "svc";
    private static readonly KeyBlobSpec BlobSpec = new(
        saltLength: 64, encryptedKeySaltLength: 32, encryptedKeyValueLength: 60, signatureLength: 64);

    private static IKeySpec CreateKeySpec(
        IKeyInputStorage storage, int materialIdentifier = 1, int iterations = 1, string serviceName = ServiceName)
        => new CryptoRecipeBuilder()
            .WithServiceName(serviceName)
            .WithKeyDerivation(new Pbkdf2KeyDerivationFunction(storage))
            .WithCipher(new AesGcmCipher())
            .WithHash(new HmacSha512Hash())
            .WithMaterialIdentifier(materialIdentifier)
            .WithIterations(iterations)
            .Build();

    private static byte[] CreateSignedBlobBytes(IKeySpec keySpec)
    {
        var salt = RandomNumberGenerator.GetBytes(BlobSpec.SaltLength);
        var protector = new KeyProtector(keySpec, salt);
        var plaintextKey = RandomNumberGenerator.GetBytes(32);

        var blob = KeyBlobFactory.Create(plaintextKey, protector, keySpec, BlobSpec, salt);
        var blobBytes = new byte[BlobSpec.TotalLength];
        blob.Save(blobBytes);
        return blobBytes;
    }

    [Fact]
    public void CreateThenTryLoad_RoundTrips()
    {
        var keySpec = CreateKeySpec(new InMemoryKeyInputStorage());
        var blobBytes = CreateSignedBlobBytes(keySpec);

        Assert.True(KeyBlobFactory.TryLoad(blobBytes, keySpec, BlobSpec, out var blob));
        Assert.Equal(BlobSpec.SaltLength, blob!.Salt.Length);
        Assert.Equal(BlobSpec.EncryptedKeySaltLength, blob.EncryptedKeySalt.Length);
        Assert.Equal(BlobSpec.EncryptedKeyValueLength, blob.EncryptedKeyValue.Length);
        Assert.Equal(BlobSpec.SignatureLength, blob.Signature.Length);
    }

    [Fact]
    public void TryLoad_WithWrongLength_Fails()
    {
        var keySpec = CreateKeySpec(new InMemoryKeyInputStorage());

        Assert.False(KeyBlobFactory.TryLoad(new byte[10], keySpec, BlobSpec, out var blob));
        Assert.Null(blob);
    }

    [Fact]
    public void TryLoad_WithTamperedSalt_Fails()
    {
        var keySpec = CreateKeySpec(new InMemoryKeyInputStorage());
        var blobBytes = CreateSignedBlobBytes(keySpec);

        blobBytes[0] ^= 0xFF;

        Assert.False(KeyBlobFactory.TryLoad(blobBytes, keySpec, BlobSpec, out _));
    }

    [Fact]
    public void TryLoad_WithTamperedSignature_Fails()
    {
        var keySpec = CreateKeySpec(new InMemoryKeyInputStorage());
        var blobBytes = CreateSignedBlobBytes(keySpec);

        blobBytes[^1] ^= 0xFF;

        Assert.False(KeyBlobFactory.TryLoad(blobBytes, keySpec, BlobSpec, out _));
    }

    [Fact]
    public void TryLoad_WithTamperedEncryptedKeyValue_SignatureStillValid()
    {
        // The signature covers Salt + MaterialIdentifier + Iterations only, so the encrypted key
        // payload itself is not authenticated by KeyBlobFactory's signature.
        var keySpec = CreateKeySpec(new InMemoryKeyInputStorage());
        var blobBytes = CreateSignedBlobBytes(keySpec);

        blobBytes[BlobSpec.SaltLength] ^= 0xFF;

        Assert.True(KeyBlobFactory.TryLoad(blobBytes, keySpec, BlobSpec, out _));
    }

    [Fact]
    public void TryLoad_WithDifferentMaterialIdentifier_Fails()
    {
        // Share one storage instance so the only variable between the two specs is
        // MaterialIdentifier itself, not each spec deriving from unrelated random key material.
        var storage = new InMemoryKeyInputStorage();
        var keySpec = CreateKeySpec(storage, materialIdentifier: 1);
        var blobBytes = CreateSignedBlobBytes(keySpec);

        var mismatchedSpec = CreateKeySpec(storage, materialIdentifier: 2);

        Assert.False(KeyBlobFactory.TryLoad(blobBytes, mismatchedSpec, BlobSpec, out _));
    }

    [Fact]
    public void TryLoad_WithDifferentIterations_Fails()
    {
        // Shared storage: Iterations isn't part of the storage lookup index, so without sharing
        // one instance here, two fresh InMemoryKeyInputStorage instances would hand out unrelated
        // random key material regardless of Iterations, and the test would pass for the wrong reason.
        var storage = new InMemoryKeyInputStorage();
        var keySpec = CreateKeySpec(storage, iterations: 1);
        var blobBytes = CreateSignedBlobBytes(keySpec);

        var mismatchedSpec = CreateKeySpec(storage, iterations: 2);

        Assert.False(KeyBlobFactory.TryLoad(blobBytes, mismatchedSpec, BlobSpec, out _));
    }

    [Fact]
    public void TryLoad_WithDifferentServiceName_Fails()
    {
        var storage = new InMemoryKeyInputStorage();
        var keySpec = CreateKeySpec(storage, serviceName: ServiceName);
        var blobBytes = CreateSignedBlobBytes(keySpec);

        var mismatchedSpec = CreateKeySpec(storage, serviceName: "other-service");

        Assert.False(KeyBlobFactory.TryLoad(blobBytes, mismatchedSpec, BlobSpec, out _));
    }

    [Fact]
    public void Create_WithWrongPlaintextKeyLength_Throws()
    {
        var keySpec = CreateKeySpec(new InMemoryKeyInputStorage());
        var salt = RandomNumberGenerator.GetBytes(BlobSpec.SaltLength);
        var protector = new KeyProtector(keySpec, salt);

        Assert.Throws<ArgumentException>(() =>
            KeyBlobFactory.Create(RandomNumberGenerator.GetBytes(16), protector, keySpec, BlobSpec, salt));
    }

    [Fact]
    public void Create_WithWrongSaltLength_Throws()
    {
        var keySpec = CreateKeySpec(new InMemoryKeyInputStorage());
        var salt = RandomNumberGenerator.GetBytes(BlobSpec.SaltLength);
        var protector = new KeyProtector(keySpec, salt);

        Assert.Throws<ArgumentException>(() =>
            KeyBlobFactory.Create(RandomNumberGenerator.GetBytes(32), protector, keySpec, BlobSpec, RandomNumberGenerator.GetBytes(16)));
    }

    [Fact]
    public void Create_WhenProtectorProducesWrongLength_Throws()
    {
        var keySpec = CreateKeySpec(new InMemoryKeyInputStorage());
        var salt = RandomNumberGenerator.GetBytes(BlobSpec.SaltLength);

        Assert.Throws<ArgumentException>(() =>
            KeyBlobFactory.Create(RandomNumberGenerator.GetBytes(32), new FixedLengthKeyProtector(1), keySpec, BlobSpec, salt));
    }

    [Fact]
    public void TryLoad_WithZeroLengthSignatureSpec_SkipsSignatureVerification()
    {
        // A BlobSpec with SignatureLength: 0 has nothing to verify, so TryLoad should short-circuit
        // to success as soon as the raw bytes fit the layout - it never calls Sign at all.
        var unsignedSpec = new KeyBlobSpec(
            saltLength: 64, encryptedKeySaltLength: 32, encryptedKeyValueLength: 60, signatureLength: 0);
        var keySpec = CreateKeySpec(new InMemoryKeyInputStorage());
        var salt = RandomNumberGenerator.GetBytes(unsignedSpec.SaltLength);
        var protector = new KeyProtector(keySpec, salt);
        var plaintextKey = RandomNumberGenerator.GetBytes(32);

        var blob = KeyBlobFactory.Create(plaintextKey, protector, keySpec, unsignedSpec, salt);
        var blobBytes = new byte[unsignedSpec.TotalLength];
        blob.Save(blobBytes);

        Assert.True(KeyBlobFactory.TryLoad(blobBytes, keySpec, unsignedSpec, out var loaded));
        Assert.NotNull(loaded);
    }

    // Simulates an IKeyProtector implementation that doesn't honor the KeyBlobSpec's expected
    // wrapped length - exercises KeyBlobFactory.Create's own defensive check against that.
    private sealed class FixedLengthKeyProtector(int length) : IKeyProtector
    {
        public int Encrypt(Span<byte> plaintext, Span<byte> result) => length;
        public int Encrypt(Span<byte> plaintext, IAdditionalAuthData aad, Span<byte> result) => length;
    }
}
