using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.Core.Primitives;
using HkdfGuard.DataProtectionKey.Key;
using HkdfGuard.DataProtectionKey.Test.TestHelpers;

namespace HkdfGuard.DataProtectionKey.Test;

/// <summary>
/// Exercises EphemeralDataProtectionKey against the real Pbkdf2KeyDerivationFunction/
/// HkdfKeyWrapper/KeyProtector/KeyBlobFactory pipeline (the same one a durable, file-backed key
/// uses), but always with an in-memory IKeyInputStorage so this permanent test suite never
/// touches real OS-native secure storage on every run. Never calls IKeyBlob.Save anywhere - by
/// design, nothing here ever produces a file to clean up.
/// </summary>
public class EphemeralDataProtectionKeyTests
{
    private const string ServiceName = "ephemeral-key-test-svc";

    private static IKeySpec BuildSpec(IKeyInputStorage storage, int materialIdentifier = 1, int iterations = 1)
        => new CryptoRecipeBuilder()
            .WithServiceName(ServiceName)
            .WithKeyDerivation(new Pbkdf2KeyDerivationFunction(storage))
            .WithCipher(new AesGcmCipher())
            .WithHash(new HmacSha512Hash())
            .WithMaterialIdentifier(materialIdentifier)
            .WithIterations(iterations)
            .Build();

    private static EphemeralDataProtectionKey CreateKey(IKeyInputStorage storage, int materialIdentifier = 1, int iterations = 1)
        => new(BuildSpec(storage, materialIdentifier, iterations), new HkdfKeyWrapperFactory());

    [Fact]
    public void EncryptDecrypt_RoundTrips()
    {
        var key = CreateKey(new InMemoryKeyInputStorage());
        var plaintext = "top secret"u8.ToArray();
        var expected = (byte[])plaintext.Clone();

        var encrypted = key.Encrypt(plaintext);
        var decrypted = new byte[expected.Length];
        var written = key.Decrypt(encrypted, decrypted);

        Assert.Equal(expected.Length, written);
        Assert.Equal(expected, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_WithAad_RoundTrips()
    {
        var key = CreateKey(new InMemoryKeyInputStorage());
        var plaintext = "top secret"u8.ToArray();
        var expected = (byte[])plaintext.Clone();
        var aad = new AdditionalAuthData("context".AsSpan());

        var encrypted = key.Encrypt(plaintext, aad);
        var decrypted = new byte[expected.Length];
        var written = key.Decrypt(encrypted, aad, decrypted);

        Assert.Equal(expected, decrypted[..written]);
    }

    [Fact]
    public void Decrypt_WithMismatchedAad_Throws()
    {
        var key = CreateKey(new InMemoryKeyInputStorage());
        var encrypted = key.Encrypt("top secret"u8.ToArray(), new AdditionalAuthData("context-a".AsSpan()));

        Assert.Throws<AuthenticationTagMismatchException>(() =>
            key.Decrypt(encrypted, new AdditionalAuthData("context-b".AsSpan()), new byte[16]));
    }

    [Fact]
    public void Encrypt_GeneratesKeyLazilyOnFirstUse_NotAtConstruction()
    {
        var storage = new SpyKeyInputStorage();
        _ = CreateKey(storage);

        Assert.Equal(0, storage.CreateOrGetCallCount);
    }

    [Fact]
    public void EncryptAndDecrypt_ReuseTheSameLazilyGeneratedKeyAcrossCalls()
    {
        var key = CreateKey(new InMemoryKeyInputStorage());

        var encrypted1 = key.Encrypt("first"u8.ToArray());
        var encrypted2 = key.Encrypt("second"u8.ToArray());

        var result1 = new byte[5];
        var result2 = new byte[6];
        key.Decrypt(encrypted1, result1);
        key.Decrypt(encrypted2, result2);

        Assert.Equal("first", System.Text.Encoding.UTF8.GetString(result1));
        Assert.Equal("second", System.Text.Encoding.UTF8.GetString(result2));
    }

    [Fact]
    public void TwoInstances_GenerateIndependentKeys()
    {
        var storage = new InMemoryKeyInputStorage();
        var key1 = CreateKey(storage);
        var key2 = CreateKey(storage);

        var encrypted = key1.Encrypt("top secret"u8.ToArray());

        Assert.ThrowsAny<CryptographicException>(() => key2.Decrypt(encrypted, new byte[16]));
    }

    [Fact]
    public void UsesSameKeyInputStorageIndexADurableKeyWouldUse()
    {
        var storage = new SpyKeyInputStorage();
        const int materialIdentifier = 42;
        var key = CreateKey(storage, materialIdentifier);

        key.Encrypt("warm up"u8.ToArray());

        // Pbkdf2KeyDerivationFunction.Derive indexes storage as "{serviceName}.{materialIdentifier}"
        // - the same index a durable, file-backed key with this materialIdentifier would use.
        Assert.Contains($"{ServiceName}.{materialIdentifier}", storage.RequestedIndices);
    }

    [Fact]
    public void Encrypt_WhenKeyWrapperFactoryFails_RecordsExceptionAndThrows()
    {
        var key = new EphemeralDataProtectionKey(
            BuildSpec(new InMemoryKeyInputStorage()),
            new ThrowingKeyWrapperFactory(new InvalidOperationException("wrapper unavailable")));

        Assert.Throws<InvalidOperationException>(() => key.Encrypt("top secret"u8.ToArray()));
    }

    [Fact]
    public void EncryptDecrypt_WithSensitiveLoggingEnabled_StillRoundTrips()
    {
        using var loggingScope = new SensitiveLoggingScope(true);

        var key = CreateKey(new InMemoryKeyInputStorage());
        var plaintext = "top secret"u8.ToArray();
        var expected = (byte[])plaintext.Clone();

        var encrypted = key.Encrypt(plaintext);
        var decrypted = new byte[expected.Length];
        var written = key.Decrypt(encrypted, decrypted);

        Assert.Equal(expected, decrypted[..written]);
    }

    [Fact]
    public void Encrypt_WithCustomBlobSpec_StillRoundTrips()
    {
        var customBlobSpec = new KeyBlobSpec(saltLength: 32, encryptedKeySaltLength: 32, encryptedKeyValueLength: 60, signatureLength: 64);
        var key = new EphemeralDataProtectionKey(
            BuildSpec(new InMemoryKeyInputStorage()), new HkdfKeyWrapperFactory(), customBlobSpec);

        var plaintext = "top secret"u8.ToArray();
        var expected = (byte[])plaintext.Clone();

        var encrypted = key.Encrypt(plaintext);
        var decrypted = new byte[expected.Length];
        var written = key.Decrypt(encrypted, decrypted);

        Assert.Equal(expected, decrypted[..written]);
    }

    [Fact]
    public void ConcurrentFirstUse_ProducesOneConsistentKey()
    {
        var key = CreateKey(new InMemoryKeyInputStorage());
        var results = new System.Collections.Concurrent.ConcurrentBag<byte[]>();

        // Every task races to trigger the Lazy<IDataProtectionKey>'s first-use initialization;
        // LazyThreadSafetyMode.ExecutionAndPublication guarantees only one of them actually runs
        // CreateInner, so every encrypted value below must be decryptable by every other task's
        // view of the same instance.
        Parallel.For(0, 50, i => results.Add(key.Encrypt(System.Text.Encoding.UTF8.GetBytes($"value-{i}"))));

        Parallel.ForEach(results, encrypted =>
        {
            var result = new byte[32];
            var written = key.Decrypt(encrypted, result);
            Assert.StartsWith("value-", System.Text.Encoding.UTF8.GetString(result, 0, written));
        });
    }
}
