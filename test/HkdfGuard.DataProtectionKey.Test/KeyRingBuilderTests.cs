using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.Core.Primitives;
using HkdfGuard.DataProtectionKey.KeyTracking;
using HkdfGuard.DataProtectionKey.Test.TestHelpers;

namespace HkdfGuard.DataProtectionKey.Test;

/// <summary>
/// Exercises KeyRingBuilder against real, on-disk protected key files, built via the same
/// KeyBlobFactory/CryptoRecipeBuilder pipeline HkdfGuard.Initializer uses - but always with
/// an in-memory IKeyInputStorage, so this permanent test suite never touches real OS-native
/// secure storage (Keychain/Credential Manager/systemd-creds) on every run.
/// </summary>
public class KeyRingBuilderTests
{
    private const string ServiceName = "keyring-builder-test-svc";
    private static readonly KeyBlobSpec DefaultBlobSpec = new(
        saltLength: 64, encryptedKeySaltLength: 32, encryptedKeyValueLength: 60, signatureLength: 32);

    private static ICryptoRecipeBuilder CreateRecipe(IKeyInputStorage storage)
        => new CryptoRecipeBuilder()
            .WithServiceName(ServiceName)
            .WithKeyDerivation(new Pbkdf2KeyDerivationFunction(storage))
            .WithCipher(new AesGcmCipher())
            .WithHash(new HmacSha256Hash());

    private static IKeySpec BuildSpec(IKeyInputStorage storage, int materialIdentifier, int iterations)
        => CreateRecipe(storage)
            .WithMaterialIdentifier(materialIdentifier)
            .WithIterations(iterations)
            .Build();

    private static string ProtectKeyFile(TempDirectory tempDir, string fileName, IKeySpec spec, KeyBlobSpec? blobSpec = null)
    {
        var effectiveBlobSpec = blobSpec ?? DefaultBlobSpec;
        var salt = RandomNumberGenerator.GetBytes(effectiveBlobSpec.SaltLength);
        var protector = new KeyProtectorFactory().Create(spec, salt);
        var plaintextKey = RandomNumberGenerator.GetBytes(32);

        var blob = KeyBlobFactory.Create((byte[])plaintextKey.Clone(), protector, spec, effectiveBlobSpec, salt);
        var bytes = new byte[effectiveBlobSpec.TotalLength];
        blob.Save(bytes);

        var path = tempDir.GetFilePath(fileName);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    [Fact]
    public void Build_WithoutCryptoRecipe_ThrowsInvalidOperationException()
    {
        var builder = new KeyRingBuilder().WithKeyWrapperFactory(new HkdfKeyWrapperFactory());

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void Build_WithoutKeyWrapperFactory_ThrowsInvalidOperationException()
    {
        var recipe = CreateRecipe(new InMemoryKeyInputStorage())
            .WithMaterialIdentifier(1)
            .WithIterations(1);

        var builder = new KeyRingBuilder().WithCryptoRecipe(recipe);

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void Build_WithValidKeyFile_ProducesWorkingKeyRing()
    {
        using var tempDir = new TempDirectory();
        var storage = new InMemoryKeyInputStorage();
        const int materialIdentifier = 4, iterations = 2;

        var spec = BuildSpec(storage, materialIdentifier, iterations);
        var path = ProtectKeyFile(tempDir, "v1.key", spec);

        var ring = new KeyRingBuilder()
            .WithCryptoRecipe(CreateRecipe(storage))
            .WithKeyWrapperFactory(new HkdfKeyWrapperFactory())
            .AddKeyFile(1, path, materialIdentifier, iterations)
            .Build();

        var protector = ring.CreateProtector("purpose");
        var formatted = protector.Encrypt("hello".AsSpan());
        Span<char> result = new char[protector.GetMaxDecryptedLength(formatted.AsSpan())];
        var written = protector.Decrypt(formatted.AsSpan(), result);

        Assert.Equal("hello", new string(result[..written]));
    }

    [Fact]
    public void Build_WithMultipleKeyFiles_HighestVersionBecomesCurrent()
    {
        using var tempDir = new TempDirectory();
        var storage = new InMemoryKeyInputStorage();

        var spec1 = BuildSpec(storage, materialIdentifier: 1, iterations: 1);
        var spec2 = BuildSpec(storage, materialIdentifier: 2, iterations: 1);
        var path1 = ProtectKeyFile(tempDir, "v1.key", spec1);
        var path2 = ProtectKeyFile(tempDir, "v2.key", spec2);

        var ring = new KeyRingBuilder()
            .WithCryptoRecipe(CreateRecipe(storage))
            .WithKeyWrapperFactory(new HkdfKeyWrapperFactory())
            .AddKeyFile(1, path1, 1, 1)
            .AddKeyFile(2, path2, 2, 1)
            .Build();

        Assert.Equal(2, ring.CurrentVersion);

        var formatted = ring.CreateProtector("purpose").Encrypt("newest key".AsSpan());
        Assert.Contains("::v2::", formatted);
    }

    [Fact]
    public void Build_WithMismatchedIterations_ThrowsCryptographicException()
    {
        using var tempDir = new TempDirectory();
        var storage = new InMemoryKeyInputStorage();
        const int materialIdentifier = 5;

        var spec = BuildSpec(storage, materialIdentifier, iterations: 2);
        var path = ProtectKeyFile(tempDir, "v1.key", spec);

        var builder = new KeyRingBuilder()
            .WithCryptoRecipe(CreateRecipe(storage))
            .WithKeyWrapperFactory(new HkdfKeyWrapperFactory())
            .AddKeyFile(1, path, materialIdentifier, iterations: 999);

        Assert.Throws<CryptographicException>(() => builder.Build());
    }

    [Fact]
    public void Build_WithMismatchedMaterialIdentifier_ThrowsCryptographicException()
    {
        using var tempDir = new TempDirectory();
        var storage = new InMemoryKeyInputStorage();

        var spec = BuildSpec(storage, materialIdentifier: 6, iterations: 1);
        var path = ProtectKeyFile(tempDir, "v1.key", spec);

        var builder = new KeyRingBuilder()
            .WithCryptoRecipe(CreateRecipe(storage))
            .WithKeyWrapperFactory(new HkdfKeyWrapperFactory())
            .AddKeyFile(1, path, materialIdentifier: 999, iterations: 1);

        Assert.Throws<CryptographicException>(() => builder.Build());
    }

    [Fact]
    public void Build_WithCustomBlobSpec_ReadsMatchingLayout()
    {
        using var tempDir = new TempDirectory();
        var storage = new InMemoryKeyInputStorage();
        const int materialIdentifier = 9, iterations = 1;
        var customBlobSpec = new KeyBlobSpec(saltLength: 32, encryptedKeySaltLength: 32, encryptedKeyValueLength: 60, signatureLength: 32);

        var spec = BuildSpec(storage, materialIdentifier, iterations);
        var path = ProtectKeyFile(tempDir, "v1.key", spec, customBlobSpec);

        var ring = new KeyRingBuilder()
            .WithCryptoRecipe(CreateRecipe(storage))
            .WithKeyWrapperFactory(new HkdfKeyWrapperFactory())
            .WithBlobSpec(customBlobSpec)
            .AddKeyFile(1, path, materialIdentifier, iterations)
            .Build();

        Assert.Equal(1, ring.CurrentVersion);
    }

    [Fact]
    public void Build_WithDefaultBlobSpec_RejectsFileWrittenWithDifferentLayout()
    {
        using var tempDir = new TempDirectory();
        var storage = new InMemoryKeyInputStorage();
        const int materialIdentifier = 10, iterations = 1;
        var customBlobSpec = new KeyBlobSpec(saltLength: 32, encryptedKeySaltLength: 32, encryptedKeyValueLength: 60, signatureLength: 32);

        var spec = BuildSpec(storage, materialIdentifier, iterations);
        var path = ProtectKeyFile(tempDir, "v1.key", spec, customBlobSpec);

        // Built WITHOUT WithBlobSpec, so it expects the default 64-byte-salt layout, but the file
        // on disk was written with a 32-byte salt - lengths won't match.
        var builder = new KeyRingBuilder()
            .WithCryptoRecipe(CreateRecipe(storage))
            .WithKeyWrapperFactory(new HkdfKeyWrapperFactory())
            .AddKeyFile(1, path, materialIdentifier, iterations);

        Assert.Throws<CryptographicException>(() => builder.Build());
    }

    [Fact]
    public void Build_WithEphemeralKeyWithoutKeyProtectorFactory_ThrowsInvalidOperationException()
    {
        var storage = new InMemoryKeyInputStorage();

        var builder = new KeyRingBuilder()
            .WithCryptoRecipe(CreateRecipe(storage))
            .WithKeyWrapperFactory(new HkdfKeyWrapperFactory())
            .AddEphemeralKey(1, materialIdentifier: 1, iterations: 1);

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void Build_WithEphemeralKey_ProducesWorkingKeyRing()
    {
        var storage = new InMemoryKeyInputStorage();

        var ring = new KeyRingBuilder()
            .WithCryptoRecipe(CreateRecipe(storage))
            .WithKeyWrapperFactory(new HkdfKeyWrapperFactory())
            .WithKeyProtectorFactory(new KeyProtectorFactory())
            .AddEphemeralKey(1, materialIdentifier: 1, iterations: 1)
            .Build();

        var protector = ring.CreateProtector("purpose");
        var formatted = protector.Encrypt("hello".AsSpan());
        Span<char> result = new char[protector.GetMaxDecryptedLength(formatted.AsSpan())];
        var written = protector.Decrypt(formatted.AsSpan(), result);

        Assert.Equal("hello", new string(result[..written]));
    }

    [Fact]
    public void Build_WithKeyFileAndHigherVersionEphemeralKey_EphemeralBecomesCurrent()
    {
        using var tempDir = new TempDirectory();
        var storage = new InMemoryKeyInputStorage();

        var spec1 = BuildSpec(storage, materialIdentifier: 1, iterations: 1);
        var path1 = ProtectKeyFile(tempDir, "v1.key", spec1);

        var ring = new KeyRingBuilder()
            .WithCryptoRecipe(CreateRecipe(storage))
            .WithKeyWrapperFactory(new HkdfKeyWrapperFactory())
            .WithKeyProtectorFactory(new KeyProtectorFactory())
            .AddKeyFile(1, path1, materialIdentifier: 1, iterations: 1)
            .AddEphemeralKey(2, materialIdentifier: 2, iterations: 1)
            .Build();

        Assert.Equal(2, ring.CurrentVersion);

        var formatted = ring.CreateProtector("purpose").Encrypt("newest key".AsSpan());
        Assert.Contains("::v2::", formatted);
    }

    [Fact]
    public void Build_WithEphemeralKeyReusingKeyFileVersion_ThrowsArgumentException()
    {
        using var tempDir = new TempDirectory();
        var storage = new InMemoryKeyInputStorage();

        var spec1 = BuildSpec(storage, materialIdentifier: 1, iterations: 1);
        var path1 = ProtectKeyFile(tempDir, "v1.key", spec1);

        var builder = new KeyRingBuilder()
            .WithCryptoRecipe(CreateRecipe(storage))
            .WithKeyWrapperFactory(new HkdfKeyWrapperFactory())
            .WithKeyProtectorFactory(new KeyProtectorFactory())
            .AddKeyFile(1, path1, materialIdentifier: 1, iterations: 1)
            .AddEphemeralKey(1, materialIdentifier: 2, iterations: 1);

        Assert.Throws<ArgumentException>(() => builder.Build());
    }

    [Fact]
    public void Build_WithMultipleEphemeralKeys_EachHasIndependentMaterial()
    {
        var storage = new InMemoryKeyInputStorage();

        var ring = new KeyRingBuilder()
            .WithCryptoRecipe(CreateRecipe(storage))
            .WithKeyWrapperFactory(new HkdfKeyWrapperFactory())
            .WithKeyProtectorFactory(new KeyProtectorFactory())
            .AddEphemeralKey(1, materialIdentifier: 1, iterations: 1)
            .AddEphemeralKey(2, materialIdentifier: 2, iterations: 1)
            .Build();

        var formattedV2 = ring.CreateProtector("purpose").Encrypt("hello".AsSpan());
        Assert.Contains("::v2::", formattedV2);

        var v1Key = ring.Get(1);
        var v2Key = ring.Get(2);
        var encrypted1 = v1Key.Encrypt("hello"u8.ToArray());
        var result = new byte[16];
        Assert.Throws<AuthenticationTagMismatchException>(() => v2Key.Decrypt(encrypted1, result));
    }

    [Fact]
    public void Build_WithCustomFormatProvider_UsesItForCreateProtector()
    {
        using var tempDir = new TempDirectory();
        var storage = new InMemoryKeyInputStorage();
        const int materialIdentifier = 3, iterations = 1;
        var recordingFormatProvider = new RecordingFormatProvider();

        var spec = BuildSpec(storage, materialIdentifier, iterations);
        var path = ProtectKeyFile(tempDir, "v1.key", spec);

        var ring = new KeyRingBuilder()
            .WithCryptoRecipe(CreateRecipe(storage))
            .WithKeyWrapperFactory(new HkdfKeyWrapperFactory())
            .WithFormatProvider(recordingFormatProvider)
            .AddKeyFile(1, path, materialIdentifier, iterations)
            .Build();

        ring.CreateProtector("purpose").Encrypt("hello".AsSpan());

        Assert.True(recordingFormatProvider.FormatCalled);
    }
}
