using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using HkdfGuard.Abstractions;
using HkdfGuard.Options.Test.TestHelpers;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.Core.Primitives;

namespace HkdfGuard.Options.Test;

public class HkdfGuardKeyRingFactoryTests
{
    private const string ServiceName = "config-factory-test-svc";
    private static readonly KeyBlobSpec BlobSpec = new(
        saltLength: 64, encryptedKeySaltLength: 32, encryptedKeyValueLength: 60, signatureLength: 32);

    // Every test drives real KeyBlobFactory/KeyRingBuilder/HkdfKeyWrapper code paths, but replaces
    // the "Pbkdf2" registry entry with one backed by InMemoryKeyInputStorage, so nothing here ever
    // touches real OS-native secure storage (Keychain/Credential Manager/systemd-creds).
    private static CryptoComponentRegistry CreateInMemoryRegistry(IKeyInputStorage storage)
    {
        var registry = new CryptoComponentRegistry();
        registry.RegisterKeyDerivation("Pbkdf2", _ => new Pbkdf2KeyDerivationFunction(storage));
        return registry;
    }

    private static IKeySpec BuildSpec(IKeyInputStorage storage, int materialIdentifier, int iterations)
        => new CryptoRecipeBuilder()
            .WithServiceName(ServiceName)
            .WithKeyDerivation(new Pbkdf2KeyDerivationFunction(storage))
            .WithCipher(new AesGcmCipher())
            .WithHash(new HmacSha256Hash())
            .WithMaterialIdentifier(materialIdentifier)
            .WithIterations(iterations)
            .Build();

    private static string ProtectKeyFile(TempDirectory tempDir, string fileName, IKeySpec spec)
    {
        var salt = RandomNumberGenerator.GetBytes(BlobSpec.SaltLength);
        var protector = new KeyProtectorFactory().Create(spec, salt);
        var plaintextKey = RandomNumberGenerator.GetBytes(32);

        var blob = KeyBlobFactory.Create((byte[])plaintextKey.Clone(), protector, spec, BlobSpec, salt);
        var bytes = new byte[BlobSpec.TotalLength];
        blob.Save(bytes);

        var path = tempDir.GetFilePath(fileName);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    [Fact]
    public void Build_FromOptions_ProducesWorkingKeyRing()
    {
        using var tempDir = new TempDirectory();
        var storage = new InMemoryKeyInputStorage();
        const int materialIdentifier = 4, iterations = 2;

        var spec = BuildSpec(storage, materialIdentifier, iterations);
        var path = ProtectKeyFile(tempDir, "v1.key", spec);

        var options = new HkdfGuardOptions
        {
            ServiceName = ServiceName,
            KeyFiles = { new KeyFileOptions { Version = 1, Path = path, MaterialIdentifier = materialIdentifier, Iterations = iterations } }
        };

        var ring = new HkdfGuardKeyRingFactory(CreateInMemoryRegistry(storage)).Build(options);

        var protector = ring.CreateProtector("cookie-auth");
        var formatted = protector.Encrypt("hello from HkdfGuardKeyRingFactory".AsSpan());
        Span<char> result = new char[protector.GetMaxDecryptedLength(formatted.AsSpan())];
        var written = protector.Decrypt(formatted.AsSpan(), result);

        Assert.Equal("hello from HkdfGuardKeyRingFactory", new string(result[..written]));
    }

    [Fact]
    public void Build_WithIOptionsOverload_ProducesEquivalentKeyRing()
    {
        using var tempDir = new TempDirectory();
        var storage = new InMemoryKeyInputStorage();
        const int materialIdentifier = 6, iterations = 1;

        var spec = BuildSpec(storage, materialIdentifier, iterations);
        var path = ProtectKeyFile(tempDir, "v1.key", spec);

        var options = new HkdfGuardOptions
        {
            ServiceName = ServiceName,
            KeyFiles = { new KeyFileOptions { Version = 1, Path = path, MaterialIdentifier = materialIdentifier, Iterations = iterations } }
        };

        var ring = new HkdfGuardKeyRingFactory(CreateInMemoryRegistry(storage)).Build(Microsoft.Extensions.Options.Options.Create(options));

        var protector = ring.CreateProtector("cookie-auth");
        var formatted = protector.Encrypt("via IOptions".AsSpan());
        Span<char> result = new char[protector.GetMaxDecryptedLength(formatted.AsSpan())];
        var written = protector.Decrypt(formatted.AsSpan(), result);

        Assert.Equal("via IOptions", new string(result[..written]));
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

        var options = new HkdfGuardOptions
        {
            ServiceName = ServiceName,
            KeyFiles =
            {
                new KeyFileOptions { Version = 1, Path = path1, MaterialIdentifier = 1, Iterations = 1 },
                new KeyFileOptions { Version = 2, Path = path2, MaterialIdentifier = 2, Iterations = 1 }
            }
        };

        var ring = new HkdfGuardKeyRingFactory(CreateInMemoryRegistry(storage)).Build(options);

        Assert.Equal(2, ring.CurrentVersion);

        var protector = ring.CreateProtector("cookie-auth");
        var formatted = protector.Encrypt("newest key".AsSpan());
        Assert.Contains("::v2::", formatted);
    }

    [Fact]
    public void Build_WithUnknownCipherName_ThrowsNotSupportedException()
    {
        var options = new HkdfGuardOptions
        {
            ServiceName = ServiceName,
            Cipher = "NotARealCipher",
            KeyFiles = { new KeyFileOptions { Version = 1, Path = "irrelevant.key", MaterialIdentifier = 1, Iterations = 1 } }
        };

        // Component resolution happens before any file is touched, so this never reads the disk.
        var ex = Assert.Throws<NotSupportedException>(() => new HkdfGuardKeyRingFactory().Build(options));
        Assert.Contains("NotARealCipher", ex.Message);
    }

    [Fact]
    public void Build_WithMismatchedIterations_ThrowsCryptographicException()
    {
        using var tempDir = new TempDirectory();
        var storage = new InMemoryKeyInputStorage();
        const int materialIdentifier = 8;

        var spec = BuildSpec(storage, materialIdentifier, iterations: 3);
        var path = ProtectKeyFile(tempDir, "v1.key", spec);

        var options = new HkdfGuardOptions
        {
            ServiceName = ServiceName,
            KeyFiles = { new KeyFileOptions { Version = 1, Path = path, MaterialIdentifier = materialIdentifier, Iterations = 999 } }
        };

        Assert.Throws<CryptographicException>(() => new HkdfGuardKeyRingFactory(CreateInMemoryRegistry(storage)).Build(options));
    }

    [Fact]
    public void Build_WithCustomRegistry_UsesReplacedComponent()
    {
        var invocationCount = 0;
        var registry = new CryptoComponentRegistry();
        registry.RegisterCipher("AesGcm", () =>
        {
            invocationCount++;
            return new AesGcmCipher();
        });

        var options = new HkdfGuardOptions { ServiceName = ServiceName };
        new HkdfGuardKeyRingFactory(registry).Build(options);

        Assert.Equal(1, invocationCount);
    }

    [Fact]
    public void Build_WithEphemeralKey_ProducesWorkingKeyRing()
    {
        var storage = new InMemoryKeyInputStorage();
        var options = new HkdfGuardOptions
        {
            ServiceName = ServiceName,
            EphemeralKeys = { new EphemeralKeyOptions { Version = 1, MaterialIdentifier = 1, Iterations = 1 } }
        };

        var ring = new HkdfGuardKeyRingFactory(CreateInMemoryRegistry(storage)).Build(options);

        var protector = ring.CreateProtector("cookie-auth");
        var formatted = protector.Encrypt("hello from an ephemeral key".AsSpan());
        Span<char> result = new char[protector.GetMaxDecryptedLength(formatted.AsSpan())];
        var written = protector.Decrypt(formatted.AsSpan(), result);

        Assert.Equal("hello from an ephemeral key", new string(result[..written]));
    }

    [Fact]
    public void Build_WithKeyFileAndHigherVersionEphemeralKey_EphemeralBecomesCurrent()
    {
        using var tempDir = new TempDirectory();
        var storage = new InMemoryKeyInputStorage();
        const int materialIdentifier = 11, iterations = 1;

        var spec = BuildSpec(storage, materialIdentifier, iterations);
        var path = ProtectKeyFile(tempDir, "v1.key", spec);

        var options = new HkdfGuardOptions
        {
            ServiceName = ServiceName,
            KeyFiles = { new KeyFileOptions { Version = 1, Path = path, MaterialIdentifier = materialIdentifier, Iterations = iterations } },
            EphemeralKeys = { new EphemeralKeyOptions { Version = 2, MaterialIdentifier = 12, Iterations = 1 } }
        };

        var ring = new HkdfGuardKeyRingFactory(CreateInMemoryRegistry(storage)).Build(options);

        Assert.Equal(2, ring.CurrentVersion);
    }

    [Fact]
    public void Build_WithUnknownKeyProtectorFactoryName_ThrowsNotSupportedException()
    {
        var options = new HkdfGuardOptions
        {
            ServiceName = ServiceName,
            KeyProtectorFactory = "NotARealProtector",
            EphemeralKeys = { new EphemeralKeyOptions { Version = 1, MaterialIdentifier = 1, Iterations = 1 } }
        };

        var ex = Assert.Throws<NotSupportedException>(() => new HkdfGuardKeyRingFactory().Build(options));
        Assert.Contains("NotARealProtector", ex.Message);
    }

    [Fact]
    public void Build_WithNoEphemeralKeys_NeverResolvesKeyProtectorFactory()
    {
        // KeyProtectorFactory defaults to "Default", which is always registered - if Build ever
        // resolved it unconditionally, this would still pass. Configuring an unknown name proves
        // it's only resolved when EphemeralKeys is actually non-empty.
        var options = new HkdfGuardOptions
        {
            ServiceName = ServiceName,
            KeyProtectorFactory = "NotARealProtector"
        };

        var ring = new HkdfGuardKeyRingFactory().Build(options);

        Assert.Throws<InvalidOperationException>(() => ring.CurrentVersion);
    }

    [Fact]
    public void Build_WithDefaultConstructor_ResolvesBuiltInComponentsWithoutTouchingAnyFile()
    {
        // No KeyFiles registered, so KeyRingBuilder never reads a file or derives a key - this
        // only proves the default (no custom registry) constructor path resolves all four
        // built-in component names successfully.
        var factory = new HkdfGuardKeyRingFactory();
        var options = new HkdfGuardOptions { ServiceName = ServiceName };

        var ring = factory.Build(options);

        Assert.Throws<InvalidOperationException>(() => ring.CurrentVersion);
    }
}
