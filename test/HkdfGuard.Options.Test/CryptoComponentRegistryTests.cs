using HkdfGuard.Abstractions;
using HkdfGuard.Core.Cryptography;

namespace HkdfGuard.Options.Test;

public class CryptoComponentRegistryTests
{
    // Constructing a Pbkdf2KeyDerivationFunction/its IKeyInputStorage never touches real OS-native
    // storage - only calling Derive() does - so resolving the built-in "Pbkdf2" entry here is safe
    // without an in-memory override, as long as the test never calls Derive.
    [Fact]
    public void CreateKeyDerivation_BuiltInPbkdf2_ResolvesCorrectType()
    {
        var registry = new CryptoComponentRegistry();

        var result = registry.CreateKeyDerivation("Pbkdf2", "some-service");

        Assert.IsType<Pbkdf2KeyDerivationFunction>(result);
    }

    [Fact]
    public void CreateKeyDerivation_UnknownName_ThrowsNotSupportedException()
    {
        var registry = new CryptoComponentRegistry();

        var ex = Assert.Throws<NotSupportedException>(() => registry.CreateKeyDerivation("DoesNotExist", "svc"));
        Assert.Contains("DoesNotExist", ex.Message);
        Assert.Contains("Pbkdf2", ex.Message);
    }

    [Fact]
    public void CreateCipher_BuiltInAesGcm_ResolvesCorrectType()
    {
        var registry = new CryptoComponentRegistry();

        Assert.IsType<AesGcmCipher>(registry.CreateCipher("AesGcm"));
    }

    [Fact]
    public void CreateCipher_UnknownName_ThrowsNotSupportedException()
    {
        var registry = new CryptoComponentRegistry();

        var ex = Assert.Throws<NotSupportedException>(() => registry.CreateCipher("DoesNotExist"));
        Assert.Contains("DoesNotExist", ex.Message);
        Assert.Contains("AesGcm", ex.Message);
    }

    [Fact]
    public void CreateHash_BuiltInHmacSha512_ResolvesCorrectType()
    {
        var registry = new CryptoComponentRegistry();

        Assert.IsType<HmacSha512Hash>(registry.CreateHash("HmacSha512"));
    }

    [Fact]
    public void CreateHash_UnknownName_ThrowsNotSupportedException()
    {
        var registry = new CryptoComponentRegistry();

        var ex = Assert.Throws<NotSupportedException>(() => registry.CreateHash("DoesNotExist"));
        Assert.Contains("DoesNotExist", ex.Message);
        Assert.Contains("HmacSha512", ex.Message);
    }

    [Fact]
    public void CreateKeyWrapperFactory_BuiltInHkdf_ResolvesCorrectType()
    {
        var registry = new CryptoComponentRegistry();

        Assert.IsType<HkdfKeyWrapperFactory>(registry.CreateKeyWrapperFactory("Hkdf"));
    }

    [Fact]
    public void CreateKeyWrapperFactory_UnknownName_ThrowsNotSupportedException()
    {
        var registry = new CryptoComponentRegistry();

        var ex = Assert.Throws<NotSupportedException>(() => registry.CreateKeyWrapperFactory("DoesNotExist"));
        Assert.Contains("DoesNotExist", ex.Message);
        Assert.Contains("Hkdf", ex.Message);
    }

    [Fact]
    public void RegisterCipher_WithNewName_AddsOptionAlongsideBuiltIns()
    {
        var registry = new CryptoComponentRegistry();
        registry.RegisterCipher("MyCustomCipher", () => new AesGcmCipher());

        var custom = registry.CreateCipher("MyCustomCipher");
        var builtIn = registry.CreateCipher("AesGcm");

        Assert.IsType<AesGcmCipher>(custom);
        Assert.IsType<AesGcmCipher>(builtIn);
    }

    [Fact]
    public void RegisterCipher_WithExistingBuiltInName_ReplacesIt()
    {
        var registry = new CryptoComponentRegistry();
        var invocationCount = 0;

        registry.RegisterCipher("AesGcm", () =>
        {
            invocationCount++;
            return new AesGcmCipher();
        });

        registry.CreateCipher("AesGcm");

        Assert.Equal(1, invocationCount);
    }

    [Fact]
    public void RegisterKeyDerivation_WithNewName_ResolvesCustomFactory()
    {
        var registry = new CryptoComponentRegistry();
        var receivedServiceName = string.Empty;

        registry.RegisterKeyDerivation("Custom", serviceName =>
        {
            receivedServiceName = serviceName;
            return new Pbkdf2KeyDerivationFunction(new TestHelpers.InMemoryKeyInputStorage());
        });

        var result = registry.CreateKeyDerivation("Custom", "my-service");

        Assert.IsType<Pbkdf2KeyDerivationFunction>(result);
        Assert.Equal("my-service", receivedServiceName);
    }

    [Fact]
    public void RegisterHash_WithExistingBuiltInName_ReplacesIt()
    {
        var registry = new CryptoComponentRegistry();
        IHash replacement = new HmacSha512Hash();

        registry.RegisterHash("HmacSha512", () => replacement);

        Assert.Same(replacement, registry.CreateHash("HmacSha512"));
    }

    [Fact]
    public void RegisterKeyWrapperFactory_WithExistingBuiltInName_ReplacesIt()
    {
        var registry = new CryptoComponentRegistry();
        IKeyWrapperFactory replacement = new HkdfKeyWrapperFactory();

        registry.RegisterKeyWrapperFactory("Hkdf", () => replacement);

        Assert.Same(replacement, registry.CreateKeyWrapperFactory("Hkdf"));
    }

    [Fact]
    public void UnknownNameException_ListsCurrentlyRegisteredNames_NotJustBuiltIns()
    {
        var registry = new CryptoComponentRegistry();
        registry.RegisterCipher("MyCustomCipher", () => new AesGcmCipher());

        var ex = Assert.Throws<NotSupportedException>(() => registry.CreateCipher("DoesNotExist"));

        Assert.Contains("AesGcm", ex.Message);
        Assert.Contains("MyCustomCipher", ex.Message);
    }
}
