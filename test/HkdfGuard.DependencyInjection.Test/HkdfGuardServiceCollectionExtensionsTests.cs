using HkdfGuard.DataProtectionKey.KeyTracking;
using HkdfGuard.DependencyInjection.Test.TestHelpers;
using HkdfGuard.Options;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace HkdfGuard.DependencyInjection.Test;

public class HkdfGuardServiceCollectionExtensionsTests
{
    [Fact]
    public void AddHkdfGuard_ReturnsSameServiceCollection_ForFluentChaining()
    {
        var services = new ServiceCollection();

        var returned = services.AddHkdfGuard();

        Assert.Same(services, returned);
    }

    [Fact]
    public void AddHkdfGuard_WithConfigureCallback_ReturnsSameServiceCollection()
    {
        var services = new ServiceCollection();

        var returned = services.AddHkdfGuard(_ => { });

        Assert.Same(services, returned);
    }

    [Fact]
    public void AddHkdfGuard_RegistersKeyRingAsSingleton()
    {
        var services = new ServiceCollection();
        services.AddHkdfGuard(builder => builder.Configure(options => options.ServiceName = "svc"));
        using var provider = services.BuildServiceProvider();

        var ring1 = provider.GetRequiredService<KeyRing>();
        var ring2 = provider.GetRequiredService<KeyRing>();

        Assert.Same(ring1, ring2);
    }

    [Fact]
    public void AddHkdfGuard_WithNoKeys_ResolvesKeyRingWithNoCurrentVersion()
    {
        var services = new ServiceCollection();
        services.AddHkdfGuard(builder => builder.Configure(options => options.ServiceName = "svc"));
        using var provider = services.BuildServiceProvider();

        var ring = provider.GetRequiredService<KeyRing>();

        Assert.Throws<InvalidOperationException>(() => ring.CurrentVersion);
    }

    [Fact]
    public void AddHkdfGuard_RegistersCryptoComponentRegistryAsSingleton_SameInstanceBuilderExposes()
    {
        var services = new ServiceCollection();
        IHkdfGuardBuilder? capturedBuilder = null;
        services.AddHkdfGuard(builder => capturedBuilder = builder);
        using var provider = services.BuildServiceProvider();

        var resolved = provider.GetRequiredService<CryptoComponentRegistry>();

        Assert.NotNull(capturedBuilder);
        Assert.Same(capturedBuilder!.Registry, resolved);
    }

    [Fact]
    public void AddHkdfGuard_RegistersValidateOptions_InvalidOptionsThrowOnResolve()
    {
        var services = new ServiceCollection();
        services.AddHkdfGuard(builder => builder.Configure(options => options.ServiceName = ""));
        using var provider = services.BuildServiceProvider();

        Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<KeyRing>());
    }

    [Fact]
    public void AddHkdfGuard_ConfigureRegistersCustomKeyDerivation_UsedByResolvedKeyRing()
    {
        var storage = new InMemoryKeyInputStorage();
        var services = new ServiceCollection();

        services.AddHkdfGuard(builder =>
        {
            builder.Registry.RegisterKeyDerivation("Pbkdf2", _ => new HkdfGuard.Core.Cryptography.Pbkdf2KeyDerivationFunction(storage));
            builder.Configure(options =>
            {
                options.ServiceName = "di-test-svc";
                options.EphemeralKeys.Add(new EphemeralKeyOptions { Version = 1, MaterialIdentifier = 1, Iterations = 1 });
            });
        });

        using var provider = services.BuildServiceProvider();
        var ring = provider.GetRequiredService<KeyRing>();

        var protector = ring.CreateProtector("purpose");
        var formatted = protector.Encrypt("hello from DI".AsSpan());
        Span<char> result = new char[protector.GetMaxDecryptedLength(formatted.AsSpan())];
        var written = protector.Decrypt(formatted.AsSpan(), result);

        Assert.Equal("hello from DI", new string(result[..written]));
    }

    [Fact]
    public void AddHkdfGuard_WithUnknownCipherName_ThrowsNotSupportedExceptionOnResolve()
    {
        var services = new ServiceCollection();
        services.AddHkdfGuard(builder => builder.Configure(options =>
        {
            options.ServiceName = "svc";
            options.Cipher = "NotARealCipher";
        }));
        using var provider = services.BuildServiceProvider();

        var ex = Assert.Throws<NotSupportedException>(() => provider.GetRequiredService<KeyRing>());
        Assert.Contains("NotARealCipher", ex.Message);
    }
}
