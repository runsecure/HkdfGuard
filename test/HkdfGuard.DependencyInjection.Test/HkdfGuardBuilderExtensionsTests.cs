using System.Text;
using HkdfGuard.DataProtectionKey.KeyTracking;
using HkdfGuard.DependencyInjection.Test.TestHelpers;
using HkdfGuard.Options;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace HkdfGuard.DependencyInjection.Test;

public class HkdfGuardBuilderExtensionsTests
{
    [Fact]
    public void Configure_ReturnsSameBuilder_ForFluentChaining()
    {
        var services = new ServiceCollection();
        IHkdfGuardBuilder? captured = null;
        services.AddHkdfGuard(builder => captured = builder);

        var returned = captured!.Configure(_ => { });

        Assert.Same(captured, returned);
    }

    [Fact]
    public void BindConfiguration_ReturnsSameBuilder_ForFluentChaining()
    {
        var services = new ServiceCollection();
        IHkdfGuardBuilder? captured = null;
        services.AddHkdfGuard(builder => captured = builder);
        var configuration = new ConfigurationBuilder().Build();

        var returned = captured!.BindConfiguration(configuration);

        Assert.Same(captured, returned);
    }

    [Fact]
    public void Configure_SetsOptionsUsedByResolvedKeyRing()
    {
        var services = new ServiceCollection();

        services.AddHkdfGuard(builder => builder
            .Configure(options => options.ServiceName = "configured-via-fluent-chain"));

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<HkdfGuardOptions>>();

        Assert.Equal("configured-via-fluent-chain", options.Value.ServiceName);
    }

    [Fact]
    public void BindConfiguration_BindsOptionsFromRealJsonConfiguration()
    {
        const string json = """
            {
              "HkdfGuard": {
                "ServiceName": "bound-from-json",
                "EphemeralKeys": [
                  { "Version": 1, "MaterialIdentifier": 1, "Iterations": 1 }
                ]
              }
            }
            """;
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
        var configuration = new ConfigurationBuilder().AddJsonStream(stream).Build();
        var storage = new InMemoryKeyInputStorage();

        var services = new ServiceCollection();
        services.AddHkdfGuard(builder =>
        {
            builder.Registry.RegisterKeyDerivation("Pbkdf2", _ => new HkdfGuard.Core.Cryptography.Pbkdf2KeyDerivationFunction(storage));
            builder.BindConfiguration(configuration.GetSection("HkdfGuard"));
        });

        using var provider = services.BuildServiceProvider();
        var ring = provider.GetRequiredService<KeyRing>();

        Assert.Equal(1, ring.CurrentVersion);
    }
}
