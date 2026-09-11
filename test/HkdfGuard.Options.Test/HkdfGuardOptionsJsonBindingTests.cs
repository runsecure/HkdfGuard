using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace HkdfGuard.Options.Test;

/// <summary>
/// Confirms HkdfGuardOptions/KeyFileOptions bind correctly from real JSON via
/// Microsoft.Extensions.Configuration.Json - the shape application appsettings.json config is
/// expected to use - both via direct IConfiguration binding and via the full Options pattern
/// (services.Configure&lt;HkdfGuardOptions&gt;(section) + IOptions&lt;HkdfGuardOptions&gt;).
/// </summary>
public class HkdfGuardOptionsJsonBindingTests
{
    private const string FullJson = """
        {
          "HkdfGuard": {
            "ServiceName": "my-service",
            "KeyDerivation": "Pbkdf2",
            "Cipher": "AesGcm",
            "Hash": "HmacSha256",
            "KeyWrapperFactory": "Hkdf",
            "KeyProtectorFactory": "Default",
            "KeyFiles": [
              { "Version": 1, "Path": "/keys/v1.key", "MaterialIdentifier": 7, "Iterations": 3 },
              { "Version": 2, "Path": "/keys/v2.key", "MaterialIdentifier": 42, "Iterations": 9 }
            ],
            "EphemeralKeys": [
              { "Version": 3, "MaterialIdentifier": 11, "Iterations": 5 }
            ]
          }
        }
        """;

    private static IConfigurationRoot BuildConfiguration(string json)
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
        return new ConfigurationBuilder().AddJsonStream(stream).Build();
    }

    [Fact]
    public void Get_FromJsonConfiguration_PopulatesAllProperties()
    {
        var configuration = BuildConfiguration(FullJson);

        var options = configuration.GetSection("HkdfGuard").Get<HkdfGuardOptions>();

        Assert.NotNull(options);
        Assert.Equal("my-service", options!.ServiceName);
        Assert.Equal("Pbkdf2", options.KeyDerivation);
        Assert.Equal("AesGcm", options.Cipher);
        Assert.Equal("HmacSha256", options.Hash);
        Assert.Equal("Hkdf", options.KeyWrapperFactory);

        Assert.Equal(2, options.KeyFiles.Count);
        Assert.Equal(1, options.KeyFiles[0].Version);
        Assert.Equal("/keys/v1.key", options.KeyFiles[0].Path);
        Assert.Equal(7, options.KeyFiles[0].MaterialIdentifier);
        Assert.Equal(3, options.KeyFiles[0].Iterations);
        Assert.Equal(2, options.KeyFiles[1].Version);
        Assert.Equal("/keys/v2.key", options.KeyFiles[1].Path);
        Assert.Equal(42, options.KeyFiles[1].MaterialIdentifier);
        Assert.Equal(9, options.KeyFiles[1].Iterations);

        Assert.Equal("Default", options.KeyProtectorFactory);
        Assert.Single(options.EphemeralKeys);
        Assert.Equal(3, options.EphemeralKeys[0].Version);
        Assert.Equal(11, options.EphemeralKeys[0].MaterialIdentifier);
        Assert.Equal(5, options.EphemeralKeys[0].Iterations);
    }

    [Fact]
    public void Bind_WithPartialJson_KeepsDefaultsForOmittedProperties()
    {
        const string partialJson = """
            {
              "HkdfGuard": {
                "ServiceName": "svc-only"
              }
            }
            """;
        var configuration = BuildConfiguration(partialJson);

        // Bind (unlike Get<T>) populates an existing instance, so property initializer defaults
        // survive for anything the JSON doesn't mention.
        var options = new HkdfGuardOptions();
        configuration.GetSection("HkdfGuard").Bind(options);

        Assert.Equal("svc-only", options.ServiceName);
        Assert.Equal("Pbkdf2", options.KeyDerivation);
        Assert.Equal("AesGcm", options.Cipher);
        Assert.Equal("HmacSha256", options.Hash);
        Assert.Equal("Hkdf", options.KeyWrapperFactory);
        Assert.Equal("Default", options.KeyProtectorFactory);
        Assert.Empty(options.KeyFiles);
        Assert.Empty(options.EphemeralKeys);
    }

    [Fact]
    public void Bind_WithMissingSection_LeavesOptionsAtDefaults()
    {
        var configuration = BuildConfiguration("{}");

        var options = new HkdfGuardOptions();
        configuration.GetSection("HkdfGuard").Bind(options);

        Assert.Equal(string.Empty, options.ServiceName);
        Assert.Equal("Pbkdf2", options.KeyDerivation);
    }

    [Fact]
    public void ServicesConfigure_WithJsonConfigurationSection_ResolvesViaIOptions()
    {
        var configuration = BuildConfiguration(FullJson);

        var services = new ServiceCollection();
        services.Configure<HkdfGuardOptions>(configuration.GetSection("HkdfGuard"));
        using var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<IOptions<HkdfGuardOptions>>();

        Assert.Equal("my-service", options.Value.ServiceName);
        Assert.Equal(2, options.Value.KeyFiles.Count);
        Assert.Equal("/keys/v2.key", options.Value.KeyFiles[1].Path);
        Assert.Single(options.Value.EphemeralKeys);
        Assert.Equal(3, options.Value.EphemeralKeys[0].Version);
    }
}
