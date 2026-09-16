namespace HkdfGuard.Options.Test;

public class HkdfGuardOptionsTests
{
    [Fact]
    public void Defaults_MatchBuiltInRegistryNames()
    {
        var options = new HkdfGuardOptions();

        Assert.Equal(string.Empty, options.ServiceName);
        Assert.Equal("Pbkdf2", options.KeyDerivation);
        Assert.Equal("AesGcm", options.Cipher);
        Assert.Equal("HmacSha512", options.Hash);
        Assert.Equal("Hkdf", options.KeyWrapperFactory);
        Assert.Empty(options.KeyFiles);
        Assert.Empty(options.EphemeralKeys);
    }

    [Fact]
    public void Properties_AreMutable()
    {
        var options = new HkdfGuardOptions
        {
            ServiceName = "svc",
            KeyDerivation = "Custom",
            Cipher = "Custom",
            Hash = "Custom",
            KeyWrapperFactory = "Custom"
        };

        Assert.Equal("svc", options.ServiceName);
        Assert.Equal("Custom", options.KeyDerivation);
        Assert.Equal("Custom", options.Cipher);
        Assert.Equal("Custom", options.Hash);
        Assert.Equal("Custom", options.KeyWrapperFactory);
    }

    [Fact]
    public void KeyFileOptions_Defaults()
    {
        var keyFile = new KeyFileOptions();

        Assert.Equal(0, keyFile.Version);
        Assert.Equal(string.Empty, keyFile.Path);
        Assert.Equal(0, keyFile.MaterialIdentifier);
        Assert.Equal(0, keyFile.Iterations);
    }

    [Fact]
    public void KeyFiles_CanBePopulated()
    {
        var options = new HkdfGuardOptions
        {
            KeyFiles =
            {
                new KeyFileOptions { Version = 1, Path = "/keys/v1.key", MaterialIdentifier = 5, Iterations = 2 },
                new KeyFileOptions { Version = 2, Path = "/keys/v2.key", MaterialIdentifier = 9, Iterations = 4 }
            }
        };

        Assert.Equal(2, options.KeyFiles.Count);
        Assert.Equal(1, options.KeyFiles[0].Version);
        Assert.Equal("/keys/v2.key", options.KeyFiles[1].Path);
    }

    [Fact]
    public void EphemeralKeyOptions_Defaults()
    {
        var ephemeralKey = new EphemeralKeyOptions();

        Assert.Equal(0, ephemeralKey.Version);
        Assert.Equal(0, ephemeralKey.MaterialIdentifier);
        Assert.Equal(0, ephemeralKey.Iterations);
    }

    [Fact]
    public void EphemeralKeys_CanBePopulated()
    {
        var options = new HkdfGuardOptions
        {
            EphemeralKeys =
            {
                new EphemeralKeyOptions { Version = 1, MaterialIdentifier = 5, Iterations = 2 },
                new EphemeralKeyOptions { Version = 2, MaterialIdentifier = 9, Iterations = 4 }
            }
        };

        Assert.Equal(2, options.EphemeralKeys.Count);
        Assert.Equal(1, options.EphemeralKeys[0].Version);
        Assert.Equal(9, options.EphemeralKeys[1].MaterialIdentifier);
    }
}
