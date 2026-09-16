namespace HkdfGuard.Options.Test;

public class HkdfGuardOptionsValidatorTests
{
    private readonly HkdfGuardOptionsValidator _validator = new();

    private static HkdfGuardOptions CreateValidOptions()
        => new()
        {
            ServiceName = "svc",
            KeyFiles = { new KeyFileOptions { Version = 1, Path = "/keys/v1.key", MaterialIdentifier = 1, Iterations = 1 } }
        };

    [Fact]
    public void Validate_WithValidOptions_Succeeds()
    {
        var result = _validator.Validate(null, CreateValidOptions());

        Assert.False(result.Failed);
        Assert.Same(Microsoft.Extensions.Options.ValidateOptionsResult.Success, result);
    }

    [Fact]
    public void Validate_WithNoKeyFiles_StillSucceeds()
    {
        var options = new HkdfGuardOptions { ServiceName = "svc" };

        var result = _validator.Validate(null, options);

        Assert.False(result.Failed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void Validate_WithMissingServiceName_Fails(string? serviceName)
    {
        var options = CreateValidOptions();
        options.ServiceName = serviceName!;

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(nameof(HkdfGuardOptions.ServiceName), result.FailureMessage);
    }

    [Fact]
    public void Validate_WithMissingKeyDerivation_Fails()
    {
        var options = CreateValidOptions();
        options.KeyDerivation = "";

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(nameof(HkdfGuardOptions.KeyDerivation), result.FailureMessage);
    }

    [Fact]
    public void Validate_WithMissingCipher_Fails()
    {
        var options = CreateValidOptions();
        options.Cipher = "";

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(nameof(HkdfGuardOptions.Cipher), result.FailureMessage);
    }

    [Fact]
    public void Validate_WithMissingHash_Fails()
    {
        var options = CreateValidOptions();
        options.Hash = "";

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(nameof(HkdfGuardOptions.Hash), result.FailureMessage);
    }

    [Fact]
    public void Validate_WithMissingKeyWrapperFactory_Fails()
    {
        var options = CreateValidOptions();
        options.KeyWrapperFactory = "";

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(nameof(HkdfGuardOptions.KeyWrapperFactory), result.FailureMessage);
    }

    [Fact]
    public void Validate_WithNullKeyFiles_Fails()
    {
        var options = CreateValidOptions();
        options.KeyFiles = null!;

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(nameof(HkdfGuardOptions.KeyFiles), result.FailureMessage);
    }

    [Fact]
    public void Validate_WithMissingKeyFilePath_Fails()
    {
        var options = CreateValidOptions();
        options.KeyFiles[0].Path = "";

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("KeyFiles[0]", result.FailureMessage);
        Assert.Contains(nameof(KeyFileOptions.Path), result.FailureMessage);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_WithNonPositiveMaterialIdentifier_Fails(int materialIdentifier)
    {
        var options = CreateValidOptions();
        options.KeyFiles[0].MaterialIdentifier = materialIdentifier;

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(nameof(KeyFileOptions.MaterialIdentifier), result.FailureMessage);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_WithNonPositiveIterations_Fails(int iterations)
    {
        var options = CreateValidOptions();
        options.KeyFiles[0].Iterations = iterations;

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(nameof(KeyFileOptions.Iterations), result.FailureMessage);
    }

    [Fact]
    public void Validate_WithDuplicateKeyFileVersions_Fails()
    {
        var options = CreateValidOptions();
        options.KeyFiles.Add(new KeyFileOptions { Version = 1, Path = "/keys/v1-again.key", MaterialIdentifier = 2, Iterations = 1 });

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(nameof(KeyFileOptions.Version), result.FailureMessage);
    }

    [Fact]
    public void Validate_WithValidEphemeralKey_Succeeds()
    {
        var options = new HkdfGuardOptions
        {
            ServiceName = "svc",
            EphemeralKeys = { new EphemeralKeyOptions { Version = 1, MaterialIdentifier = 1, Iterations = 1 } }
        };

        var result = _validator.Validate(null, options);

        Assert.False(result.Failed);
    }

    [Fact]
    public void Validate_WithNoEphemeralKeys_StillSucceeds()
    {
        var result = _validator.Validate(null, CreateValidOptions());

        Assert.False(result.Failed);
    }

    [Fact]
    public void Validate_WithNullEphemeralKeys_Fails()
    {
        var options = CreateValidOptions();
        options.EphemeralKeys = null!;

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(nameof(HkdfGuardOptions.EphemeralKeys), result.FailureMessage);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_WithNonPositiveEphemeralMaterialIdentifier_Fails(int materialIdentifier)
    {
        var options = CreateValidOptions();
        options.EphemeralKeys.Add(new EphemeralKeyOptions { Version = 2, MaterialIdentifier = materialIdentifier, Iterations = 1 });

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(nameof(EphemeralKeyOptions.MaterialIdentifier), result.FailureMessage);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_WithNonPositiveEphemeralIterations_Fails(int iterations)
    {
        var options = CreateValidOptions();
        options.EphemeralKeys.Add(new EphemeralKeyOptions { Version = 2, MaterialIdentifier = 1, Iterations = iterations });

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(nameof(EphemeralKeyOptions.Iterations), result.FailureMessage);
    }

    [Fact]
    public void Validate_WithDuplicateEphemeralKeyVersions_Fails()
    {
        var options = CreateValidOptions();
        options.EphemeralKeys.Add(new EphemeralKeyOptions { Version = 2, MaterialIdentifier = 1, Iterations = 1 });
        options.EphemeralKeys.Add(new EphemeralKeyOptions { Version = 2, MaterialIdentifier = 2, Iterations = 1 });

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(nameof(EphemeralKeyOptions.Version), result.FailureMessage);
    }

    [Fact]
    public void Validate_WithEphemeralKeyReusingKeyFileVersion_Fails()
    {
        var options = CreateValidOptions();
        options.EphemeralKeys.Add(new EphemeralKeyOptions { Version = 1, MaterialIdentifier = 1, Iterations = 1 });

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(nameof(EphemeralKeyOptions.Version), result.FailureMessage);
    }

    [Fact]
    public void Validate_WithMultipleProblems_ReportsAllFailuresNotJustTheFirst()
    {
        var options = new HkdfGuardOptions
        {
            ServiceName = "",
            Cipher = "",
            KeyFiles = { new KeyFileOptions { Version = 1, Path = "", MaterialIdentifier = 0, Iterations = 0 } }
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        var failures = Assert.IsAssignableFrom<IEnumerable<string>>(result.Failures).ToList();
        Assert.Equal(5, failures.Count);
        Assert.Contains(failures, f => f.Contains(nameof(HkdfGuardOptions.ServiceName)));
        Assert.Contains(failures, f => f.Contains(nameof(HkdfGuardOptions.Cipher)));
        Assert.Contains(failures, f => f.Contains(nameof(KeyFileOptions.Path)));
        Assert.Contains(failures, f => f.Contains(nameof(KeyFileOptions.MaterialIdentifier)));
        Assert.Contains(failures, f => f.Contains(nameof(KeyFileOptions.Iterations)));
    }
}
