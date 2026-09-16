using HkdfGuard.Core.Cryptography;

namespace HkdfGuard.Core.Test;

public class DefaultCryptoRecipeTests
{
    [Fact]
    public void Create_ReturnsSpecWithGivenServiceNameMaterialIdentifierAndIterations()
    {
        var spec = DefaultCryptoRecipe.Create("svc", materialIdentifier: 3, iterations: 5);

        Assert.Equal("svc", spec.ServiceName);
        Assert.Equal(3, spec.MaterialIdentifier);
        Assert.Equal(5, spec.Iterations);
    }

    [Fact]
    public void Create_UsesPbkdf2KeyDerivation()
    {
        var spec = DefaultCryptoRecipe.Create("svc", 1, 1);

        Assert.IsType<Pbkdf2KeyDerivationFunction>(spec.KeyDerivation);
    }

    [Fact]
    public void Create_UsesAesGcmCipher()
    {
        var spec = DefaultCryptoRecipe.Create("svc", 1, 1);

        Assert.IsType<AesGcmCipher>(spec.Cipher);
    }

    [Fact]
    public void Create_UsesHmacSha512Hash()
    {
        var spec = DefaultCryptoRecipe.Create("svc", 1, 1);

        Assert.IsType<HmacSha512Hash>(spec.Hash);
    }

    [Fact]
    public void KeyWrapperFactory_ReturnsHkdfKeyWrapperFactory()
    {
        Assert.IsType<HkdfKeyWrapperFactory>(DefaultCryptoRecipe.KeyWrapperFactory);
    }

    [Fact]
    public void KeyWrapperFactory_IsASingleton()
    {
        Assert.Same(DefaultCryptoRecipe.KeyWrapperFactory, DefaultCryptoRecipe.KeyWrapperFactory);
    }
}
