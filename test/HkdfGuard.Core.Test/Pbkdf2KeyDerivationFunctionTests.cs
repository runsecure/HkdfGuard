using System.Security.Cryptography;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.Core.Test.TestHelpers;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Core.Test;

public class Pbkdf2KeyDerivationFunctionTests
{
    private const string ServiceName = "svc";
    private const int MaterialIdentifier = 1;
    private const int Iterations = 1;

    private static byte[] CreateSalt() => RandomNumberGenerator.GetBytes(64);

    [Fact]
    public void Derive_WritesRequestedLength()
    {
        var keyDerivation = new Pbkdf2KeyDerivationFunction(new InMemoryKeyInputStorage());
        var salt = CreateSalt();

        var result = new byte[32];
        var written = keyDerivation.Derive(RandomNumberGenerator.GetBytes(16), salt, MaterialIdentifier, Iterations, ServiceName, result);

        Assert.Equal(32, written);
    }

    [Fact]
    public void Derive_IsDeterministicForSameInputs()
    {
        var keyDerivation = new Pbkdf2KeyDerivationFunction(new InMemoryKeyInputStorage());
        var salt = CreateSalt();

        var uniqueBytes = RandomNumberGenerator.GetBytes(16);
        var first = new byte[32];
        var second = new byte[32];

        keyDerivation.Derive(uniqueBytes, salt, MaterialIdentifier, Iterations, ServiceName, first);
        keyDerivation.Derive(uniqueBytes, salt, MaterialIdentifier, Iterations, ServiceName, second);

        Assert.Equal(first, second);
    }

    [Fact]
    public void Derive_DifferentUniqueBytes_ProduceDifferentKeys()
    {
        var keyDerivation = new Pbkdf2KeyDerivationFunction(new InMemoryKeyInputStorage());
        var salt = CreateSalt();

        var first = new byte[32];
        var second = new byte[32];

        keyDerivation.Derive(RandomNumberGenerator.GetBytes(16), salt, MaterialIdentifier, Iterations, ServiceName, first);
        keyDerivation.Derive(RandomNumberGenerator.GetBytes(16), salt, MaterialIdentifier, Iterations, ServiceName, second);

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Derive_DifferentServiceName_ProducesDifferentKeys()
    {
        var keyDerivation = new Pbkdf2KeyDerivationFunction(new InMemoryKeyInputStorage());
        var salt = CreateSalt();

        var uniqueBytes = RandomNumberGenerator.GetBytes(16);
        var first = new byte[32];
        var second = new byte[32];

        keyDerivation.Derive(uniqueBytes, salt, MaterialIdentifier, Iterations, ServiceName, first);
        keyDerivation.Derive(uniqueBytes, salt, MaterialIdentifier, Iterations, "other-service", second);

        Assert.NotEqual(first, second);
    }
}
