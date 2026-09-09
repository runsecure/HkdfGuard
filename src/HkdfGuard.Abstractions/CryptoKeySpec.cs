namespace HkdfGuard.Abstractions;

/// <summary>
/// Default IKeySpec, produced by CryptoRecipeBuilder. Pure configuration data - minting an
/// IKeyWrapper or IKeyProtector from it is IKeyWrapperFactory/IKeyProtectorFactory's job, not
/// this class's, so it carries no factory dependency of its own.
/// </summary>
public sealed class CryptoKeySpec(
    IKeyDerivationFunction keyDerivation,
    ISymmetricCipher cipher,
    IHash hash,
    int materialIdentifier,
    int iterations,
    string serviceName) : IKeySpec
{
    public string ServiceName => serviceName;
    public IKeyDerivationFunction KeyDerivation => keyDerivation;
    public ISymmetricCipher Cipher => cipher;
    public IHash Hash => hash;
    public int MaterialIdentifier => materialIdentifier;
    public int Iterations => iterations;
}
