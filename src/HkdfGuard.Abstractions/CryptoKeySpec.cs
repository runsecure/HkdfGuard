namespace HkdfGuard.Abstractions;

/// <summary>
/// Default IKeySpec, produced by CryptoRecipeBuilder. Pure configuration data - minting an
/// IKeyWrapper from it is IKeyWrapperFactory's job, not this class's; an IKeyProtector is instead
/// constructed directly from this spec plus a salt (see KeyProtector), so it carries no factory
/// dependency of its own either way.
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
