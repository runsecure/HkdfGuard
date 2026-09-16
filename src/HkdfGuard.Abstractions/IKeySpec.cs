namespace HkdfGuard.Abstractions;

/// <summary>
/// A configured recipe of modules (key derivation, cipher, hash, service name) plus the fixed
/// material identifier and iteration count this service uses to protect keys. Pure configuration
/// data - minting an IKeyWrapper from it is IKeyWrapperFactory's job, not this interface's; an
/// IKeyProtector is instead constructed directly from this spec plus a salt (see KeyProtector).
/// </summary>
public interface IKeySpec
{
    public string ServiceName { get; }
    public IKeyDerivationFunction KeyDerivation { get; }
    public ISymmetricCipher Cipher { get; }
    public IHash Hash { get; }

    /// <summary>
    /// Identifies which underlying key material this spec's key derivation should use
    /// </summary>
    public int MaterialIdentifier { get; }

    /// <summary>
    /// The iteration count this spec's key derivation should use
    /// </summary>
    public int Iterations { get; }
}
