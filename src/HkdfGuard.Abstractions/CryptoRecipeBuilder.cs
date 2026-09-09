namespace HkdfGuard.Abstractions;

/// <summary>
/// Default ICryptoRecipeBuilder. Depends only on interfaces - every module must be supplied
/// explicitly via With* calls, there are no built-in concrete defaults. This makes it reusable
/// for any IKeyDerivationFunction/ISymmetricCipher/IHash combination, not just this library's own
/// implementations.
/// </summary>
public sealed class CryptoRecipeBuilder : ICryptoRecipeBuilder
{
    private string? _serviceName;
    private IKeyDerivationFunction? _keyDerivation;
    private ISymmetricCipher? _cipher;
    private IHash? _hash;
    private int? _materialIdentifier;
    private int? _iterations;

    public ICryptoRecipeBuilder WithServiceName(string serviceName)
    {
        _serviceName = serviceName;
        return this;
    }

    public ICryptoRecipeBuilder WithKeyDerivation(IKeyDerivationFunction keyDerivation)
    {
        _keyDerivation = keyDerivation;
        return this;
    }

    public ICryptoRecipeBuilder WithCipher(ISymmetricCipher cipher)
    {
        _cipher = cipher;
        return this;
    }

    public ICryptoRecipeBuilder WithHash(IHash hash)
    {
        _hash = hash;
        return this;
    }

    public ICryptoRecipeBuilder WithMaterialIdentifier(int materialIdentifier)
    {
        _materialIdentifier = materialIdentifier;
        return this;
    }

    public ICryptoRecipeBuilder WithIterations(int iterations)
    {
        _iterations = iterations;
        return this;
    }

    public IKeySpec Build()
    {
        if (string.IsNullOrEmpty(_serviceName))
            throw new InvalidOperationException("A service name is required. Call WithServiceName first.");

        if (_keyDerivation is null)
            throw new InvalidOperationException("A key derivation function is required. Call WithKeyDerivation first.");

        if (_cipher is null)
            throw new InvalidOperationException("A cipher is required. Call WithCipher first.");

        if (_hash is null)
            throw new InvalidOperationException("A hash is required. Call WithHash first.");

        if (_materialIdentifier is null)
            throw new InvalidOperationException("A material identifier is required. Call WithMaterialIdentifier first.");

        if (_iterations is null)
            throw new InvalidOperationException("An iteration count is required. Call WithIterations first.");

        return new CryptoKeySpec(
            _keyDerivation, _cipher, _hash, _materialIdentifier.Value, _iterations.Value, _serviceName);
    }
}
